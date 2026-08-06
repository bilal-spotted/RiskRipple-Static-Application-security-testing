"""
Shared credential detection.

Two secret scanners used to exist side by side: one inside the scan pipeline
(``core/repo_hygiene.py``) and one as a pre-commit hook
(``tools/check_secrets.py``). They carried separate pattern lists and separate
exclusion rules, and they disagreed - the hook correctly ignored
``.env.example`` while the pipeline flagged it as a tracked secret file, even
though that template exists precisely to be committed.

Both now share this module, so the two cannot drift apart again.

It also distinguishes a credential from something merely *shaped* like one.
Documentation, tests, and fixtures are full of placeholder keys, and reporting
``AKIAIOSFODNN7EXAMPLE`` - the example key from AWS's own documentation - as a
critical exposure is noise that teaches people to ignore the tool.

Placeholders are downgraded, never silently dropped. Suppressing something that
turns out to be real is far worse than an over-cautious LOW finding, so the
heuristics stay deliberately conservative: a value must either say it is fake
or contain a long run of sequential characters no random key would have.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, NamedTuple, Pattern, Tuple

# ---------------------------------------------------------------------------
# Credential patterns
# ---------------------------------------------------------------------------


class SecretPattern(NamedTuple):
    """A named credential signature."""

    name: str
    pattern: Pattern[str]
    description: str


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        "OpenAI API key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "sk-… service key",
    ),
    SecretPattern(
        "AWS access key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AKIA… access key ID",
    ),
    SecretPattern(
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "ghp_/gho_/ghu_/ghs_/ghr_ token",
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "xox…- token",
    ),
    SecretPattern(
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "AIza… API key",
    ),
    SecretPattern(
        "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "PEM private key block",
    ),
]

# ---------------------------------------------------------------------------
# Placeholder recognition
# ---------------------------------------------------------------------------

# Words that announce a value is not real.
PLACEHOLDER_MARKERS = (
    "example",
    "sample",
    "placeholder",
    "dummy",
    "fake",
    "changeme",
    "change_me",
    # "your" covers your_api_key, yourtoken, YOUR-KEY-HERE and similar. The odds
    # of it appearing by chance in a random credential are negligible.
    "your",
    "replaceme",
    "replace_me",
    "notreal",
    "xxxxxxxx",
    "abcdef",
    "redacted",
    "insert",
    "todo",
)

# A run this long of sequential or repeated characters does not occur in a
# randomly generated credential, but is typical of hand-written filler.
_SEQUENCE_RUN_LENGTH = 6


def _has_sequential_run(value: str, run: int = _SEQUENCE_RUN_LENGTH) -> bool:
    """True if the value contains a long ascending or repeating character run."""
    if len(value) < run:
        return False
    ascending = 1
    repeating = 1
    for previous, current in zip(value, value[1:]):
        ascending = ascending + 1 if ord(current) - ord(previous) == 1 else 1
        repeating = repeating + 1 if current == previous else 1
        if ascending >= run or repeating >= run:
            return True
    return False


def looks_like_placeholder(value: str) -> bool:
    """
    True if a credential-shaped string is almost certainly not a real secret.

    Deliberately conservative. A real key is high-entropy: it will not announce
    itself as an example, and it will not contain six sequential or repeated
    characters. Anything not matching these signals is treated as real.
    """
    if not value:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    return _has_sequential_run(lowered)


# ---------------------------------------------------------------------------
# Environment files
# ---------------------------------------------------------------------------


ENV_TEMPLATE_NAMES = (".env.example", ".env.sample", ".env.template", ".env.dist")


def is_env_template(path: str | Path) -> bool:
    """True for committed environment templates such as ``.env.example``."""
    return Path(path).name in ENV_TEMPLATE_NAMES


def is_env_file(path: str | Path) -> bool:
    """
    True for ``.env`` and its variants, but never for ``.env.example``.

    The example file is a committed template documenting which variables exist.
    Flagging it as an exposed secret file is a false positive, and it was the
    single most visible one in a self-scan.
    """
    name = Path(path).name
    if is_env_template(name):
        return False
    return name == ".env" or name.startswith(".env.")


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


class SecretMatch(NamedTuple):
    """A credential signature found in text."""

    name: str
    matched_value: str
    is_placeholder: bool


def scan_text(content: str) -> List[SecretMatch]:
    """
    Return one match per distinct credential signature found in ``content``.

    At most one match is reported per pattern: a file containing twenty AWS keys
    has one problem, not twenty. A signature is reported as a placeholder only
    when every occurrence of it looks like one, so a real key sitting beside an
    example is still reported as real.
    """
    matches: List[SecretMatch] = []
    for name, pattern, _ in SECRET_PATTERNS:
        found = pattern.findall(content)
        if not found:
            continue
        values = [v if isinstance(v, str) else str(v) for v in found]
        real = [v for v in values if not looks_like_placeholder(v)]
        if real:
            matches.append(SecretMatch(name, real[0], False))
        else:
            matches.append(SecretMatch(name, values[0], True))
    return matches


def scan_file(path: str | Path, max_bytes: int = 512 * 1024) -> List[SecretMatch]:
    """Scan a file's text for credentials, skipping unreadable or oversized files."""
    try:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return []
    if len(content) > max_bytes:
        return []
    return scan_text(content)


# Text-like extensions worth scanning for credentials.
TEXT_EXTENSIONS: Tuple[str, ...] = (
    ".py",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".txt",
    ".md",
    ".cfg",
    ".ini",
    ".toml",
    ".conf",
    ".sh",
    ".env",
    ".properties",
    ".xml",
)


def is_scannable_text_file(path: str | Path) -> bool:
    """True if a file is a text type worth scanning for credentials."""
    name = Path(path).name.lower()
    if name.startswith(".env"):
        return True
    return any(name.endswith(ext) for ext in TEXT_EXTENSIONS)
