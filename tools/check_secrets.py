#!/usr/bin/env python3
"""
Pre-commit secret scanner for this repository.

Scans project code and config for values that look like real credentials. By
default tests/, benchmark/, and samples/ are excluded because they intentionally
contain fixture secrets used to validate the main scanner; pass
--include-test-fixtures to scan them too.

.env and .env.* files are always checked wherever they appear, since they should
never be committed. Committed templates such as .env.example are exempt.

Detection is shared with the scan pipeline via core.secrets_detection, so the
hook and the scanner cannot disagree about what counts as a secret.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Runnable as a standalone script ("python tools/check_secrets.py"), which puts
# tools/ on sys.path rather than the project root. Add the root so the shared
# detection module resolves either way.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.git_context import STATUS_IGNORED, GitContext  # noqa: E402
from core.secrets_detection import is_env_file  # noqa: E402
from core.secrets_detection import scan_file as scan_file_for_secrets  # noqa: E402

# Always skip these directories (build/cache/vcs)
ALWAYS_IGNORED_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "output",
    }
)

# Directories that often contain intentional dummy secrets (excluded unless --include-test-fixtures)
FIXTURE_DIRS = frozenset(
    {
        "tests",
        "benchmark",
        "samples",
    }
)


def _is_env_file(path: Path) -> bool:
    """True for .env and .env.* but not committed templates like .env.example."""
    return is_env_file(path)


def _should_skip_path(path: Path, include_test_fixtures: bool) -> bool:
    """Return True if this path should be skipped (not scanned)."""
    parts = path.parts
    for d in ALWAYS_IGNORED_DIRS:
        if d in parts:
            return True
    if not include_test_fixtures:
        for d in FIXTURE_DIRS:
            if d in parts:
                # Still scan .env files anywhere
                if path.is_file() and _is_env_file(path):
                    return False
                return True
    return False


def scan_file(path: Path) -> list[str]:
    """
    Return the names of credential signatures found in a file.

    Placeholder values are excluded: this runs as a pre-commit hook, and
    blocking a commit over the example key from AWS's own documentation would
    train people to bypass the hook.
    """
    return [match.name for match in scan_file_for_secrets(path) if not match.is_placeholder]


def scan_repository(root: Path, include_test_fixtures: bool = False) -> list[tuple[Path, str]]:
    """
    Return (path, issue) tuples for potential secrets about to be committed.

    Gitignored files are skipped. This hook exists to stop secrets entering the
    repository, and an ignored file is not going to be committed - reporting
    scan output and other local artifacts would be noise that teaches people to
    pass --no-verify. When git is unavailable every file is scanned, which is
    the safer default.
    """
    candidates = [
        path
        for path in root.rglob("*")
        if path.is_file() and not _should_skip_path(path, include_test_fixtures)
    ]

    git = GitContext.discover(root)
    if git.available:
        git.prime_ignored(candidates)
        candidates = [p for p in candidates if git.status_of(p) != STATUS_IGNORED]

    issues: list[tuple[Path, str]] = []
    for file in candidates:
        if _is_env_file(file):
            issues.append((file, "Sensitive .env file detected (should not be committed)"))
            continue
        for finding in scan_file(file):
            issues.append((file, finding))

    return issues


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pre-commit secret scanner; excludes tests/benchmark/samples by default."
    )
    parser.add_argument(
        "--include-test-fixtures",
        action="store_true",
        help="Also scan tests/, benchmark/, and samples/ (may have intentional dummy secrets).",
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    issues = scan_repository(root, include_test_fixtures=args.include_test_fixtures)

    if not issues:
        print("No potential secrets found.")
        return

    print("Possible secret exposure detected:\n", file=sys.stderr)
    for path, issue in issues:
        print(f"  {path} -> {issue}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
