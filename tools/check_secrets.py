#!/usr/bin/env python3
"""
Pre-commit secret scanner for this repository.

Scans project code and config for patterns that look like real secrets (API keys,
tokens, etc.). By default, tests/, benchmark/, and samples/ are excluded because
they may intentionally contain dummy or fixture secrets used to validate the
main scanner; use --include-test-fixtures to scan those directories too.

.env and .env.* files are always checked wherever they appear (including under
excluded dirs), since they should not be committed with real secrets.
"""

import argparse
import re
import sys
from pathlib import Path

SECRET_PATTERNS = {
    "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{40,}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "Generic API Key": re.compile(r"api[_-]?key\s*=\s*['\"][A-Za-z0-9\-]{16,}['\"]", re.IGNORECASE),
}

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
    """True if path is .env or .env.* (e.g. .env.local), but not .env.example."""
    name = path.name
    if name == ".env":
        return True
    if name == ".env.example":
        return False
    return name.startswith(".env.")


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
    """Return list of secret pattern names found in file content."""
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)
    return findings


def scan_repository(root: Path, include_test_fixtures: bool = False) -> list[tuple[Path, str]]:
    """Return a list of (path, issue) tuples for potential secrets."""
    issues: list[tuple[Path, str]] = []
    for file in root.rglob("*"):
        if not file.is_file():
            continue
        if _should_skip_path(file, include_test_fixtures):
            continue

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
