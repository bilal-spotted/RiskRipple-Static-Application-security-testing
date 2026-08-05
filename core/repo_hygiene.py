"""
Repository hygiene and secure development checks.

Detects sensitive artifacts, tracked files that should be ignored,
and .gitignore gaps. Findings include remediation guidance.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Sensitive filenames or patterns (exact name or suffix)
# Env/secret files (key files id_rsa etc. are handled separately as RH003)
SENSITIVE_FILE_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.secret",
    }
)
SENSITIVE_EXTENSIONS = frozenset(
    {
        ".pem",
        ".key",
        ".crt",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".pyc",
        ".pyo",
    }
)
# Directories that should not be committed
SENSITIVE_DIR_NAMES = frozenset({"__pycache__", ".pytest_cache", "node_modules"})

# Secret patterns: if detected in file content -> CRITICAL finding
# OpenAI-style API key (sk-...)
SECRET_PATTERN_OPENAI = re.compile(r"\bsk-[A-Za-z0-9]{40,}\b")
# AWS access key
SECRET_PATTERN_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# GitHub personal access token
SECRET_PATTERN_GITHUB = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
# Generic API key (common placeholder patterns; avoid false positives with short strings)
SECRET_PATTERN_GENERIC = re.compile(
    r"\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{32,})['\"]?",
    re.IGNORECASE,
)

# All secret patterns to scan for (name, pattern, description)
SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    ("OpenAI API key", SECRET_PATTERN_OPENAI, "sk-[A-Za-z0-9]{40,}"),
    ("AWS access key", SECRET_PATTERN_AWS, "AKIA[0-9A-Z]{16}"),
    ("GitHub token", SECRET_PATTERN_GITHUB, "ghp_[A-Za-z0-9]{36}"),
]

# Legacy: single pattern for backward compatibility (OpenAI-style)
API_KEY_PATTERN = SECRET_PATTERN_OPENAI

# Required .gitignore patterns for secure repo hygiene
REQUIRED_GITIGNORE_PATTERNS = [
    (".env", "Environment files containing secrets"),
    ("__pycache__/", "Python bytecode cache directories"),
    ("*.pyc", "Python compiled files"),
    ("*.pyo", "Python optimized bytecode files"),
    ("venv/", "Virtual environment directory"),
    (".venv/", "Virtual environment directory"),
]


def _make_finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    file_path: str,
    description: str,
    recommendation: str,
    remediation: str,
    line_number: int | None = None,
    code_snippet: str = "",
) -> Dict[str, Any]:
    """Build a finding dict compatible with report generators."""
    f: Dict[str, Any] = {
        "rule_id": rule_id,
        "title": title,
        "type": title,
        "severity": severity,
        "confidence": "HIGH",
        "category": category,
        "file_path": file_path,
        "file": file_path,
        "line_number": line_number or 0,
        "line": line_number,
        "description": description,
        "recommendation": recommendation,
        "suggested_fix": recommendation,
        "remediation": remediation,
        "code_snippet": code_snippet,
        "snippet": code_snippet,
        "code": code_snippet.strip()[:200] if code_snippet else "",
    }
    return f


def _scan_file_for_secrets(
    file_path_abs: str,
    rel_path_norm: str,
    name_lower: str,
    findings: List[Dict[str, Any]],
    seen_paths: set[str],
) -> None:
    """
    Scan file content for secret patterns (OpenAI, AWS, GitHub, etc.).
    If any pattern matches, append a CRITICAL finding. Skips binary/extensions we don't scan.
    """
    # Only scan text-like files to avoid binary and huge files
    text_extensions = (
        ".py",
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".txt",
        ".md",
        ".cfg",
        ".ini",
        ".toml",
        ".conf",
    )
    if not name_lower.startswith(".env") and not any(
        name_lower.endswith(ext) or name_lower.endswith(ext + ".bak") for ext in text_extensions
    ):
        return
    try:
        content = Path(file_path_abs).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    # Cap size to avoid scanning huge files
    if len(content) > 512 * 1024:
        return
    for pattern_name, pattern, _ in SECRET_PATTERNS:
        if pattern.search(content):
            key_finding_path = rel_path_norm + " (secret: " + pattern_name + ")"
            if key_finding_path not in seen_paths:
                seen_paths.add(key_finding_path)
                findings.append(
                    _make_finding(
                        rule_id="RH005",
                        title="Secret or API key detected in file",
                        severity="CRITICAL",
                        category="Secret Exposure",
                        file_path=rel_path_norm,
                        description=f"File content matches secret pattern: {pattern_name}. Treat as exposed.",
                        recommendation="Revoke and rotate the credential immediately. Remove from repo and consider purging from git history.",
                        remediation="Revoke/rotate the key in the provider dashboard. Remove from git: git rm --cached "
                        + rel_path_norm
                        + ". Add to .gitignore. Consider: git filter-branch or BFG to remove from history.",
                    )
                )
            return  # One finding per file for secrets
    # Legacy: also check OpenAI-style with older pattern for .env-like files
    if name_lower.startswith(".env") or "env" in name_lower and name_lower.startswith("."):
        if API_KEY_PATTERN.search(content):
            key_finding_path = rel_path_norm + " (contains API key pattern)"
            if key_finding_path not in seen_paths:
                seen_paths.add(key_finding_path)
                findings.append(
                    _make_finding(
                        rule_id="RH005",
                        title="Secret or API key detected in file",
                        severity="CRITICAL",
                        category="Secret Exposure",
                        file_path=rel_path_norm,
                        description="File content matches API key pattern (e.g. sk-...). Treat as exposed.",
                        recommendation="Revoke and rotate the key immediately. Remove from repo and add to .gitignore.",
                        remediation="Revoke/rotate the API key in the provider dashboard. Remove file from git: git rm --cached "
                        + rel_path_norm
                        + ". Add to .gitignore. Never commit this file again.",
                    )
                )


def scan_repository_hygiene(root_path: str) -> List[Dict[str, Any]]:
    """
    Walk the repository and detect sensitive artifacts and hygiene issues.

    Returns a list of findings (same schema as core.analyzer) for:
    - Tracked .env and secret-like env files
    - Tracked .pyc and __pycache__
    - Private key and certificate artifacts
    - Suspicious API key patterns in text files
    """
    root = Path(root_path).resolve()
    if not root.is_dir():
        return []

    findings: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        dirpath_norm = os.path.normpath(dirpath)
        rel_dir = os.path.relpath(dirpath_norm, root) if dirpath_norm != str(root) else "."

        # Check directory names (e.g. __pycache__); skip descent into excluded/sensitive dirs
        for d in list(dirnames):
            if d in (".git", "venv", ".venv", "node_modules", "build", "dist"):
                dirnames.remove(d)
            elif d in SENSITIVE_DIR_NAMES:
                path_key = os.path.join(rel_dir, d).replace("\\", "/")
                if path_key not in seen_paths:
                    seen_paths.add(path_key)
                    findings.append(
                        _make_finding(
                            rule_id="RH001",
                            title="Tracked cache or build directory",
                            severity="MEDIUM",
                            category="Repository Hygiene",
                            file_path=path_key,
                            description=f"Directory '{d}' should not be committed. It is generated/cache content.",
                            recommendation="Add this directory to .gitignore and remove from git history if already tracked.",
                            remediation="Add to .gitignore: "
                            + (d + "/" if not d.endswith("/") else d)
                            + ". Then run: git rm -r --cached "
                            + path_key
                            + " (if already tracked).",
                        )
                    )
                dirnames.remove(d)

        for filename in filenames:
            file_path_abs = os.path.join(dirpath, filename)
            try:
                rel_path = os.path.relpath(file_path_abs, root)
            except ValueError:
                continue
            rel_path_norm = rel_path.replace("\\", "/")

            if rel_path_norm in seen_paths:
                continue

            name_lower = filename.lower()
            ext = os.path.splitext(filename)[1].lower()

            # .env and env-like files
            if name_lower in SENSITIVE_FILE_NAMES or name_lower.startswith(".env."):
                seen_paths.add(rel_path_norm)
                findings.append(
                    _make_finding(
                        rule_id="RH002",
                        title="Environment or secret file tracked",
                        severity="HIGH",
                        category="Sensitive Artifacts",
                        file_path=rel_path_norm,
                        description="Environment or secret-bearing file should not be committed.",
                        recommendation="Add .env (and variants) to .gitignore. Use environment variables or a secrets manager at runtime.",
                        remediation="Add '.env' and '.env.*' to .gitignore. If already committed: revoke/rotate any exposed secrets, then run: git rm --cached "
                        + rel_path_norm
                        + " and commit. Do not commit the file again.",
                    )
                )
                continue

            # Private keys and certs
            if name_lower in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519") or ext in (
                ".pem",
                ".key",
                ".p12",
                ".pfx",
            ):
                seen_paths.add(rel_path_norm)
                findings.append(
                    _make_finding(
                        rule_id="RH003",
                        title="Private key or certificate artifact",
                        severity="HIGH",
                        category="Secret Exposure",
                        file_path=rel_path_norm,
                        description="Private key or certificate file should never be committed.",
                        recommendation="Remove from repository and rotate/revoke the affected credentials immediately.",
                        remediation="Revoke/rotate the key or certificate. Remove from repo: git rm --cached "
                        + rel_path_norm
                        + ". Add pattern to .gitignore (e.g. *.pem, *.key, id_rsa).",
                    )
                )
                continue

            # .pyc and .pyo files
            if ext == ".pyc" or name_lower.endswith(".pyc"):
                seen_paths.add(rel_path_norm)
                findings.append(
                    _make_finding(
                        rule_id="RH004",
                        title="Python bytecode file tracked",
                        severity="LOW",
                        category="Repository Hygiene",
                        file_path=rel_path_norm,
                        description="Compiled .pyc file should not be committed.",
                        recommendation="Add *.pyc and __pycache__/ to .gitignore. Remove cached: git rm --cached '*.pyc'.",
                        remediation="Add '*.pyc' and '__pycache__/' to .gitignore. Run: find . -name '*.pyc' -exec git rm --cached {} \\; (or equivalent).",
                    )
                )
            elif ext == ".pyo" or name_lower.endswith(".pyo"):
                seen_paths.add(rel_path_norm)
                findings.append(
                    _make_finding(
                        rule_id="RH004b",
                        title="Python optimized bytecode file tracked",
                        severity="LOW",
                        category="Repository Hygiene",
                        file_path=rel_path_norm,
                        description="Compiled .pyo file should not be committed.",
                        recommendation="Add *.pyo and __pycache__/ to .gitignore. Remove from index: git rm --cached '*.pyo'.",
                        remediation="Add '*.pyo' and '__pycache__/' to .gitignore. Run: git rm --cached '*.pyo' (or find and remove).",
                    )
                )

            # Scan text-like files for secret patterns -> CRITICAL finding
            _scan_file_for_secrets(
                file_path_abs=file_path_abs,
                rel_path_norm=rel_path_norm,
                name_lower=name_lower,
                findings=findings,
                seen_paths=seen_paths,
            )

    return findings


def check_gitignore_hygiene(root_path: str) -> List[Dict[str, Any]]:
    """
    Check that .gitignore contains critical patterns. If risky paths exist on disk
    but .gitignore is missing patterns (or files are still tracked), emit findings.
    """
    root = Path(root_path).resolve()
    repo_root = _find_repo_root(root)
    if repo_root is None:
        return []
    gitignore_path = repo_root / ".gitignore"
    findings: List[Dict[str, Any]] = []

    present_patterns, missing_patterns = _read_gitignore_patterns(gitignore_path)

    if missing_patterns:
        missing_list = [m for m, _ in missing_patterns]
        findings.append(
            _make_finding(
                rule_id="RH010",
                title=".gitignore missing critical patterns",
                severity="HIGH",
                category="Repository Hygiene",
                file_path=".gitignore",
                description=".gitignore does not include recommended patterns: "
                + ", ".join(missing_list)
                + ". Adding patterns only affects future commits; files already tracked remain in the index and in git history until removed with git rm --cached.",
                recommendation="Add the missing patterns to .gitignore. Remove any already-tracked sensitive files from the index with 'git rm --cached <file>' so they are not committed again.",
                remediation="Add to .gitignore: "
                + " ; ".join(missing_list)
                + ". Then remove already-tracked sensitive files: git rm --cached <file>. Avoid committing .env or cache artifacts.",
            )
        )

    # If .gitignore exists but we found sensitive paths on disk, add a note that rules don't remove tracked files
    if gitignore_path.exists() and present_patterns:
        # We could run `git check-ignore` or list tracked files; for simplicity we add one finding
        # when .gitignore has some patterns but we recommend verifying no sensitive files are tracked
        findings.append(
            _make_finding(
                rule_id="RH011",
                title="Verify sensitive files are not tracked",
                severity="MEDIUM",
                category="Repository Hygiene",
                file_path=".gitignore",
                description=".gitignore only prevents untracked files from being added; it does not untrack or remove files already in the index. Sensitive or cache files already committed remain in repository history until explicitly removed.",
                recommendation="Run 'git ls-files' to list tracked files. For any .env, __pycache__, *.pyc, or venv paths: use 'git rm --cached <file>' to stop tracking. Rotate any exposed secrets.",
                remediation="Run: git ls-files | grep -E '\\.env|__pycache__|\\.pyc|venv' (or equivalent). For any listed file: git rm --cached <file>. Clean build/cache artifacts and avoid committing environment files.",
            )
        )

    return findings


def _find_repo_root(start: Path) -> Optional[Path]:
    """Find the nearest parent directory containing .git or .gitignore."""
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / ".gitignore").exists():
            return candidate
    return None


def _read_gitignore_patterns(
    gitignore_path: Path,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Return (present_patterns, missing_patterns) from REQUIRED_GITIGNORE_PATTERNS."""
    present: List[Tuple[str, str]] = []
    missing: List[Tuple[str, str]] = []

    if not gitignore_path.exists():
        return [], list(REQUIRED_GITIGNORE_PATTERNS)

    try:
        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except OSError:
        return [], list(REQUIRED_GITIGNORE_PATTERNS)

    for pattern, desc in REQUIRED_GITIGNORE_PATTERNS:
        if any(pattern in line or line == pattern for line in lines):
            present.append((pattern, desc))
        else:
            missing.append((pattern, desc))

    return present, missing


def get_hygiene_rule_metadata() -> List[Dict[str, Any]]:
    """Return rule metadata for repository hygiene rules (for SARIF and reporting)."""
    return [
        {
            "rule_id": "RH001",
            "title": "Tracked cache or build directory",
            "severity": "MEDIUM",
            "category": "Repository Hygiene",
            "description": "Directory should not be committed.",
            "recommendation": "Add to .gitignore and remove from index if tracked.",
        },
        {
            "rule_id": "RH002",
            "title": "Environment or secret file tracked",
            "severity": "HIGH",
            "category": "Sensitive Artifacts",
            "description": "Environment/secret file should not be committed.",
            "recommendation": "Add to .gitignore; revoke/rotate if exposed.",
        },
        {
            "rule_id": "RH003",
            "title": "Private key or certificate artifact",
            "severity": "HIGH",
            "category": "Secret Exposure",
            "description": "Private key or cert should never be committed.",
            "recommendation": "Remove and rotate/revoke credentials.",
        },
        {
            "rule_id": "RH004",
            "title": "Python bytecode file tracked",
            "severity": "LOW",
            "category": "Repository Hygiene",
            "description": ".pyc should not be committed.",
            "recommendation": "Add *.pyc and __pycache__/ to .gitignore.",
        },
        {
            "rule_id": "RH004b",
            "title": "Python optimized bytecode file tracked",
            "severity": "LOW",
            "category": "Repository Hygiene",
            "description": ".pyo should not be committed.",
            "recommendation": "Add *.pyo and __pycache__/ to .gitignore.",
        },
        {
            "rule_id": "RH005",
            "title": "Secret or API key detected in file",
            "severity": "CRITICAL",
            "category": "Secret Exposure",
            "description": "File content matches a secret or API key pattern. Exposed secrets in version control are critical: they remain in git history and can be exploited until revoked and rotated.",
            "recommendation": "Revoke and rotate the credential immediately. Remove the file from the repo and add to .gitignore; consider purging from history (e.g. BFG or git filter-repo).",
        },
        {
            "rule_id": "RH010",
            "title": ".gitignore missing critical patterns",
            "severity": "HIGH",
            "category": "Repository Hygiene",
            "description": ".gitignore missing recommended patterns.",
            "recommendation": "Add patterns and remove tracked sensitive files.",
        },
        {
            "rule_id": "RH011",
            "title": "Verify sensitive files are not tracked",
            "severity": "MEDIUM",
            "category": "Repository Hygiene",
            "description": ".gitignore rules do not remove already tracked files; use git rm --cached.",
            "recommendation": "Use git rm --cached for any tracked sensitive paths.",
        },
    ]
