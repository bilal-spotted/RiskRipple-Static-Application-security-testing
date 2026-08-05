from pathlib import Path

# Default set of extensions to scan. Can be overridden via CLI.
ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".rs",
    ".php",
    ".cpp",
    ".c",
    ".cs",
}

SECURITY_KEYWORDS = [
    "auth",
    "login",
    "admin",
    "session",
    "token",
    "crypto",
    "crypt",
    "db",
    "database",
    "config",
    "secret",
    "user",
    "permission",
    "middleware",
    "api",
]

SKIP_DIR_NAMES = {".git", "venv", "node_modules", "dist", "build", "__pycache__"}


def _extension_priority(suffix: str) -> int:
    """
    Simple heuristic to prioritize more interesting source files first.
    Lower numbers are higher priority.
    """
    priority_order = [
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rs",
        ".php",
        ".cs",
        ".cpp",
        ".c",
    ]
    try:
        return priority_order.index(suffix.lower())
    except ValueError:
        return len(priority_order)


def _has_security_keyword(path: Path) -> bool:
    lowered = "/".join(path.parts).lower()
    return any(keyword in lowered for keyword in SECURITY_KEYWORDS)


def collect_source_files(
    repo_path: Path,
    max_files: int = 50,
    extensions: set[str] | None = None,
) -> list[Path]:
    """
    Collect candidate source files, prioritizing security-relevant names.
    """
    if extensions is None:
        extensions = ALLOWED_EXTENSIONS

    files: list[Path] = []

    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue

        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue

        if path.suffix.lower() not in extensions:
            continue

        files.append(path)

    # Prioritize by:
    # 1) security keyword in path (True first),
    # 2) extension priority,
    # 3) shorter paths first.
    files.sort(
        key=lambda p: (
            0 if _has_security_keyword(p) else 1,
            _extension_priority(p.suffix),
            len(str(p)),
        )
    )

    return files[:max_files]


def read_file_content(file_path: Path, max_chars: int = 6000) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception as e:
        return f"ERROR READING FILE: {e}"
