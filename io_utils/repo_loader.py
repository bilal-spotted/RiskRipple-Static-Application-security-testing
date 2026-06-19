"""Repository and file collection utilities for the scanner."""

from __future__ import annotations

import os
from typing import List

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".php",
    ".rb",
    ".c",
    ".cpp",
}


EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "build",
    "dist",
}


def get_source_files(root_path: str) -> List[str]:
    """
    Recursively collect source files from a directory.

    Walks the tree under root_path, skipping EXCLUDED_DIRS, and returns
    paths to files whose extension is in SUPPORTED_EXTENSIONS.

    Args:
        root_path: Directory path to scan.

    Returns:
        List of file paths (relative or absolute depending on root_path).
    """
    source_files = []

    for root, dirs, files in os.walk(root_path):
        # remove excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            file_path = os.path.join(root, file)

            ext = os.path.splitext(file)[1].lower()

            if ext in SUPPORTED_EXTENSIONS:
                source_files.append(file_path)

    return source_files
