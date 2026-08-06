"""
Git repository context for hygiene analysis.

The repository hygiene rules make claims like "environment file tracked" and
"tracked cache directory", but historically they were pure filesystem walks:
nothing ever asked git whether a file was actually in the repository. That
produced confident false positives - a self-scan reported eight ``__pycache__``
directories as "tracked" when all eight were gitignored and none were in the
index.

This module supplies the missing fact. A file's relationship to the repository
determines whether it is a problem at all:

``tracked``
    The file is in the index. Its contents are in the repository and, if it
    holds a secret, in the history. This is the case the rules describe.
``ignored``
    Deliberately excluded. Present on disk but not in the repository, which is
    the correct state for caches and local environment files.
``untracked``
    Neither committed nor ignored, so a stray ``git add -A`` would commit it.
    Worth flagging, but less urgent than something already committed.
``unknown``
    No git metadata available - scanning a plain directory, or git is not
    installed. Findings are still reported but worded without asserting
    tracking, since we genuinely do not know.

Git is queried through ``subprocess`` with argument lists and no shell, which
is the same practice rule PY004 recommends to users of this scanner.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, Optional, Set

# Git calls are bounded so a pathological repository cannot stall a scan.
GIT_TIMEOUT_SECONDS = 15

STATUS_TRACKED = "tracked"
STATUS_IGNORED = "ignored"
STATUS_UNTRACKED = "untracked"
STATUS_UNKNOWN = "unknown"


def _run_git(repo_root: Path, args: list[str], stdin_data: Optional[bytes] = None):
    """
    Run a git command in ``repo_root``, returning the CompletedProcess or None.

    Never raises: git may be missing, the directory may not be a repository, or
    the call may time out. Any of those means "no git information available",
    which callers degrade gracefully on.
    """
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            input=stdin_data,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _decode_nul_list(payload: bytes) -> Set[str]:
    """Split git's NUL-delimited output into a set of forward-slash paths."""
    text = payload.decode("utf-8", errors="replace")
    return {entry.replace("\\", "/") for entry in text.split("\0") if entry}


class GitContext:
    """
    Answers "what is this path's relationship to the repository?".

    Tracked files are read once up front. Ignore status is resolved in a single
    batched call, because ``git check-ignore`` per file would mean one process
    spawn per candidate.
    """

    def __init__(self, repo_root: Optional[Path], tracked: Optional[Set[str]]) -> None:
        self.repo_root = repo_root
        self._tracked = tracked or set()
        self._ignored: Set[str] = set()
        self._ignore_resolved = False

    # -- construction -------------------------------------------------------

    @classmethod
    def discover(cls, path: str | Path) -> GitContext:
        """
        Build a context for the repository containing ``path``.

        Returns an unavailable context when the path is not inside a working
        tree, so callers get consistent behaviour rather than an exception.
        """
        root = Path(path).resolve()
        probe = _run_git(root, ["rev-parse", "--show-toplevel"])
        if probe is None or probe.returncode != 0:
            return cls(None, None)

        toplevel = probe.stdout.decode("utf-8", errors="replace").strip()
        if not toplevel:
            return cls(None, None)
        repo_root = Path(toplevel).resolve()

        listing = _run_git(repo_root, ["ls-files", "-z"])
        if listing is None or listing.returncode != 0:
            return cls(repo_root, None)

        return cls(repo_root, _decode_nul_list(listing.stdout))

    @property
    def available(self) -> bool:
        """True when git metadata was successfully read."""
        return self.repo_root is not None

    # -- queries ------------------------------------------------------------

    def _repo_relative(self, absolute_path: str | Path) -> Optional[str]:
        """Express a path relative to the repository root, or None if outside."""
        if self.repo_root is None:
            return None
        try:
            return Path(absolute_path).resolve().relative_to(self.repo_root).as_posix()
        except (ValueError, OSError, RuntimeError):
            return None

    def is_tracked(self, absolute_path: str | Path) -> bool:
        """True if the path is in the git index."""
        rel = self._repo_relative(absolute_path)
        return rel is not None and rel in self._tracked

    def has_tracked_under(self, absolute_dir: str | Path) -> bool:
        """
        True if any tracked file lives under this directory.

        Directories are never in the index themselves, only their contents, so
        a directory rule such as "tracked cache directory" has to ask about the
        files beneath it.
        """
        rel = self._repo_relative(absolute_dir)
        if rel is None:
            return False
        prefix = rel.rstrip("/") + "/"
        return any(tracked.startswith(prefix) for tracked in self._tracked)

    def prime_ignored(self, absolute_paths: Iterable[str | Path]) -> None:
        """
        Resolve ignore status for a batch of paths in one git call.

        Call once with every candidate before querying status, so the cost is a
        single process spawn rather than one per file.
        """
        if self.repo_root is None:
            self._ignore_resolved = True
            return

        relatives = []
        for path in absolute_paths:
            rel = self._repo_relative(path)
            if rel and rel not in self._tracked:
                relatives.append(rel)

        if not relatives:
            self._ignore_resolved = True
            return

        payload = "\0".join(relatives).encode("utf-8")
        # --no-index so the answer reflects ignore rules alone; tracked files
        # were already filtered out above.
        result = _run_git(self.repo_root, ["check-ignore", "--stdin", "-z", "--no-index"], payload)
        if result is not None and result.returncode in (0, 1):
            self._ignored = _decode_nul_list(result.stdout)
        self._ignore_resolved = True

    def status_of(self, absolute_path: str | Path) -> str:
        """
        Classify a path as tracked, ignored, untracked, or unknown.

        ``prime_ignored`` should be called first; without it nothing can be
        reported as ignored and untracked files would be over-reported.
        """
        if self.repo_root is None:
            return STATUS_UNKNOWN
        rel = self._repo_relative(absolute_path)
        if rel is None:
            return STATUS_UNKNOWN
        if rel in self._tracked:
            return STATUS_TRACKED
        if not self._ignore_resolved:
            return STATUS_UNKNOWN
        if rel in self._ignored or self._has_ignored_ancestor(rel):
            return STATUS_IGNORED
        return STATUS_UNTRACKED

    def _has_ignored_ancestor(self, rel_path: str) -> bool:
        """True if any parent directory of this path is itself ignored."""
        parts = rel_path.split("/")
        for depth in range(1, len(parts)):
            if "/".join(parts[:depth]) in self._ignored:
                return True
        return False
