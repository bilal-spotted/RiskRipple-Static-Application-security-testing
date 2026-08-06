"""
Tests for git-aware hygiene analysis.

These build real repositories with real git commands rather than mocking the
subprocess layer. The whole point of the module is that it agrees with git, so
a test that agrees only with a mock of git would prove nothing.

Every test skips cleanly when git is unavailable, so the suite still runs in
environments without it.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from core.git_context import (
    STATUS_IGNORED,
    STATUS_TRACKED,
    STATUS_UNKNOWN,
    STATUS_UNTRACKED,
    GitContext,
)
from core.repo_hygiene import scan_repository_hygiene

GIT_AVAILABLE = shutil.which("git") is not None


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=True,
        timeout=30,
    )


def _init_repo(repo: Path) -> None:
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")


@unittest.skipUnless(GIT_AVAILABLE, "git is not installed")
class TestGitContextClassification(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name).resolve()
        _init_repo(self.repo)

        (self.repo / ".gitignore").write_text("ignored.txt\ncache/\n", encoding="utf-8")
        (self.repo / "committed.py").write_text("x = 1\n", encoding="utf-8")
        (self.repo / "ignored.txt").write_text("noise\n", encoding="utf-8")
        (self.repo / "stray.txt").write_text("new\n", encoding="utf-8")
        (self.repo / "cache").mkdir()
        (self.repo / "cache" / "blob.bin").write_text("cached\n", encoding="utf-8")

        _git(self.repo, "add", ".gitignore", "committed.py")
        _git(self.repo, "commit", "-m", "initial")

        self.context = GitContext.discover(self.repo)
        self.context.prime_ignored(
            [
                self.repo / "committed.py",
                self.repo / "ignored.txt",
                self.repo / "stray.txt",
                self.repo / "cache",
            ]
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_context_is_available_in_a_repository(self) -> None:
        self.assertTrue(self.context.available)

    def test_committed_file_is_tracked(self) -> None:
        self.assertEqual(STATUS_TRACKED, self.context.status_of(self.repo / "committed.py"))

    def test_gitignored_file_is_ignored(self) -> None:
        self.assertEqual(STATUS_IGNORED, self.context.status_of(self.repo / "ignored.txt"))

    def test_new_file_is_untracked(self) -> None:
        self.assertEqual(STATUS_UNTRACKED, self.context.status_of(self.repo / "stray.txt"))

    def test_ignored_directory_is_ignored(self) -> None:
        self.assertEqual(STATUS_IGNORED, self.context.status_of(self.repo / "cache"))

    def test_is_tracked_matches_status(self) -> None:
        self.assertTrue(self.context.is_tracked(self.repo / "committed.py"))
        self.assertFalse(self.context.is_tracked(self.repo / "stray.txt"))


@unittest.skipUnless(GIT_AVAILABLE, "git is not installed")
class TestHygieneUsesGitStatus(unittest.TestCase):
    """The behaviour that motivated this module: no more false 'tracked' claims."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name).resolve()
        _init_repo(self.repo)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _rule_ids(self):
        return {f.get("rule_id") for f in scan_repository_hygiene(str(self.repo))}

    def test_gitignored_pycache_is_not_reported(self) -> None:
        """
        A self-scan previously reported eight __pycache__ directories as
        "tracked" when every one was gitignored and none were in the index.
        """
        (self.repo / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        cache = self.repo / "__pycache__"
        cache.mkdir()
        (cache / "mod.cpython-311.pyc").write_text("bytecode\n", encoding="utf-8")
        _git(self.repo, "add", ".gitignore")
        _git(self.repo, "commit", "-m", "ignore cache")

        self.assertNotIn("RH001", self._rule_ids())

    def test_committed_pycache_is_reported(self) -> None:
        """The same directory, actually committed, must still be caught."""
        cache = self.repo / "__pycache__"
        cache.mkdir()
        (cache / "mod.cpython-311.pyc").write_text("bytecode\n", encoding="utf-8")
        _git(self.repo, "add", "-f", "__pycache__")
        _git(self.repo, "commit", "-m", "oops")

        findings = scan_repository_hygiene(str(self.repo))
        rh001 = [f for f in findings if f.get("rule_id") == "RH001"]
        self.assertEqual(1, len(rh001))
        self.assertEqual(STATUS_TRACKED, rh001[0].get("git_status"))
        self.assertEqual("MEDIUM", rh001[0].get("severity"))

    def test_untracked_env_file_is_downgraded(self) -> None:
        """Present but uncommitted is a smaller problem than committed."""
        (self.repo / ".env").write_text("SECRET=1\n", encoding="utf-8")
        findings = scan_repository_hygiene(str(self.repo))
        env = [f for f in findings if f.get("rule_id") == "RH002"]
        self.assertEqual(1, len(env))
        self.assertEqual(STATUS_UNTRACKED, env[0].get("git_status"))
        self.assertEqual("MEDIUM", env[0].get("severity"), "HIGH downgrades to MEDIUM")

    def test_committed_env_file_keeps_full_severity(self) -> None:
        (self.repo / ".env").write_text("SECRET=1\n", encoding="utf-8")
        _git(self.repo, "add", "-f", ".env")
        _git(self.repo, "commit", "-m", "committed env")

        findings = scan_repository_hygiene(str(self.repo))
        env = [f for f in findings if f.get("rule_id") == "RH002"]
        self.assertEqual(1, len(env))
        self.assertEqual(STATUS_TRACKED, env[0].get("git_status"))
        self.assertEqual("HIGH", env[0].get("severity"))

    def test_gitignored_env_file_is_not_reported(self) -> None:
        """A gitignored .env is correct practice, not a finding."""
        (self.repo / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.repo / ".env").write_text("SECRET=1\n", encoding="utf-8")
        _git(self.repo, "add", ".gitignore")
        _git(self.repo, "commit", "-m", "ignore env")

        self.assertNotIn("RH002", self._rule_ids())


class TestGitContextWithoutRepository(unittest.TestCase):
    """Outside a repository the scanner must degrade, not fail."""

    def test_plain_directory_reports_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = GitContext.discover(tmp)
            self.assertFalse(context.available)
            self.assertEqual(STATUS_UNKNOWN, context.status_of(Path(tmp) / "anything.txt"))

    def test_hygiene_still_reports_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text("SECRET=1\n", encoding="utf-8")
            findings = scan_repository_hygiene(tmp)
            env = [f for f in findings if f.get("rule_id") == "RH002"]
            self.assertEqual(1, len(env))
            self.assertEqual(STATUS_UNKNOWN, env[0].get("git_status"))
            self.assertEqual("HIGH", env[0].get("severity"), "no downgrade when status is unknown")


if __name__ == "__main__":
    unittest.main()
