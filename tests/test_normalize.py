"""Tests for finding normalization and deduplication."""

import os
import tempfile
import unittest
from pathlib import Path

from core.normalize import (
    finding_fingerprint,
    normalize_and_deduplicate_findings,
    normalize_single_finding,
    relativize_path,
)


class TestPathRelativization(unittest.TestCase):
    """
    Paths must come out relative to the scan target.

    Absolute paths broke three things at once: SARIF upload (GitHub Code
    Scanning rejects absolute artifact URIs), fingerprint stability across
    machines, and per-file grouping.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_absolute_path_inside_root_becomes_relative(self) -> None:
        absolute = self.root / "pkg" / "module.py"
        self.assertEqual("pkg/module.py", relativize_path(str(absolute), self.root))

    def test_relative_path_is_left_relative(self) -> None:
        self.assertEqual("pkg/module.py", relativize_path("pkg/module.py", self.root))

    def test_separators_are_normalised_to_forward_slash(self) -> None:
        self.assertNotIn("\\", relativize_path("pkg\\sub\\module.py", self.root))

    def test_path_outside_root_is_left_alone(self) -> None:
        """Better an absolute path than a long chain of '..' segments."""
        outside = Path(tempfile.gettempdir()).resolve() / "elsewhere" / "mod.py"
        result = relativize_path(str(outside), self.root)
        self.assertNotIn("..", result)

    def test_no_root_leaves_path_normalised_only(self) -> None:
        self.assertEqual("a/b.py", relativize_path("a/b.py", None))

    def test_normalization_applies_root_to_findings(self) -> None:
        absolute = self.root / "src" / "app.py"
        out = normalize_single_finding(
            {"rule_id": "PY001", "file_path": str(absolute), "line_number": 3}, root=self.root
        )
        self.assertEqual("src/app.py", out["file_path"])
        self.assertFalse(os.path.isabs(out["file_path"]))
        self.assertEqual(out["file"], out["file_path"])

    def test_fingerprint_is_machine_independent(self) -> None:
        """
        The same finding checked out at two locations must fingerprint alike.

        Fingerprints hash the path, so before relativization the same issue
        produced a different fingerprint per machine and dedup silently failed.

        Two real temporary directories stand in for two checkouts. Literal
        POSIX paths would not work here: on Windows, ``Path('/a/b')`` is not
        absolute without a drive letter, so nothing would be relativized.
        """
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            root_a, root_b = Path(first).resolve(), Path(second).resolve()
            norm_a = normalize_single_finding(
                {
                    "rule_id": "PY001",
                    "file_path": str(root_a / "src" / "app.py"),
                    "line_number": 3,
                },
                root=root_a,
            )
            norm_b = normalize_single_finding(
                {
                    "rule_id": "PY001",
                    "file_path": str(root_b / "src" / "app.py"),
                    "line_number": 3,
                },
                root=root_b,
            )
            self.assertEqual("src/app.py", norm_a["file_path"])
            self.assertEqual(norm_a["file_path"], norm_b["file_path"])
            self.assertEqual(norm_a["fingerprint"], norm_b["fingerprint"])


class TestFindingFingerprint(unittest.TestCase):
    def test_same_location_same_rule_same_fingerprint(self):
        a = {"rule_id": "PY001", "file_path": "a.py", "line_number": 1, "title": "eval"}
        b = {"rule_id": "PY001", "file_path": "a.py", "line_number": 1, "title": "eval"}
        self.assertEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_different_line_different_fingerprint(self):
        a = {"rule_id": "PY001", "file_path": "a.py", "line_number": 1, "title": "eval"}
        b = {"rule_id": "PY001", "file_path": "a.py", "line_number": 2, "title": "eval"}
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))

    def test_different_rule_different_fingerprint(self):
        a = {"rule_id": "PY001", "file_path": "a.py", "line_number": 1, "title": "eval"}
        b = {"rule_id": "PY002", "file_path": "a.py", "line_number": 1, "title": "exec"}
        self.assertNotEqual(finding_fingerprint(a), finding_fingerprint(b))


class TestNormalizeSingleFinding(unittest.TestCase):
    def test_severity_normalized(self):
        f = {"rule_id": "X", "file_path": "f.py", "line_number": 1, "severity": "high"}
        out = normalize_single_finding(f)
        self.assertEqual(out["severity"], "HIGH")

    def test_fingerprint_added(self):
        f = {"rule_id": "X", "file_path": "f.py", "line_number": 1}
        out = normalize_single_finding(f)
        self.assertIn("fingerprint", out)
        self.assertEqual(len(out["fingerprint"]), 32)


class TestNormalizeAndDeduplicate(unittest.TestCase):
    def test_duplicates_removed(self):
        findings = [
            {"rule_id": "PY001", "file_path": "a.py", "line_number": 10, "title": "eval"},
            {"rule_id": "PY001", "file_path": "a.py", "line_number": 10, "title": "eval"},
        ]
        out = normalize_and_deduplicate_findings(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["rule_id"], "PY001")

    def test_distinct_findings_kept(self):
        findings = [
            {"rule_id": "PY001", "file_path": "a.py", "line_number": 10, "title": "eval"},
            {"rule_id": "PY002", "file_path": "a.py", "line_number": 11, "title": "exec"},
        ]
        out = normalize_and_deduplicate_findings(findings)
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main()
