"""Tests for finding normalization and deduplication."""

import unittest

from core.normalize import (
    finding_fingerprint,
    normalize_and_deduplicate_findings,
    normalize_single_finding,
)


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
