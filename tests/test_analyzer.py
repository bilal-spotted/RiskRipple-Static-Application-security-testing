import tempfile
import unittest
from pathlib import Path

from core.analyzer import analyze_file


class TestAnalyzerSmoke(unittest.TestCase):
    def test_analyze_sample_vuln_file_finds_issues(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "vulnerable_sample.py"
        findings = analyze_file(str(sample))

        self.assertIsInstance(findings, list)
        self.assertGreaterEqual(len(findings), 1)

        rule_ids = {f.get("rule_id") for f in findings}
        # AST rules should trigger on this sample.
        self.assertTrue({"PY001", "PY003", "PY005", "PY006"}.intersection(rule_ids))

    def test_compile_detected_as_py007(self):
        """compile() is reported as PY007 (Code Injection)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = compile('1+1', '<str>', 'eval')\n")
            path = f.name
        try:
            findings = analyze_file(path)
            rule_ids = {f.get("rule_id") for f in findings}
            self.assertIn("PY007", rule_ids)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
