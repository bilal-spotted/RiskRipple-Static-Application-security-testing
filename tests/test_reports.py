import tempfile
import unittest
from pathlib import Path

from core.severity import SEVERITY_LEVELS
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report
from reports.sarif_report import generate_sarif_report


class TestReportsSmoke(unittest.TestCase):
    def test_reports_generate_files(self):
        report_data = {
            "target": "sample",
            "files_scanned": 1,
            "total_findings": 1,
            "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "repository_risk_score": 10,
            "top_risky_files": [
                {
                    "file_path": "sample.py",
                    "risk_score": 10,
                    "findings_count": 1,
                    "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
                }
            ],
            "findings": [
                {
                    "rule_id": "X",
                    "title": "Test Finding",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "category": "Test",
                    "file_path": "sample.py",
                    "line_number": 1,
                    "code_snippet": ">>    1: eval('1')",
                    "description": "desc",
                    "recommendation": "fix",
                }
            ],
            "scan_errors": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            md = tmp_path / "security_report.md"
            html = tmp_path / "security_report.html"
            js = tmp_path / "security_report.json"
            sarif = tmp_path / "security_report.sarif"

            generate_markdown_report(report_data, md)
            generate_html_report(report_data, html)
            generate_json_report(report_data, js)
            generate_sarif_report(report_data, sarif)

            self.assertTrue(md.exists())
            self.assertTrue(html.exists())
            self.assertTrue(js.exists())
            self.assertTrue(sarif.exists())

            self.assertIn("Risk Ripple Report", md.read_text(encoding="utf-8"))
            self.assertIn("Risk Ripple", html.read_text(encoding="utf-8"))
            self.assertIn('"tool": "Risk Ripple"', js.read_text(encoding="utf-8"))
            self.assertIn('"version": "2.1.0"', sarif.read_text(encoding="utf-8"))

    def test_report_data_severity_counts_include_all_levels(self):
        """Severity counts used in reports should support CRITICAL, HIGH, MEDIUM, LOW."""
        from scanner import build_report_data

        target = Path(__file__).resolve().parents[1] / "samples"
        files = ["samples/vulnerable_sample.py"]
        findings = [
            {
                "file_path": "a.py",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "Secret Exposure",
            },
            {
                "file_path": "b.py",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "category": "Command Injection",
            },
        ]
        errors = []
        data = build_report_data(target, files, findings, errors, top_files_n=5, top_categories_n=5)
        for level in SEVERITY_LEVELS:
            self.assertIn(level, data["severity_counts"])
        self.assertEqual(data["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(data["severity_counts"]["HIGH"], 1)
        self.assertIn("score_breakdown", data)
        self.assertIn("risk_level", data)
        self.assertIn("top_risky_categories", data)


if __name__ == "__main__":
    unittest.main()
