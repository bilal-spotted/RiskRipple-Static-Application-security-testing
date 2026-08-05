"""
Tests for repository hygiene and .gitignore checks.

Covers: sensitive file detection, .env/.pyc/__pycache__/key artifacts,
.gitignore pattern validation, and remediation guidance in findings.
"""

import tempfile
import unittest
from pathlib import Path

from core.repo_hygiene import (
    check_gitignore_hygiene,
    get_hygiene_rule_metadata,
    scan_repository_hygiene,
)


class TestRepositoryHygieneDetection(unittest.TestCase):
    """Test scan_repository_hygiene detects sensitive artifacts."""

    def test_scan_empty_dir_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = scan_repository_hygiene(tmp)
        self.assertIsInstance(findings, list)
        self.assertEqual(len(findings), 0)

    def test_scan_non_directory_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            findings = scan_repository_hygiene(path)
            self.assertEqual(findings, [])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_detects_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            env_path.write_text("KEY=value\n", encoding="utf-8")
            findings = scan_repository_hygiene(tmp)
        env_findings = [f for f in findings if f.get("rule_id") == "RH002"]
        self.assertGreaterEqual(len(env_findings), 1)
        self.assertEqual(env_findings[0].get("category"), "Sensitive Artifacts")
        self.assertIn("remediation", env_findings[0])
        self.assertIn("git rm", env_findings[0]["remediation"])

    def test_detects_pyc_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pyc = Path(tmp) / "foo.pyc"
            pyc.write_bytes(b"\x00\x00\x00\x00")
            findings = scan_repository_hygiene(tmp)
        pyc_findings = [f for f in findings if f.get("rule_id") == "RH004"]
        self.assertGreaterEqual(len(pyc_findings), 1)
        self.assertEqual(pyc_findings[0].get("category"), "Repository Hygiene")

    def test_detects_pem_key_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pem = Path(tmp) / "secret.pem"
            pem.write_text(
                "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n", encoding="utf-8"
            )
            findings = scan_repository_hygiene(tmp)
        key_findings = [f for f in findings if f.get("rule_id") == "RH003"]
        self.assertGreaterEqual(len(key_findings), 1)
        self.assertEqual(key_findings[0].get("category"), "Secret Exposure")
        self.assertIn("rotate", key_findings[0].get("remediation", "").lower())

    def test_detects_id_rsa(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "id_rsa"
            key.write_text("private key material", encoding="utf-8")
            findings = scan_repository_hygiene(tmp)
        key_findings = [f for f in findings if f.get("rule_id") == "RH003"]
        self.assertGreaterEqual(len(key_findings), 1)

    def test_detects_pycache_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "__pycache__"
            cache_dir.mkdir()
            (cache_dir / "foo.pyc").write_bytes(b"\x00")
            findings = scan_repository_hygiene(tmp)
        dir_findings = [f for f in findings if f.get("rule_id") == "RH001"]
        self.assertGreaterEqual(len(dir_findings), 1)
        self.assertIn("__pycache__", dir_findings[0].get("file_path", ""))

    def test_detects_pyo_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pyo = Path(tmp) / "module.pyo"
            pyo.write_bytes(b"\x00\x00\x00\x00")
            findings = scan_repository_hygiene(tmp)
        pyo_findings = [f for f in findings if f.get("rule_id") == "RH004b"]
        self.assertGreaterEqual(len(pyo_findings), 1)
        self.assertEqual(pyo_findings[0].get("category"), "Repository Hygiene")
        self.assertIn("*.pyo", pyo_findings[0].get("remediation", ""))

    def test_detects_secret_pattern_openai(self) -> None:
        """Detect OpenAI-style API key (sk-...) in a file -> CRITICAL."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "config.py"
            # Use a 40+ char key as per spec
            # sk- + 40+ alphanumeric (pattern: sk-[A-Za-z0-9]{40,})
            f.write_text(
                "OPENAI_API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ'\n",
                encoding="utf-8",
            )
            findings = scan_repository_hygiene(tmp)
        secret_findings = [x for x in findings if x.get("rule_id") == "RH005"]
        self.assertGreaterEqual(len(secret_findings), 1)
        self.assertEqual(secret_findings[0].get("severity"), "CRITICAL")
        self.assertIn("Secret Exposure", secret_findings[0].get("category", ""))

    def test_detects_secret_pattern_aws(self) -> None:
        """Detect AWS access key (AKIA...) in a file -> CRITICAL."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "creds.txt"
            f.write_text("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
            findings = scan_repository_hygiene(tmp)
        secret_findings = [x for x in findings if x.get("rule_id") == "RH005"]
        self.assertGreaterEqual(len(secret_findings), 1)
        self.assertEqual(secret_findings[0].get("severity"), "CRITICAL")

    def test_detects_secret_pattern_github(self) -> None:
        """Detect GitHub token (ghp_...) in a file -> CRITICAL."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "token.env"
            # ghp_ + exactly 36 alphanumeric chars per spec
            f.write_text(
                "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8"
            )
            findings = scan_repository_hygiene(tmp)
        secret_findings = [x for x in findings if x.get("rule_id") == "RH005"]
        self.assertGreaterEqual(len(secret_findings), 1)
        self.assertEqual(secret_findings[0].get("severity"), "CRITICAL")

    def test_findings_have_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text("x=1", encoding="utf-8")
            findings = scan_repository_hygiene(tmp)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("rule_id", f)
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("category", f)
            self.assertIn("file_path", f)
            self.assertIn("recommendation", f)
            self.assertIn("remediation", f)


class TestGitignoreHygiene(unittest.TestCase):
    """Test check_gitignore_hygiene for missing patterns and tracked-file guidance."""

    def test_missing_gitignore_reports_missing_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # No .gitignore
            findings = check_gitignore_hygiene(tmp)
        rh010 = [f for f in findings if f.get("rule_id") == "RH010"]
        self.assertGreaterEqual(len(rh010), 1)
        self.assertIn(".gitignore", rh010[0].get("description", ""))

    def test_complete_gitignore_has_no_rh010(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gi = Path(tmp) / ".gitignore"
            gi.write_text(
                ".env\n__pycache__/\n*.pyc\n*.pyo\nvenv/\n.venv/\n",
                encoding="utf-8",
            )
            findings = check_gitignore_hygiene(tmp)
        rh010 = [f for f in findings if f.get("rule_id") == "RH010"]
        self.assertEqual(len(rh010), 0)

    def test_gitignore_with_some_patterns_may_emit_rh011(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gi = Path(tmp) / ".gitignore"
            gi.write_text(".env\n__pycache__/\n", encoding="utf-8")
            findings = check_gitignore_hygiene(tmp)
        # RH010 if patterns still missing, RH011 when .gitignore exists and has some patterns
        rule_ids = {f.get("rule_id") for f in findings}
        self.assertTrue("RH010" in rule_ids or "RH011" in rule_ids)

    def test_gitignore_findings_have_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = check_gitignore_hygiene(tmp)
        for f in findings:
            self.assertIn("remediation", f)
            self.assertIn("git rm", f.get("remediation", "") or "")

    def test_gitignore_warning_mentions_rm_cached(self) -> None:
        """RH010/RH011 should explain that .gitignore does not remove tracked files."""
        with tempfile.TemporaryDirectory() as tmp:
            findings = check_gitignore_hygiene(tmp)
        all_remediation = " ".join(
            f.get("remediation", "") or f.get("description", "") for f in findings
        )
        self.assertIn("git rm", all_remediation)
        self.assertTrue(
            "cached" in all_remediation or "tracked" in all_remediation.lower(),
            "Hygiene findings should mention git rm --cached or tracked files",
        )


class TestHygieneRuleMetadata(unittest.TestCase):
    """Test get_hygiene_rule_metadata for SARIF/reporting."""

    def test_returns_list_of_rule_dicts(self) -> None:
        meta = get_hygiene_rule_metadata()
        self.assertIsInstance(meta, list)
        self.assertGreater(len(meta), 0)

    def test_each_rule_has_id_title_category(self) -> None:
        meta = get_hygiene_rule_metadata()
        for rule in meta:
            self.assertIn("rule_id", rule)
            self.assertIn("title", rule)
            self.assertIn("category", rule)
            self.assertIn("severity", rule)


class TestReportSerializationOfHygieneFindings(unittest.TestCase):
    """Test that reports include repository hygiene findings correctly."""

    def test_json_report_includes_hygiene_findings(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        from reports.json_report import generate_json_report

        report_data = {
            "target": ".",
            "files_scanned": 0,
            "total_findings": 1,
            "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "repository_risk_score": 10,
            "top_risky_files": [],
            "findings": [
                {
                    "rule_id": "RH002",
                    "title": "Environment or secret file tracked",
                    "severity": "HIGH",
                    "category": "Sensitive Artifacts",
                    "file_path": ".env",
                    "description": "desc",
                    "recommendation": "rec",
                    "remediation": "Revoke keys; git rm --cached .env",
                }
            ],
            "scan_errors": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            generate_json_report(report_data, out)
            data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["rule_id"], "RH002")
        self.assertEqual(data["findings"][0]["category"], "Sensitive Artifacts")

    def test_markdown_report_includes_repository_hygiene_section(self) -> None:
        from reports.markdown_report import generate_markdown_report

        report_data = {
            "target": ".",
            "files_scanned": 0,
            "total_findings": 1,
            "severity_counts": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "repository_risk_score": 10,
            "top_risky_files": [],
            "findings": [
                {
                    "rule_id": "RH010",
                    "title": ".gitignore missing critical patterns",
                    "severity": "HIGH",
                    "category": "Repository Hygiene",
                    "file_path": ".gitignore",
                    "description": "Missing patterns.",
                    "recommendation": "Add them.",
                    "remediation": "Add .env to .gitignore.",
                }
            ],
            "scan_errors": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.md"
            generate_markdown_report(report_data, out)
            text = out.read_text(encoding="utf-8")
        self.assertIn("Repository Hygiene & Sensitive Artifacts", text)
        self.assertIn(".gitignore missing critical patterns", text)
        self.assertIn("Remediation:", text)


if __name__ == "__main__":
    unittest.main()
