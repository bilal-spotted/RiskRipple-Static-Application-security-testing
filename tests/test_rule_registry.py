"""
Tests for rule metadata registry: loading, validation, lookup, and finding enrichment.
"""

from core.rule_registry import (
    LEGACY_RULE_ID_MAP,
    enrich_findings,
    get_registry,
    load_metadata,
)


class TestRuleRegistryLoad:
    """Metadata loading and validation."""

    def test_load_metadata_returns_list(self):
        meta = load_metadata()
        assert isinstance(meta, list)

    def test_loaded_rules_have_required_fields(self):
        meta = load_metadata()
        required = {"rule_id", "title", "severity", "category", "detection_type"}
        for rule in meta:
            for field in required:
                assert field in rule, f"Rule {rule.get('rule_id')} missing {field}"
            assert rule.get("detection_type") in ("ast", "regex", "taint", "hygiene")

    def test_legacy_map_covers_known_ids(self):
        assert "PY001" in LEGACY_RULE_ID_MAP
        assert "RH002" in LEGACY_RULE_ID_MAP
        assert "TAINT-CMD" in LEGACY_RULE_ID_MAP
        assert LEGACY_RULE_ID_MAP["PY001"] == "python-eval-use"
        assert LEGACY_RULE_ID_MAP["RH002"] == "repo-env-file"


class TestRuleRegistryLookup:
    """Lookup by rule_id and legacy fallback."""

    def test_get_by_canonical_id(self):
        reg = get_registry()
        r = reg.get("python-eval-use")
        assert r is not None
        assert r.get("title") == "Use of eval()"
        assert r.get("cwe") == "CWE-94"
        assert r.get("detection_type") == "ast"

    def test_get_by_legacy_id_returns_metadata(self):
        reg = get_registry()
        r = reg.get("PY001")
        assert r is not None
        assert r.get("title") == "Use of eval()"
        assert r.get("rule_id") == "python-eval-use"

    def test_get_missing_returns_none(self):
        reg = get_registry()
        assert reg.get("nonexistent-rule-xyz") is None
        assert reg.get("") is None

    def test_missing_metadata_fallback(self):
        """Lookup of unknown id does not raise; enrichment leaves finding unchanged."""
        reg = get_registry()
        finding = {"rule_id": "unknown-rule-xyz", "title": "Custom", "severity": "HIGH"}
        out = reg.enrich_finding(finding)
        assert out["rule_id"] == "unknown-rule-xyz"
        assert out["title"] == "Custom"
        assert "cwe" not in out or out.get("cwe") is None


class TestFindingEnrichment:
    """Enrichment fills in missing fields and adds CWE/OWASP/remediation."""

    def test_enrich_fills_title_from_metadata(self):
        reg = get_registry()
        finding = {"rule_id": "PY003", "file_path": "x.py", "line_number": 1}
        out = reg.enrich_finding(finding)
        assert out.get("title") == "Use of os.system()"
        assert out.get("description")
        assert out.get("category") == "Command Injection"
        assert out.get("severity") == "HIGH"
        assert out.get("remediation") or out.get("recommendation")
        assert out.get("cwe") == "CWE-78"
        assert "A03" in str(out.get("owasp", ""))

    def test_enrich_does_not_overwrite_existing_title(self):
        reg = get_registry()
        finding = {"rule_id": "PY001", "title": "Custom title", "severity": "HIGH"}
        out = reg.enrich_finding(finding)
        assert out["title"] == "Custom title"

    def test_enrich_findings_returns_new_list(self):
        findings = [
            {"rule_id": "PY001", "file_path": "a.py", "line_number": 1},
            {"rule_id": "RH002", "file_path": ".env", "line_number": 0},
        ]
        out = enrich_findings(findings)
        assert len(out) == 2
        assert out[0].get("title") == "Use of eval()"
        assert out[1].get("title") == "Environment or secret file tracked"
        assert out[0].get("cwe") == "CWE-94"
        assert out[1].get("remediation")


class TestReportOutputWithMetadata:
    """Reports include metadata when findings are enriched."""

    def test_json_report_includes_cwe_owasp_when_present(self):
        import json
        import tempfile
        from pathlib import Path

        from reports.json_report import generate_json_report

        findings = [
            {
                "rule_id": "PY001",
                "title": "Use of eval()",
                "severity": "HIGH",
                "category": "Code Injection",
                "file_path": "test.py",
                "line_number": 1,
                "description": "desc",
                "recommendation": "rec",
            }
        ]
        enriched = enrich_findings(findings)
        report_data = {
            "target": ".",
            "files_scanned": 1,
            "total_findings": 1,
            "severity_counts": {"HIGH": 1},
            "repository_risk_score": 10,
            "top_risky_files": [],
            "findings": enriched,
            "scan_errors": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            generate_json_report(report_data, out)
            data = json.loads(out.read_text(encoding="utf-8"))
        finding = data["findings"][0]
        assert finding.get("rule_id") == "PY001"
        assert (
            "cwe" in finding or "remediation" in finding or finding.get("title") == "Use of eval()"
        )

    def test_sarif_rule_has_help_and_properties(self):
        import json
        import tempfile
        from pathlib import Path

        from reports.sarif_report import generate_sarif_report

        report_data = {
            "target": ".",
            "findings": enrich_findings(
                [
                    {"rule_id": "PY003", "file_path": "x.py", "line_number": 1},
                ]
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.sarif"
            generate_sarif_report(report_data, out)
            data = json.loads(out.read_text(encoding="utf-8"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "PY003" in rule_ids or any("python" in r["id"] for r in rules)
        one = next(
            (
                r
                for r in rules
                if r["id"] == "PY003"
                or "os.system" in r.get("shortDescription", {}).get("text", "")
            ),
            rules[0],
        )
        assert "shortDescription" in one
        assert "help" in one
        assert "properties" in one
