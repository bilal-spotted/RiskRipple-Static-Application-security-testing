"""
Tests for the repository risk scoring model.

Validates count-based severity scoring (CRITICAL×10, HIGH×6, MEDIUM×3, LOW×1),
RiskSummary, compute_risk_score, risk level boundaries, and top risky file/category.
All scoring is deterministic and explainable.
"""

import unittest

from core.risk import (
    TAINT_FLOW_BONUS_PER_FINDING,
    RiskSummary,
    build_risk_summary,
    calculate_file_risk_score,
    calculate_repository_risk_score,
    compute_risk_breakdown,
    compute_risk_score,
    get_risk_level,
    get_top_risky_categories,
    get_top_risky_files,
    severity_counts_to_risk_summary,
    summarize_severity_counts,
)


class TestRiskSmoke(unittest.TestCase):
    """Basic smoke tests for risk functions."""

    def test_risk_functions_return_reasonable_values(self):
        findings = [
            {"file_path": "a.py", "severity": "HIGH", "confidence": "HIGH"},
            {"file_path": "a.py", "severity": "MEDIUM", "confidence": "MEDIUM"},
            {"file_path": "b.py", "severity": "LOW", "confidence": "LOW"},
        ]

        counts = summarize_severity_counts(findings)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 1)

        repo_score = calculate_repository_risk_score(findings)
        self.assertGreaterEqual(repo_score, 0)

        top_files = get_top_risky_files(findings, top_n=5)
        self.assertTrue(top_files)
        self.assertIn("file_path", top_files[0])
        self.assertIn("risk_score", top_files[0])

        file_score = calculate_file_risk_score([f for f in findings if f["file_path"] == "a.py"])
        self.assertGreater(file_score, 0)


class TestSeverityWeighting(unittest.TestCase):
    """Count-based severity scoring: CRITICAL×10, HIGH×6, MEDIUM×3, LOW×1."""

    def test_single_critical_contribution(self):
        findings = [{"file_path": "x.py", "severity": "CRITICAL", "confidence": "HIGH"}]
        score, breakdown = compute_risk_breakdown(findings)
        self.assertEqual(score, 10)
        self.assertEqual(breakdown["critical_contribution"], 10)
        self.assertEqual(breakdown["severity_contribution"], 10)

    def test_single_high_contribution(self):
        findings = [{"file_path": "x.py", "severity": "HIGH", "confidence": "MEDIUM"}]
        score, breakdown = compute_risk_breakdown(findings)
        self.assertEqual(score, 6)
        self.assertEqual(breakdown["high_contribution"], 6)
        self.assertEqual(breakdown["severity_contribution"], 6)

    def test_single_medium_and_low(self):
        findings = [
            {"file_path": "x.py", "severity": "MEDIUM", "confidence": "MEDIUM"},
            {"file_path": "x.py", "severity": "LOW", "confidence": "LOW"},
        ]
        score, breakdown = compute_risk_breakdown(findings)
        self.assertEqual(score, 4)  # 3 + 1
        self.assertEqual(breakdown["medium_contribution"], 3)
        self.assertEqual(breakdown["low_contribution"], 1)
        self.assertEqual(breakdown["severity_contribution"], 4)

    def test_deterministic_same_findings_same_score(self):
        findings = [
            {"file_path": "a.py", "severity": "HIGH", "confidence": "HIGH"},
            {"file_path": "b.py", "severity": "MEDIUM", "confidence": "LOW"},
        ]
        s1 = calculate_repository_risk_score(findings)
        s2 = calculate_repository_risk_score(findings)
        self.assertEqual(s1, s2)


class TestTaintFlowBonus(unittest.TestCase):
    """Taint-flow bonus applies to file-level score only (not repository count-based score)."""

    def test_file_score_includes_taint_bonus(self):
        base = [{"file_path": "a.py", "severity": "LOW", "confidence": "LOW"}]
        taint = [{"file_path": "a.py", "severity": "LOW", "confidence": "LOW", "taint_flow": True}]
        base_score = calculate_file_risk_score(base)
        taint_score = calculate_file_risk_score(taint)
        self.assertGreater(taint_score, base_score)
        self.assertGreaterEqual(taint_score - base_score, TAINT_FLOW_BONUS_PER_FINDING)


class TestHygieneFindings(unittest.TestCase):
    """Findings in hygiene/secret categories count by severity plus category bonuses."""

    def test_hygiene_finding_counted_by_severity(self):
        findings = [
            {
                "file_path": ".env",
                "severity": "HIGH",
                "confidence": "HIGH",
                "category": "Repository Hygiene",
            },
        ]
        score, breakdown = compute_risk_breakdown(findings)
        self.assertEqual(breakdown["high_contribution"], 6)
        self.assertEqual(breakdown["severity_contribution"], 6)
        # Score includes severity + repository_hygiene_contribution
        self.assertGreaterEqual(score, 6)
        self.assertEqual(breakdown["repository_hygiene_contribution"], 1.5)

    def test_secret_exposure_finding_counted_by_severity(self):
        findings = [
            {
                "file_path": "x.py",
                "severity": "HIGH",
                "confidence": "HIGH",
                "category": "Secret Exposure",
            },
        ]
        score, breakdown = compute_risk_breakdown(findings)
        self.assertEqual(breakdown["severity_contribution"], 6)
        # Secret Exposure adds secret_exposure_contribution and critical_category_contribution
        self.assertGreaterEqual(score, 6)
        self.assertGreater(breakdown["secret_exposure_contribution"], 0)
        self.assertGreater(breakdown["critical_category_contribution"], 0)


class TestRiskLevelClassification(unittest.TestCase):
    """Risk level boundaries: 0–20 Low, 21–50 Moderate, 51–100 High, >100 Critical."""

    def test_low_boundary(self):
        self.assertEqual(get_risk_level(0), "Low")
        self.assertEqual(get_risk_level(10), "Low")
        self.assertEqual(get_risk_level(20), "Low")

    def test_moderate_boundary(self):
        self.assertEqual(get_risk_level(21), "Moderate")
        self.assertEqual(get_risk_level(35), "Moderate")
        self.assertEqual(get_risk_level(50), "Moderate")

    def test_high_boundary(self):
        self.assertEqual(get_risk_level(51), "High")
        self.assertEqual(get_risk_level(75), "High")
        self.assertEqual(get_risk_level(100), "High")

    def test_critical_boundary(self):
        self.assertEqual(get_risk_level(101), "Critical")
        self.assertEqual(get_risk_level(200), "Critical")


class TestTopRiskyFiles(unittest.TestCase):
    """Top risky files are ordered by file-level score."""

    def test_ordering_by_score_then_count(self):
        # a.py: 2 HIGH -> higher file score than b.py: 1 LOW
        findings = [
            {"file_path": "a.py", "severity": "HIGH", "confidence": "HIGH"},
            {"file_path": "a.py", "severity": "HIGH", "confidence": "MEDIUM"},
            {"file_path": "b.py", "severity": "LOW", "confidence": "LOW"},
        ]
        top = get_top_risky_files(findings, top_n=5)
        self.assertEqual(len(top), 2)
        self.assertEqual(top[0]["file_path"], "a.py")
        self.assertGreaterEqual(top[0]["risk_score"], top[1]["risk_score"])
        self.assertEqual(top[0]["findings_count"], 2)
        self.assertEqual(top[1]["findings_count"], 1)

    def test_top_n_limit(self):
        findings = [
            {"file_path": "f1.py", "severity": "LOW", "confidence": "LOW"},
            {"file_path": "f2.py", "severity": "LOW", "confidence": "LOW"},
            {"file_path": "f3.py", "severity": "LOW", "confidence": "LOW"},
        ]
        top = get_top_risky_files(findings, top_n=2)
        self.assertEqual(len(top), 2)

    def test_file_score_uses_same_weights(self):
        # One CRITICAL finding -> file score should reflect severity weight
        findings = [{"file_path": "x.py", "severity": "CRITICAL", "confidence": "HIGH"}]
        score = calculate_file_risk_score(findings)
        self.assertGreaterEqual(score, 10)


class TestTopRiskyCategories(unittest.TestCase):
    """Top risky categories aggregate by finding count."""

    def test_categories_aggregated(self):
        findings = [
            {"file_path": "a.py", "category": "Command Injection", "severity": "HIGH"},
            {"file_path": "b.py", "category": "Command Injection", "severity": "HIGH"},
            {"file_path": "c.py", "category": "SQL Injection", "severity": "MEDIUM"},
        ]
        top = get_top_risky_categories(findings, top_n=10)
        self.assertEqual(len(top), 2)
        cmd = next((x for x in top if x["category"] == "Command Injection"), None)
        sql = next((x for x in top if x["category"] == "SQL Injection"), None)
        self.assertIsNotNone(cmd)
        self.assertIsNotNone(sql)
        self.assertEqual(cmd["count"], 2)
        self.assertEqual(sql["count"], 1)

    def test_top_n_categories(self):
        findings = [
            {"file_path": "a.py", "category": "Cat1", "severity": "LOW"},
            {"file_path": "b.py", "category": "Cat2", "severity": "LOW"},
            {"file_path": "c.py", "category": "Cat3", "severity": "LOW"},
        ]
        top = get_top_risky_categories(findings, top_n=2)
        self.assertEqual(len(top), 2)


class TestBuildRiskSummary(unittest.TestCase):
    """build_risk_summary returns all expected keys."""

    def test_summary_has_all_keys(self):
        findings = [{"file_path": "x.py", "severity": "LOW", "confidence": "LOW"}]
        summary = build_risk_summary(findings, top_files_n=5, top_categories_n=5)
        self.assertIn("repository_risk_score", summary)
        self.assertIn("risk_level", summary)
        self.assertIn("risk_level_css_class", summary)
        self.assertIn("score_breakdown", summary)
        self.assertIn("severity_counts", summary)
        self.assertIn("top_risky_files", summary)
        self.assertIn("top_risky_categories", summary)
        self.assertIn("total_findings", summary)
        self.assertEqual(summary["total_findings"], 1)

    def test_empty_findings(self):
        summary = build_risk_summary([], top_files_n=5, top_categories_n=5)
        self.assertEqual(summary["repository_risk_score"], 0)
        self.assertEqual(summary["risk_level"], "Low")
        self.assertEqual(summary["top_risky_files"], [])
        self.assertEqual(summary["top_risky_categories"], [])

    def test_score_breakdown_has_all_components(self):
        """Full breakdown includes taint, secret, hygiene, concentration, critical category."""
        findings = [
            {"file_path": "a.py", "severity": "HIGH", "confidence": "HIGH", "taint_flow": True},
        ]
        _, breakdown = compute_risk_breakdown(findings)
        for key in (
            "severity_contribution",
            "taint_flow_contribution",
            "secret_exposure_contribution",
            "repository_hygiene_contribution",
            "file_concentration_factor",
            "unique_files_factor",
            "critical_category_contribution",
        ):
            self.assertIn(key, breakdown, msg=f"Missing breakdown key: {key}")


class TestRiskSummaryAndComputeScore(unittest.TestCase):
    """RiskSummary dataclass and compute_risk_score from counts."""

    def test_risk_summary_total_findings(self):
        r = RiskSummary(critical=1, high=2, medium=3, low=4)
        self.assertEqual(r.total_findings, 10)

    def test_compute_risk_score_from_summary(self):
        r = RiskSummary(critical=1, high=0, medium=0, low=0)
        self.assertEqual(compute_risk_score(r), 10)
        r2 = RiskSummary(critical=0, high=1, medium=1, low=1)
        self.assertEqual(compute_risk_score(r2), 6 + 3 + 1)

    def test_compute_risk_score_from_counts_dict(self):
        counts = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        self.assertEqual(compute_risk_score(counts), 16)
        self.assertEqual(compute_risk_score({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}), 0)

    def test_severity_counts_to_risk_summary(self):
        counts = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
        r = severity_counts_to_risk_summary(counts)
        self.assertEqual(r.critical, 2)
        self.assertEqual(r.high, 1)
        self.assertEqual(r.medium, 1)
        self.assertEqual(r.low, 0)
        self.assertEqual(compute_risk_score(r), 2 * 10 + 6 + 3)


class TestEdgeCases(unittest.TestCase):
    """Empty inputs and legacy field names."""

    def test_empty_findings_zero_score(self):
        self.assertEqual(calculate_repository_risk_score([]), 0)
        self.assertEqual(calculate_file_risk_score([]), 0)
        score, breakdown = compute_risk_breakdown([])
        self.assertEqual(score, 0)
        self.assertEqual(breakdown["severity_contribution"], 0)
        self.assertEqual(breakdown["critical_contribution"], 0)

    def test_legacy_file_field(self):
        findings = [{"file": "legacy.py", "severity": "HIGH", "confidence": "HIGH"}]
        top = get_top_risky_files(findings, top_n=5)
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["file_path"], "legacy.py")
        score = calculate_repository_risk_score(findings)
        self.assertGreater(score, 0)


if __name__ == "__main__":
    unittest.main()
