"""
Benchmark corpus regression tests.

The benchmark directory holds paired implementations of the same operation:
one vulnerable, one safe. Together they form the scanner's executable
correctness contract:

* every ``*_vulnerable.py`` MUST produce at least one finding (no false negatives)
* every ``*_safe.py`` MUST produce exactly zero findings (no false positives)

These two properties are what "detection accuracy" means for this project, so
they are asserted rather than measured by hand. A failure here means the
detection engine regressed, not that the test is wrong. Resist the urge to
relax an assertion: fix the engine, or move the fixture out of the benchmark
and document why.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any, Dict, List

from core.analyzer import analyze_file

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "benchmark"

# Each vulnerable fixture must be caught by at least one of these rule IDs.
# This pins *which* engine catches *what*, so a rule silently ceasing to fire
# is caught even if some unrelated rule still produces a finding for the file.
EXPECTED_RULES: Dict[str, set] = {
    "command_injection_vulnerable.py": {"PY003", "PY004", "TAINT-CMD"},
    "sql_injection_vulnerable.py": {"TAINT-SQL"},
    "path_traversal_vulnerable.py": {"TAINT-PATH"},
    "deserialization_vulnerable.py": {"PY005", "PY006"},
    "weak_crypto_vulnerable.py": {"SEC005", "SEC006", "SEC009"},
    "secret_exposure_vulnerable.py": {"SEC001", "SEC002"},
}


def _vulnerable_fixtures() -> List[Path]:
    return sorted(BENCHMARK_DIR.glob("*_vulnerable.py"))


def _safe_fixtures() -> List[Path]:
    return sorted(BENCHMARK_DIR.glob("*_safe.py"))


def _describe(findings: List[Dict[str, Any]]) -> str:
    """Render findings compactly so a failure message is actionable."""
    if not findings:
        return "no findings"
    return "; ".join(
        f"{f.get('rule_id')} at line {f.get('line_number')} ({f.get('title')})" for f in findings
    )


class TestBenchmarkCorpusIntegrity(unittest.TestCase):
    """The corpus itself must stay complete and paired."""

    def test_benchmark_directory_exists(self) -> None:
        self.assertTrue(BENCHMARK_DIR.is_dir(), f"benchmark directory missing: {BENCHMARK_DIR}")

    def test_every_vulnerable_fixture_has_a_safe_pair(self) -> None:
        vulnerable = {p.name.replace("_vulnerable.py", "") for p in _vulnerable_fixtures()}
        safe = {p.name.replace("_safe.py", "") for p in _safe_fixtures()}
        self.assertEqual(
            vulnerable,
            safe,
            "every vulnerable fixture needs a safe counterpart (and vice versa)",
        )

    def test_corpus_covers_expected_categories(self) -> None:
        found = {p.name for p in _vulnerable_fixtures()}
        missing = set(EXPECTED_RULES) - found
        self.assertFalse(missing, f"expected benchmark fixtures are missing: {sorted(missing)}")


class TestNoFalseNegatives(unittest.TestCase):
    """Every vulnerable fixture must be detected."""

    def test_all_vulnerable_fixtures_produce_findings(self) -> None:
        fixtures = _vulnerable_fixtures()
        self.assertTrue(fixtures, "no vulnerable fixtures found")

        undetected = []
        for path in fixtures:
            if not analyze_file(str(path)):
                undetected.append(path.name)

        self.assertFalse(
            undetected,
            "vulnerable fixtures produced no findings (false negatives): "
            f"{undetected}. The scanner fails to detect code its own benchmark "
            "documents as vulnerable.",
        )

    def test_vulnerable_fixtures_trigger_their_expected_rules(self) -> None:
        for name, expected in EXPECTED_RULES.items():
            path = BENCHMARK_DIR / name
            if not path.exists():
                self.fail(f"expected benchmark fixture missing: {name}")
            with self.subTest(fixture=name):
                findings = analyze_file(str(path))
                actual = {f.get("rule_id") for f in findings}
                self.assertTrue(
                    actual & expected,
                    f"{name}: expected one of {sorted(expected)}, got {_describe(findings)}",
                )


class TestNoFalsePositives(unittest.TestCase):
    """Safe fixtures are correct implementations and must stay silent."""

    def test_all_safe_fixtures_produce_no_findings(self) -> None:
        fixtures = _safe_fixtures()
        self.assertTrue(fixtures, "no safe fixtures found")

        for path in fixtures:
            with self.subTest(fixture=path.name):
                findings = analyze_file(str(path))
                self.assertEqual(
                    [],
                    findings,
                    f"{path.name} is a correct implementation but produced "
                    f"findings (false positives): {_describe(findings)}",
                )


class TestDetectionAccuracy(unittest.TestCase):
    """The headline accuracy figures the project claims."""

    def test_detection_rate_is_total(self) -> None:
        fixtures = _vulnerable_fixtures()
        detected = sum(1 for p in fixtures if analyze_file(str(p)))
        self.assertEqual(
            len(fixtures),
            detected,
            f"detection rate {detected}/{len(fixtures)} - expected all vulnerable "
            "fixtures to be detected",
        )

    def test_false_positive_rate_is_zero(self) -> None:
        fixtures = _safe_fixtures()
        clean = sum(1 for p in fixtures if not analyze_file(str(p)))
        self.assertEqual(
            len(fixtures),
            clean,
            f"only {clean}/{len(fixtures)} safe fixtures were clean - expected zero "
            "false positives",
        )


class TestPathTraversalGuardRecognition(unittest.TestCase):
    """
    Regression tests for the containment-guard logic.

    The safe path-traversal fixture derives its path from a parameter, so it is
    only distinguishable from the vulnerable one by its containment check.
    These tests pin that reasoning, including the important negative case:
    os.path.normpath alone must NOT be treated as a defence.
    """

    def _findings_for(self, code: str) -> List[Dict[str, Any]]:
        from core.taint_analysis import analyze_file_taint

        return analyze_file_taint("t.py", code, code.splitlines())

    def test_containment_guard_clears_taint(self) -> None:
        code = (
            "def read(p):\n"
            "    full = os.path.normpath(os.path.join('/base', p))\n"
            "    if not full.startswith('/base'):\n"
            "        return None\n"
            "    return open(full)\n"
        )
        self.assertEqual([], self._findings_for(code), "containment guard should clear taint")

    def test_normpath_without_guard_still_reported(self) -> None:
        code = (
            "def read(p):\n"
            "    full = os.path.normpath(os.path.join('/base', p))\n"
            "    return open(full)\n"
        )
        self.assertEqual(
            1,
            len(self._findings_for(code)),
            "os.path.normpath alone is not a defence: normalising '/base/../etc/passwd' "
            "yields '/etc/passwd', so taint must survive it",
        )

    def test_secure_filename_clears_taint(self) -> None:
        code = "def read(p):\n    name = secure_filename(p)\n    return open(name)\n"
        self.assertEqual([], self._findings_for(code))


if __name__ == "__main__":
    unittest.main()
