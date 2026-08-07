"""
Packaging and CLI argument validation.

These guard failures that only appear once the project is installed, which the
rest of the suite never exercises because it always runs from the source tree.
Three real bugs were found this way:

* ``scanner.py`` is a top-level module, not a package, so ``packages.find``
  never installed it. The console script could not import it, and because
  ``webapp/scan_service.py`` imports from ``scanner``, the whole web interface
  failed to import in an installed package.
* ``rules/metadata/rules.yaml`` was not declared as package data, so an
  installed copy loaded **zero** rules and silently lost every CWE, OWASP and
  remediation string.
* The web templates and static assets were missing for the same reason.

Asserting the declarations is cheap. Building and installing a wheel on every
CI run is not.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


class TestPackagingDeclarations(unittest.TestCase):
    def test_pyproject_exists(self) -> None:
        self.assertTrue(PYPROJECT.is_file())

    def test_scanner_is_declared_as_a_top_level_module(self) -> None:
        """Without py-modules the console script and the webapp both break."""
        text = _pyproject_text()
        self.assertIn("py-modules", text)
        self.assertIn('"scanner"', text)

    def test_rule_metadata_is_declared_as_package_data(self) -> None:
        """Omitting this leaves an installed package with no rule metadata."""
        self.assertIn("metadata/*.yaml", _pyproject_text())

    def test_webapp_assets_are_declared_as_package_data(self) -> None:
        text = _pyproject_text()
        self.assertIn("templates", text)
        self.assertIn("static", text)

    def test_console_script_target_is_importable(self) -> None:
        """The entry point names scanner:main, so that symbol must exist."""
        self.assertIn("ai-repo-scanner", _pyproject_text())
        import scanner

        self.assertTrue(callable(scanner.main))


class TestRuleMetadataIsReachable(unittest.TestCase):
    def test_metadata_file_is_present(self) -> None:
        self.assertTrue((PROJECT_ROOT / "rules" / "metadata" / "rules.yaml").is_file())

    def test_registry_loads_rules(self) -> None:
        """A count of zero is what a broken package-data declaration looks like."""
        from core.rule_registry import load_metadata

        rules = load_metadata()
        self.assertGreater(len(rules), 0, "no rule metadata loaded")

    def test_every_rule_has_cwe_and_owasp(self) -> None:
        from core.rule_registry import load_metadata

        for rule in load_metadata():
            with self.subTest(rule=rule.get("rule_id")):
                self.assertTrue(rule.get("cwe"), "rule is missing a CWE mapping")
                self.assertTrue(rule.get("owasp"), "rule is missing an OWASP mapping")


class TestCliArgumentValidation(unittest.TestCase):
    """
    Invalid numeric arguments must produce a usage error, not a traceback.

    --workers 0 previously reached ThreadPoolExecutor and surfaced a raw
    ValueError stack trace.
    """

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scanner.py"), *args],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            timeout=120,
        )

    def test_zero_workers_is_a_usage_error(self) -> None:
        result = self._run(["samples", "--workers", "0", "--format", "json", "-q"])
        self.assertEqual(2, result.returncode)
        self.assertIn("--workers", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_negative_workers_is_a_usage_error(self) -> None:
        result = self._run(["samples", "--workers", "-3", "--format", "json", "-q"])
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)

    def test_negative_top_files_is_a_usage_error(self) -> None:
        result = self._run(["samples", "--top-files", "-1", "--format", "json", "-q"])
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)

    def test_zero_ai_max_files_is_a_usage_error(self) -> None:
        result = self._run(["samples", "--ai-max-files", "0", "--format", "json", "-q"])
        self.assertEqual(2, result.returncode)
        self.assertNotIn("Traceback", result.stderr)

    def test_nonexistent_target_exits_one_without_traceback(self) -> None:
        result = self._run(["no_such_directory_xyz", "--format", "json", "-q"])
        self.assertEqual(1, result.returncode)
        self.assertNotIn("Traceback", result.stderr)

    def test_file_target_exits_one_without_traceback(self) -> None:
        result = self._run(["scanner.py", "--format", "json", "-q"])
        self.assertEqual(1, result.returncode)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
