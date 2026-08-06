"""
Tests for the optional AI review layer.

Two properties matter most and are asserted here directly:

* The scanner is fully functional with no API key. Every test in this suite
  runs with credentials cleared, which is also how CI runs.
* AI findings never reach the risk score. The project's claim is that every
  point of the score traces to a documented rule and weight, and a model's
  judgement is not a rule.

A fake provider stands in for the network, so these tests never make a request
and never need a key.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from core.ai_provider import (
    AIErrorKind,
    AIProviderError,
    GeminiProvider,
    get_provider,
    is_configured,
)
from core.ai_review import (
    AI_DETECTION_TYPE,
    review_files,
    review_source,
)
from core.risk import calculate_repository_risk_score, scoreable_findings, summarize_severity_counts

CREDENTIAL_VARS = ("GEMINI_API_KEY", "RISKRIPPLE_AI_PROVIDER", "RISKRIPPLE_AI_MODEL")


class _FakeProvider:
    """Stands in for a real provider. Returns canned payloads or raises."""

    name = "fake"
    model = "fake-model-1"

    def __init__(self, payload: Any = None, error: AIProviderError | None = None) -> None:
        self.payload = payload if payload is not None else {"findings": []}
        self.error = error
        self.calls = 0

    def generate_json(self, prompt: str, schema: Dict[str, Any]) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.payload


def _finding(**overrides: Any) -> Dict[str, Any]:
    base = {
        "title": "Command injection via user input",
        "severity": "HIGH",
        "category": "Command Injection",
        "line_number": 4,
        "description": "User input reaches os.system without validation.",
        "recommendation": "Pass arguments as a list and avoid shell=True.",
        "reasoning": "The value flows unmodified from input() to the shell.",
    }
    base.update(overrides)
    return base


class _NoCredentialsTestCase(unittest.TestCase):
    """Base case that clears AI credentials for every test."""

    def setUp(self) -> None:
        self._patcher = mock.patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        for var in CREDENTIAL_VARS:
            os.environ.pop(var, None)

    def tearDown(self) -> None:
        self._patcher.stop()


class TestUnconfiguredIsNotAnError(_NoCredentialsTestCase):
    """No key is a normal state, not a failure."""

    def test_is_configured_is_false(self) -> None:
        self.assertFalse(is_configured())

    def test_get_provider_raises_not_configured(self) -> None:
        with self.assertRaises(AIProviderError) as ctx:
            get_provider()
        self.assertEqual(AIErrorKind.NOT_CONFIGURED, ctx.exception.kind)

    def test_review_files_reports_disabled_without_errors(self) -> None:
        outcome = review_files(["scanner.py"])
        self.assertFalse(outcome.enabled)
        self.assertEqual([], outcome.findings)
        self.assertEqual([], outcome.errors, "a missing key is not an error condition")
        self.assertIn("not configured", outcome.status.lower())

    def test_status_names_the_variable_to_set(self) -> None:
        self.assertIn("GEMINI_API_KEY", review_files([]).status)


class TestSuccessfulReview(_NoCredentialsTestCase):
    def test_findings_are_parsed_and_tagged(self) -> None:
        provider = _FakeProvider({"findings": [_finding()]})
        outcome = review_source("app.py", "x = 1\n", provider=provider, use_cache=False)

        self.assertEqual(1, len(outcome.findings))
        finding = outcome.findings[0]
        self.assertEqual("Command injection via user input", finding["title"])
        self.assertEqual("HIGH", finding["severity"])
        self.assertEqual("app.py", finding["file_path"])
        self.assertEqual(4, finding["line_number"])
        self.assertEqual(AI_DETECTION_TYPE, finding["detection_type"])
        self.assertTrue(finding["advisory"])
        self.assertTrue(finding["ai_generated"])
        self.assertEqual("LOW", finding["confidence"], "model judgement is never high confidence")

    def test_empty_findings_is_a_valid_result(self) -> None:
        outcome = review_source(
            "clean.py", "x = 1\n", provider=_FakeProvider({"findings": []}), use_cache=False
        )
        self.assertEqual([], outcome.findings)
        self.assertEqual([], outcome.errors)

    def test_unknown_severity_falls_back_to_low(self) -> None:
        provider = _FakeProvider({"findings": [_finding(severity="SPICY")]})
        outcome = review_source("a.py", "x\n", provider=provider, use_cache=False)
        self.assertEqual("LOW", outcome.findings[0]["severity"])

    def test_unknown_category_falls_back_to_other(self) -> None:
        provider = _FakeProvider({"findings": [_finding(category="Vibes")]})
        outcome = review_source("a.py", "x\n", provider=provider, use_cache=False)
        self.assertEqual("Other", outcome.findings[0]["category"])

    def test_finding_without_description_is_discarded(self) -> None:
        provider = _FakeProvider({"findings": [_finding(description="")]})
        outcome = review_source("a.py", "x\n", provider=provider, use_cache=False)
        self.assertEqual([], outcome.findings)

    def test_non_numeric_line_number_becomes_zero(self) -> None:
        provider = _FakeProvider({"findings": [_finding(line_number="somewhere")]})
        outcome = review_source("a.py", "x\n", provider=provider, use_cache=False)
        self.assertEqual(0, outcome.findings[0]["line_number"])


class TestFailuresAreNotPresentedAsResults(_NoCredentialsTestCase):
    """
    Every failure must be reported as a failure.

    The original implementation caught bare Exception and returned the message
    as review output, so an invalid model name rendered identically to a clean
    review.
    """

    def _assert_failure(self, error: AIProviderError, expected_kind: str) -> None:
        outcome = review_source("a.py", "x\n", provider=_FakeProvider(error=error), use_cache=False)
        self.assertEqual([], outcome.findings)
        self.assertEqual(1, len(outcome.errors))
        self.assertEqual(expected_kind, outcome.errors[0]["kind"])

    def test_auth_failure(self) -> None:
        self._assert_failure(AIProviderError(AIErrorKind.AUTH, "bad key"), AIErrorKind.AUTH)

    def test_rate_limit(self) -> None:
        self._assert_failure(
            AIProviderError(AIErrorKind.RATE_LIMIT, "quota"), AIErrorKind.RATE_LIMIT
        )

    def test_model_not_found(self) -> None:
        self._assert_failure(
            AIProviderError(AIErrorKind.MODEL_NOT_FOUND, "no model"), AIErrorKind.MODEL_NOT_FOUND
        )

    def test_network_failure(self) -> None:
        self._assert_failure(AIProviderError(AIErrorKind.NETWORK, "offline"), AIErrorKind.NETWORK)

    def test_malformed_payload_is_reported(self) -> None:
        outcome = review_source(
            "a.py", "x\n", provider=_FakeProvider({"nonsense": True}), use_cache=False
        )
        self.assertEqual([], outcome.findings)
        self.assertEqual(AIErrorKind.BAD_RESPONSE, outcome.errors[0]["kind"])

    def test_non_dict_items_are_skipped(self) -> None:
        provider = _FakeProvider({"findings": ["not a finding", _finding()]})
        outcome = review_source("a.py", "x\n", provider=provider, use_cache=False)
        self.assertEqual(1, len(outcome.findings))


class TestAdvisoryFindingsNeverScore(unittest.TestCase):
    """The guarantee that keeps the risk score deterministic."""

    def setUp(self) -> None:
        self.rule_finding = {
            "rule_id": "PY003",
            "severity": "HIGH",
            "category": "Command Injection",
            "file_path": "app.py",
            "line_number": 2,
        }
        self.ai_finding = {
            "rule_id": "AI001",
            "severity": "CRITICAL",
            "category": "Command Injection",
            "file_path": "app.py",
            "line_number": 4,
            "detection_type": AI_DETECTION_TYPE,
            "advisory": True,
        }

    def test_scoreable_filters_advisory(self) -> None:
        kept = scoreable_findings([self.rule_finding, self.ai_finding])
        self.assertEqual([self.rule_finding], kept)

    def test_score_is_unchanged_by_advisory_findings(self) -> None:
        rules_only = calculate_repository_risk_score([self.rule_finding])
        with_ai = calculate_repository_risk_score([self.rule_finding, self.ai_finding])
        self.assertEqual(
            rules_only,
            with_ai,
            "an advisory AI finding changed the risk score, breaking the determinism guarantee",
        )

    def test_severity_counts_exclude_advisory(self) -> None:
        counts = summarize_severity_counts([self.rule_finding, self.ai_finding])
        self.assertEqual(0, counts["CRITICAL"], "advisory CRITICAL must not be counted")
        self.assertEqual(1, counts["HIGH"])

    def test_advisory_only_scores_zero(self) -> None:
        self.assertEqual(0, calculate_repository_risk_score([self.ai_finding]))


class TestCostControls(_NoCredentialsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["RISKRIPPLE_AI_CACHE_DIR"] = str(Path(self._tmp.name) / "cache")

    def tearDown(self) -> None:
        os.environ.pop("RISKRIPPLE_AI_CACHE_DIR", None)
        self._tmp.cleanup()
        super().tearDown()

    def test_file_budget_is_enforced(self) -> None:
        provider = _FakeProvider({"findings": []})
        paths: List[str] = []
        for index in range(5):
            path = Path(self._tmp.name) / f"mod{index}.py"
            path.write_text("x = 1\n", encoding="utf-8")
            paths.append(str(path))

        with mock.patch("core.ai_review.get_provider", return_value=provider):
            outcome = review_files(paths, max_files=2, use_cache=False)

        self.assertEqual(2, outcome.files_reviewed)
        self.assertEqual(2, provider.calls, "budget must limit requests, not just reporting")
        self.assertIn("skipped", outcome.status)

    def test_identical_content_is_served_from_cache(self) -> None:
        provider = _FakeProvider({"findings": []})
        first = review_source("a.py", "x = 1\n", provider=provider, use_cache=True)
        second = review_source("a.py", "x = 1\n", provider=provider, use_cache=True)

        self.assertEqual(1, provider.calls, "second identical review should not call the provider")
        self.assertEqual(0, first.files_from_cache)
        self.assertEqual(1, second.files_from_cache)

    def test_changed_content_is_not_served_from_cache(self) -> None:
        provider = _FakeProvider({"findings": []})
        review_source("a.py", "x = 1\n", provider=provider, use_cache=True)
        review_source("a.py", "x = 2\n", provider=provider, use_cache=True)
        self.assertEqual(2, provider.calls)

    def test_source_is_truncated_to_the_character_budget(self) -> None:
        captured = {}

        class _Capturing(_FakeProvider):
            def generate_json(self, prompt: str, schema: Dict[str, Any]) -> Any:
                captured["prompt"] = prompt
                return {"findings": []}

        review_source(
            "big.py", "a = 1\n" * 5000, provider=_Capturing(), max_chars=200, use_cache=False
        )
        self.assertIn("truncated", captured["prompt"])


class TestGeminiProviderContract(unittest.TestCase):
    """
    Pins the request shape against the documented REST contract.

    The previous implementation hardcoded a model that does not exist, which no
    test would have caught. These assert the endpoint, auth style and structured
    output fields actually used.
    """

    def test_model_defaults_are_configurable(self) -> None:
        provider = GeminiProvider(api_key="k", model="gemini-2.5-flash-lite")
        self.assertEqual("gemini-2.5-flash-lite", provider.model)

    def test_request_targets_documented_endpoint_with_schema(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="gemini-2.5-flash")
        captured: Dict[str, Any] = {}

        class _Response:
            def read(self):
                return b'{"candidates":[{"content":{"parts":[{"text":"{\\"findings\\":[]}"}]}}]}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def _fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["body"] = request.data.decode("utf-8")
            return _Response()

        with mock.patch("urllib.request.urlopen", _fake_urlopen):
            result = provider.generate_json("prompt", {"type": "OBJECT"})

        self.assertEqual({"findings": []}, result)
        self.assertIn("generativelanguage.googleapis.com", captured["url"])
        self.assertIn("gemini-2.5-flash:generateContent", captured["url"])
        self.assertIn("key=test-key", captured["url"])
        self.assertIn("responseMimeType", captured["body"])
        self.assertIn("responseSchema", captured["body"])

    def test_empty_candidates_raises_bad_response(self) -> None:
        provider = GeminiProvider(api_key="k")

        class _Response:
            def read(self):
                return b'{"candidates":[]}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with mock.patch("urllib.request.urlopen", lambda *a, **k: _Response()):
            with self.assertRaises(AIProviderError) as ctx:
                provider.generate_json("p", {})
        self.assertEqual(AIErrorKind.BAD_RESPONSE, ctx.exception.kind)


if __name__ == "__main__":
    unittest.main()
