"""
AI provider adapter.

The scanner's detection engines are deterministic; this layer is the only place
that talks to a model, and it is strictly optional. Everything here is built so
that a missing key, a dead network, or a malformed reply degrades into a clear
message rather than an exception or, worse, an error string presented as if it
were review output.

Ships configured for Google Gemini, whose free tier makes the feature usable at
no cost. The REST API is called through the standard library instead of a
vendor SDK: it adds no dependency to a security tool, and it keeps the whole
provider contract small enough that swapping in another model is a readable
edit to one class.

To use a different provider, implement `generate_json` and register it in
`_PROVIDERS`. The rest of the pipeline only knows about the protocol.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Protocol

# Free-tier default. Overridable because model names are retired over time and
# a hardcoded one eventually becomes a silent failure.
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

DEFAULT_TIMEOUT_SECONDS = 45

# Environment variables recognised for configuration.
ENV_GEMINI_KEY = "GEMINI_API_KEY"
ENV_MODEL = "RISKRIPPLE_AI_MODEL"
ENV_PROVIDER = "RISKRIPPLE_AI_PROVIDER"


class AIErrorKind:
    """Why an AI review could not be produced."""

    NOT_CONFIGURED = "not_configured"
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    MODEL_NOT_FOUND = "model_not_found"
    NETWORK = "network"
    SERVER = "server"
    BAD_RESPONSE = "bad_response"
    BLOCKED = "blocked"


class AIProviderError(Exception):
    """
    A provider failure with a machine-readable kind.

    The kind exists so callers can tell a configuration problem from an outage
    from a quota limit. The previous implementation collapsed all of these into
    one string and rendered it in the results panel, which made a wrong model
    name look identical to a successful review.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class AIProvider(Protocol):
    """Minimal contract a provider must satisfy."""

    name: str
    model: str

    def generate_json(self, prompt: str, schema: Dict[str, Any]) -> Any:
        """Return parsed JSON matching ``schema``, or raise AIProviderError."""
        ...


class GeminiProvider:
    """
    Google Gemini via the REST API.

    Uses the API's structured-output mode: passing a response schema makes the
    model return parseable JSON directly, rather than prose we would have to
    scrape and guess at.
    """

    name = "gemini"

    def __init__(
        self,
        api_key: str,
        model: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.api_key = api_key
        self.model = model or os.getenv(ENV_MODEL) or DEFAULT_GEMINI_MODEL
        self.timeout = timeout

    def generate_json(self, prompt: str, schema: Dict[str, Any]) -> Any:
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
                # Low temperature: security review should be reproducible, not
                # creative. Determinism is the project's whole premise.
                "temperature": 0.1,
            },
        }
        url = GEMINI_ENDPOINT.format(model=self.model)
        request = urllib.request.Request(
            f"{url}?key={self.api_key}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from exc
        except urllib.error.URLError as exc:
            raise AIProviderError(
                AIErrorKind.NETWORK,
                f"Could not reach the Gemini API: {exc.reason}. Check network access.",
            ) from exc
        except TimeoutError as exc:
            raise AIProviderError(
                AIErrorKind.NETWORK,
                f"The Gemini API did not respond within {self.timeout}s.",
            ) from exc

        return self._extract_json(body)

    def _http_error(self, exc: urllib.error.HTTPError) -> AIProviderError:
        """Translate an HTTP status into an actionable message."""
        try:
            detail = json.loads(exc.read().decode("utf-8", errors="replace"))
            detail_message = str(detail.get("error", {}).get("message", "")).strip()
        except Exception:
            detail_message = ""

        suffix = f" API said: {detail_message}" if detail_message else ""

        # Gemini reports an invalid key as 400, not 401/403, so the status code
        # alone would misfile the most common configuration mistake.
        looks_like_key_problem = "api key" in detail_message.lower()
        if exc.code in (401, 403) or (exc.code == 400 and looks_like_key_problem):
            return AIProviderError(
                AIErrorKind.AUTH,
                f"Gemini rejected the API key (HTTP {exc.code}). Check {ENV_GEMINI_KEY}.{suffix}",
            )
        if exc.code == 404:
            return AIProviderError(
                AIErrorKind.MODEL_NOT_FOUND,
                f"Model '{self.model}' was not found. Set {ENV_MODEL} to a model your "
                f"key can access.{suffix}",
            )
        if exc.code == 429:
            return AIProviderError(
                AIErrorKind.RATE_LIMIT,
                f"Gemini free-tier quota reached. Retry later or reduce the file limit.{suffix}",
            )
        if exc.code >= 500:
            return AIProviderError(
                AIErrorKind.SERVER,
                f"Gemini returned a server error (HTTP {exc.code}).{suffix}",
            )
        return AIProviderError(
            AIErrorKind.SERVER,
            f"Gemini request failed (HTTP {exc.code}).{suffix}",
        )

    def _extract_json(self, body: str) -> Any:
        """Pull the JSON payload out of a generateContent response."""
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError as exc:
            raise AIProviderError(
                AIErrorKind.BAD_RESPONSE, "Gemini returned a response that was not JSON."
            ) from exc

        candidates = envelope.get("candidates") or []
        if not candidates:
            # A prompt blocked by safety filters comes back with no candidates.
            reason = str(envelope.get("promptFeedback", {}).get("blockReason", "")).strip()
            if reason:
                raise AIProviderError(
                    AIErrorKind.BLOCKED, f"Gemini declined to analyse this content ({reason})."
                )
            raise AIProviderError(AIErrorKind.BAD_RESPONSE, "Gemini returned no candidates.")

        parts = candidates[0].get("content", {}).get("parts") or []
        text = "".join(str(part.get("text", "")) for part in parts).strip()
        if not text:
            finish = str(candidates[0].get("finishReason", "")).strip()
            if finish and finish != "STOP":
                raise AIProviderError(
                    AIErrorKind.BAD_RESPONSE,
                    f"Gemini stopped before producing output (finishReason={finish}).",
                )
            raise AIProviderError(AIErrorKind.BAD_RESPONSE, "Gemini returned an empty response.")

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIProviderError(
                AIErrorKind.BAD_RESPONSE,
                "Gemini did not return valid JSON despite the response schema.",
            ) from exc


def _build_gemini() -> AIProvider:
    api_key = os.getenv(ENV_GEMINI_KEY, "").strip()
    if not api_key:
        raise AIProviderError(
            AIErrorKind.NOT_CONFIGURED,
            f"AI review is not configured. Set {ENV_GEMINI_KEY} to enable it. "
            "The scanner runs fully without it.",
        )
    return GeminiProvider(api_key)


_PROVIDERS = {"gemini": _build_gemini}


def available_providers() -> list[str]:
    return sorted(_PROVIDERS)


def is_configured() -> bool:
    """True if a provider could be constructed right now."""
    try:
        get_provider()
        return True
    except AIProviderError:
        return False


def get_provider(name: Optional[str] = None) -> AIProvider:
    """
    Build the configured provider.

    Raises AIProviderError with kind NOT_CONFIGURED when no credentials are
    present, which callers treat as "feature off", never as a failure.
    """
    provider_name = (name or os.getenv(ENV_PROVIDER) or "gemini").strip().lower()
    factory = _PROVIDERS.get(provider_name)
    if factory is None:
        raise AIProviderError(
            AIErrorKind.NOT_CONFIGURED,
            f"Unknown AI provider '{provider_name}'. Available: {', '.join(available_providers())}.",
        )
    return factory()
