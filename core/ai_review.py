"""
AI-assisted security review.

Optional layer over the deterministic engines. It never runs unless explicitly
enabled and credentialed, and the scanner produces identical output without it.

Two properties are deliberate:

**AI findings are advisory and never affect the risk score.** The project's
central claim is that every point of the score traces to a documented rule and
weight. Letting a model contribute would break that, so AI results are carried
separately, reported in their own section, and clearly attributed. They inform
a reviewer; they do not move a number.

**Failures are never presented as review output.** A wrong model name, an
expired key, and a clean file previously all rendered the same way. Each failure
now carries a typed reason and is reported as a failure.

Responses are cached by content hash, so re-scanning an unchanged file costs
nothing - which matters on a free tier.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.ai_provider import (
    AIErrorKind,
    AIProvider,
    AIProviderError,
    get_provider,
    is_configured,
)
from prompts.security_prompts import (
    ALLOWED_CATEGORIES,
    ALLOWED_SEVERITIES,
    RESPONSE_SCHEMA,
    build_review_prompt,
)

logger = logging.getLogger(__name__)

# Cost controls. The free tier is generous but finite, and a large repository
# would otherwise burn a daily quota in one scan.
DEFAULT_MAX_FILES = 10
DEFAULT_MAX_CHARS = 12_000

ENV_MAX_FILES = "RISKRIPPLE_AI_MAX_FILES"
ENV_MAX_CHARS = "RISKRIPPLE_AI_MAX_CHARS"
ENV_CACHE_DIR = "RISKRIPPLE_AI_CACHE_DIR"

AI_RULE_ID = "AI001"
AI_DETECTION_TYPE = "ai"


@dataclass
class AIReviewOutcome:
    """Result of reviewing one or more files."""

    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    files_reviewed: int = 0
    files_from_cache: int = 0
    model: str = ""
    provider: str = ""
    enabled: bool = False
    status: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "status": self.status,
            "provider": self.provider,
            "model": self.model,
            "files_reviewed": self.files_reviewed,
            "files_from_cache": self.files_from_cache,
            "findings": self.findings,
            "errors": self.errors,
        }


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, "").strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _cache_dir() -> Path:
    configured = os.getenv(ENV_CACHE_DIR)
    base = Path(configured) if configured else Path.home() / ".cache" / "riskripple" / "ai"
    return base


def _cache_key(model: str, prompt: str) -> str:
    return hashlib.sha256(f"{model}\0{prompt}".encode("utf-8")).hexdigest()


def _cache_read(key: str) -> Optional[Any]:
    path = _cache_dir() / f"{key}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cache_write(key: str, payload: Any) -> None:
    directory = _cache_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{key}.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        # Caching is an optimisation; failing to write must not fail a review.
        logger.debug("Could not write AI cache entry", exc_info=True)


def _number_source(content: str, max_chars: int) -> str:
    """
    Render source with line numbers, truncated to a budget.

    Numbering matters: the model is asked to report line numbers, and without
    them it guesses.
    """
    truncated = content[:max_chars]
    lines = truncated.splitlines()
    numbered = "\n".join(f"{index:>4}: {line}" for index, line in enumerate(lines, start=1))
    if len(content) > max_chars:
        numbered += f"\n... truncated at {max_chars} characters ..."
    return numbered


def _normalise_finding(raw: Dict[str, Any], file_path: str) -> Optional[Dict[str, Any]]:
    """
    Convert one model-produced finding into the report schema.

    Values are validated rather than trusted: a model can return a severity or
    category outside the allowed set even when given a schema.
    """
    title = str(raw.get("title") or "").strip()
    description = str(raw.get("description") or "").strip()
    if not title or not description:
        return None

    severity = str(raw.get("severity") or "").strip().upper()
    if severity not in ALLOWED_SEVERITIES:
        severity = "LOW"

    category = str(raw.get("category") or "").strip()
    if category not in ALLOWED_CATEGORIES:
        category = "Other"

    try:
        line_number = int(raw.get("line_number") or 0)
    except (TypeError, ValueError):
        line_number = 0
    line_number = max(line_number, 0)

    recommendation = str(raw.get("recommendation") or "").strip()
    reasoning = str(raw.get("reasoning") or "").strip()
    cwe = str(raw.get("cwe") or "").strip()

    finding: Dict[str, Any] = {
        "rule_id": AI_RULE_ID,
        "title": title,
        "type": title,
        "severity": severity,
        # Advisory by construction: a model's judgement is not evidence, so it
        # never claims high confidence alongside deterministic findings.
        "confidence": "LOW",
        "category": category,
        "file_path": file_path,
        "file": file_path,
        "line_number": line_number,
        "line": line_number,
        "description": description,
        "recommendation": recommendation,
        "suggested_fix": recommendation,
        "detection_type": AI_DETECTION_TYPE,
        "advisory": True,
        "ai_generated": True,
    }
    if reasoning:
        finding["reasoning"] = reasoning
    if cwe:
        finding["cwe"] = cwe
    return finding


def review_source(
    file_path: str,
    content: str,
    provider: Optional[AIProvider] = None,
    max_chars: Optional[int] = None,
    use_cache: bool = True,
) -> AIReviewOutcome:
    """
    Review a single source string.

    Raises nothing: every failure is captured in the outcome's errors list with
    a typed reason.
    """
    outcome = AIReviewOutcome()
    limit = max_chars or _int_env(ENV_MAX_CHARS, DEFAULT_MAX_CHARS)

    try:
        active = provider or get_provider()
    except AIProviderError as exc:
        outcome.status = exc.message
        outcome.errors.append({"file": file_path, "kind": exc.kind, "message": exc.message})
        return outcome

    outcome.enabled = True
    outcome.provider = getattr(active, "name", "unknown")
    outcome.model = getattr(active, "model", "unknown")

    prompt = build_review_prompt(file_path, _number_source(content, limit))
    key = _cache_key(outcome.model, prompt)

    payload = _cache_read(key) if use_cache else None
    if payload is not None:
        outcome.files_from_cache = 1
    else:
        try:
            payload = active.generate_json(prompt, RESPONSE_SCHEMA)
        except AIProviderError as exc:
            outcome.status = exc.message
            outcome.errors.append({"file": file_path, "kind": exc.kind, "message": exc.message})
            return outcome
        if use_cache:
            _cache_write(key, payload)

    # A missing "findings" key means the response did not match the schema. That
    # is a failure, and must not be reported as "no issues found" - the two are
    # opposite conclusions.
    if isinstance(payload, dict) and "findings" in payload:
        raw_findings = payload["findings"]
    elif isinstance(payload, list):
        raw_findings = payload
    else:
        message = "AI response did not contain a findings list."
        outcome.status = message
        outcome.errors.append(
            {"file": file_path, "kind": AIErrorKind.BAD_RESPONSE, "message": message}
        )
        return outcome

    if not isinstance(raw_findings, list):
        message = "AI response field 'findings' was not a list."
        outcome.status = message
        outcome.errors.append(
            {"file": file_path, "kind": AIErrorKind.BAD_RESPONSE, "message": message}
        )
        return outcome

    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        normalised = _normalise_finding(item, file_path)
        if normalised is not None:
            outcome.findings.append(normalised)

    outcome.files_reviewed = 1
    outcome.status = f"Reviewed {file_path}: {len(outcome.findings)} advisory finding(s)."
    return outcome


def review_files(
    file_paths: List[str],
    root: Optional[str] = None,
    max_files: Optional[int] = None,
    max_chars: Optional[int] = None,
    use_cache: bool = True,
) -> AIReviewOutcome:
    """
    Review a batch of files, honouring the configured file budget.

    Returns an outcome whose ``enabled`` flag is False when no provider is
    configured. That is the normal, non-error state for a scanner run without a
    key, and callers should treat it as "feature off".
    """
    combined = AIReviewOutcome()

    try:
        provider = get_provider()
    except AIProviderError as exc:
        combined.status = exc.message
        if exc.kind != AIErrorKind.NOT_CONFIGURED:
            combined.errors.append({"file": "", "kind": exc.kind, "message": exc.message})
        return combined

    combined.enabled = True
    combined.provider = getattr(provider, "name", "unknown")
    combined.model = getattr(provider, "model", "unknown")

    budget = max_files or _int_env(ENV_MAX_FILES, DEFAULT_MAX_FILES)
    selected = file_paths[:budget]

    for path in selected:
        try:
            content = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            combined.errors.append({"file": path, "kind": "read_error", "message": str(exc)})
            continue

        display_path = path
        if root:
            try:
                display_path = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
            except (ValueError, OSError):
                display_path = path

        outcome = review_source(
            display_path,
            content,
            provider=provider,
            max_chars=max_chars,
            use_cache=use_cache,
        )
        combined.findings.extend(outcome.findings)
        combined.errors.extend(outcome.errors)
        combined.files_reviewed += outcome.files_reviewed
        combined.files_from_cache += outcome.files_from_cache

    skipped = len(file_paths) - len(selected)
    status = (
        f"Reviewed {combined.files_reviewed} file(s) with {combined.model}, "
        f"{len(combined.findings)} advisory finding(s)."
    )
    if combined.files_from_cache:
        status += f" {combined.files_from_cache} served from cache."
    if skipped > 0:
        status += f" {skipped} file(s) skipped by the limit of {budget}."
    combined.status = status
    return combined


def ai_review_available() -> bool:
    """True when a provider is configured. Safe to call at any time."""
    return is_configured()
