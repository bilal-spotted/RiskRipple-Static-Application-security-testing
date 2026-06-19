"""
Finding normalization and deduplication.

- Normalizes severity and confidence to canonical values.
- Computes a stable fingerprint per finding for deduplication.
- Deduplicates findings by fingerprint (keeps first occurrence).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from core.severity import normalize_severity


def _normalize_path(path: str) -> str:
    """Normalize path separators to forward slash for stable fingerprinting."""
    if not path:
        return path
    return os.path.normpath(path).replace("\\", "/")


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """
    Compute a stable fingerprint for a finding for deduplication.

    Uses rule_id, file_path, line_number, and title/snippet so that
    the same issue at the same location is considered duplicate.
    """
    rule_id = str(finding.get("rule_id") or "")
    file_path = _normalize_path(str(finding.get("file_path") or finding.get("file") or ""))
    line = finding.get("line_number") or finding.get("line") or 0
    title = str(finding.get("title") or finding.get("type") or "")
    key = f"{rule_id}|{file_path}|{line}|{title}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def normalize_single_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a single finding: severity, confidence, path.
    Returns a new dict with canonical fields; adds fingerprint.
    """
    out = dict(finding)
    out["severity"] = normalize_severity(out.get("severity"))
    conf = str(out.get("confidence") or "MEDIUM").strip().upper()
    out["confidence"] = conf if conf in ("HIGH", "MEDIUM", "LOW") else "MEDIUM"
    if out.get("file_path"):
        out["file_path"] = _normalize_path(out["file_path"])
    if out.get("file") and not out.get("file_path"):
        out["file_path"] = _normalize_path(out["file"])
    out["file"] = out.get("file_path") or out.get("file")
    out["fingerprint"] = finding_fingerprint(out)
    return out


def normalize_and_deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize all findings (severity, confidence, path, fingerprint) and
    remove duplicates by fingerprint. First occurrence is kept; order
    otherwise preserved.
    """
    seen: set[str] = set()
    result: List[Dict[str, Any]] = []
    for f in findings:
        n = normalize_single_finding(f)
        fp = n["fingerprint"]
        if fp not in seen:
            seen.add(fp)
            result.append(n)
    return result
