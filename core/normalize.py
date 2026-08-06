"""
Finding normalization and deduplication.

- Rewrites file paths to be relative to the scan target.
- Normalizes severity and confidence to canonical values.
- Computes a stable fingerprint per finding for deduplication.
- Deduplicates findings by fingerprint (keeps first occurrence).

Path handling matters more than it appears. Detection engines produced a mix of
absolute paths (from file discovery) and relative ones (from hygiene checks),
and three things depended on the difference:

* **SARIF** requires ``artifactLocation.uri`` to be relative to the repository.
  An absolute path such as ``C:/Users/.../scanner.py`` is rejected by GitHub
  Code Scanning, so uploads silently annotated nothing.
* **Fingerprints** hash the path, so the same finding produced a different
  fingerprint on every machine, breaking deduplication and any future baseline.
* **File grouping** treated ``C:/repo/a.py`` and ``a.py`` as different files,
  splitting the risk attributed to one file across two entries.

Normalising here fixes all three at once, because every finding from every
engine passes through this module before it reaches a report.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional

from core.severity import normalize_severity


def _normalize_path(path: str) -> str:
    """Normalize path separators to forward slash for stable fingerprinting."""
    if not path:
        return path
    return PurePath(os.path.normpath(path)).as_posix()


def relativize_path(path: str, root: Optional[str | Path]) -> str:
    """
    Express a path relative to the scan root, using forward slashes.

    Paths already relative are returned normalised. Paths outside the root are
    returned unchanged rather than forced into a chain of ``..`` segments, which
    would be neither portable nor readable.
    """
    if not path:
        return path
    normalised = _normalize_path(path)
    if root is None:
        return normalised
    try:
        root_resolved = Path(root).resolve()
        candidate = Path(path)
        if not candidate.is_absolute():
            return normalised
        return candidate.resolve().relative_to(root_resolved).as_posix()
    except (ValueError, OSError, RuntimeError):
        # Outside the root, or unresolvable: keep what we have.
        return normalised


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


def normalize_single_finding(
    finding: Dict[str, Any], root: Optional[str | Path] = None
) -> Dict[str, Any]:
    """
    Normalize a single finding: severity, confidence, path.

    Returns a new dict with canonical fields and a fingerprint. When ``root`` is
    given, absolute paths are rewritten relative to it so output is portable
    between machines.
    """
    out = dict(finding)
    out["severity"] = normalize_severity(out.get("severity"))
    conf = str(out.get("confidence") or "MEDIUM").strip().upper()
    out["confidence"] = conf if conf in ("HIGH", "MEDIUM", "LOW") else "MEDIUM"

    raw_path = out.get("file_path") or out.get("file")
    if raw_path:
        out["file_path"] = relativize_path(str(raw_path), root)
    out["file"] = out.get("file_path") or out.get("file")

    # Fingerprint last: it hashes the final, relative path so the same finding
    # produces the same fingerprint regardless of where the repo is checked out.
    out["fingerprint"] = finding_fingerprint(out)
    return out


def normalize_and_deduplicate_findings(
    findings: List[Dict[str, Any]], root: Optional[str | Path] = None
) -> List[Dict[str, Any]]:
    """
    Normalize all findings and remove duplicates by fingerprint.

    First occurrence is kept, order otherwise preserved. Passing ``root`` makes
    paths relative to the scan target, which is required for valid SARIF and for
    fingerprints that are stable across machines.
    """
    seen: set[str] = set()
    result: List[Dict[str, Any]] = []
    for f in findings:
        n = normalize_single_finding(f, root)
        fp = n["fingerprint"]
        if fp not in seen:
            seen.add(fp)
            result.append(n)
    return result
