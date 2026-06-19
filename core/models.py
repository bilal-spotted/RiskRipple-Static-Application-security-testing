from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """
        Keep compatibility with the existing report generators which expect dicts.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "type": self.title,  # legacy field
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "file_path": self.file_path,
            "file": self.file_path,  # legacy field
            "line_number": self.line_number,
            "line": self.line_number,  # legacy field
            "code_snippet": self.code_snippet,
            "snippet": self.code_snippet,  # legacy field
            "description": self.description,
            "recommendation": self.recommendation,
            "suggested_fix": self.recommendation,  # legacy field
        }


@dataclass(frozen=True)
class ScanError:
    file: str
    error: str

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "error": self.error}


@dataclass(frozen=True)
class RepoScanSummary:
    target: str
    files_scanned: int
    total_findings: int
    severity_counts: Dict[str, int]
    repository_risk_score: int
    top_risky_files: List[Dict[str, Any]]
    scan_errors: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "repository_risk_score": self.repository_risk_score,
            "top_risky_files": self.top_risky_files,
            "scan_errors": self.scan_errors,
        }


def finding_from_dict(data: Dict[str, Any]) -> Optional[Finding]:
    """
    Best-effort conversion from legacy finding dicts.
    This is optional: the rest of the system can continue using dicts.
    """
    try:
        return Finding(
            rule_id=str(data.get("rule_id", "")),
            title=str(data.get("title") or data.get("type") or ""),
            severity=str(data.get("severity", "LOW")),
            confidence=str(data.get("confidence", "MEDIUM")),
            category=str(data.get("category", "General")),
            file_path=str(data.get("file_path") or data.get("file") or ""),
            line_number=int(data.get("line_number") or data.get("line") or 0),
            code_snippet=str(data.get("code_snippet") or data.get("snippet") or ""),
            description=str(data.get("description", "")),
            recommendation=str(data.get("recommendation") or data.get("suggested_fix") or ""),
        )
    except Exception:
        return None
