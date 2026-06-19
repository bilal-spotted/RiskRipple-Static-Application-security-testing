"""
Repository risk scoring model for Risk Ripple.

Uses the canonical four-level severity model (CRITICAL, HIGH, MEDIUM, LOW) and
deterministic, explainable scoring. No machine learning; every score can be
reproduced from severity counts and documented weights.

Severity weights (used for both per-finding and count-based scoring):
  - CRITICAL = 10
  - HIGH     = 6
  - MEDIUM   = 3
  - LOW      = 1

Risk level thresholds (numeric score → label):
  - 0–20   → Low
  - 21–50  → Moderate
  - 51–100 → High
  - >100   → Critical
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Tuple

from core.severity import (
    SEVERITY_LEVELS,
    SEVERITY_WEIGHTS,  # re-exported for tests and external use
)
from core.severity import (
    normalize_severity as _normalize_severity_canonical,
)

# ---------------------------------------------------------------------------
# Types and constants
# ---------------------------------------------------------------------------

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.6,
}

# Per-finding bonuses (used for file-level and optional detailed breakdown)
TAINT_FLOW_BONUS_PER_FINDING = 5
SECRET_EXPOSURE_BONUS_PER_FINDING = 6
CRITICAL_CATEGORY_BONUS_PER_FINDING = 3

CRITICAL_CATEGORIES = frozenset(
    {
        "Command Injection",
        "SQL Injection",
        "Secret Exposure",
        "Secrets",
        "Sensitive Artifacts",
        "Unsafe Deserialization",
    }
)

SECRET_EXPOSURE_CATEGORIES = frozenset(
    {
        "Secret Exposure",
        "Secrets",
        "Sensitive Artifacts",
    }
)

HYGIENE_CATEGORIES = frozenset(
    {
        "Repository Hygiene",
        "Sensitive Artifacts",
        "Secret Exposure",
        "Secret Exposure Risks",
    }
)

# Risk level bands (score → label)
RISK_LEVEL_LOW_MAX = 20
RISK_LEVEL_MODERATE_MAX = 50
RISK_LEVEL_HIGH_MAX = 100


# ---------------------------------------------------------------------------
# RiskSummary dataclass
# ---------------------------------------------------------------------------


@dataclass
class RiskSummary:
    """
    Severity counts used for count-based risk scoring.

    All four levels from the canonical severity model are included.
    Findings that do not specify CRITICAL are normalized (e.g. to LOW)
    before counting, so backward compatibility is preserved.
    """

    critical: int
    high: int
    medium: int
    low: int

    @property
    def total_findings(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def to_counts_dict(self) -> Dict[str, int]:
        """Return dict with CRITICAL, HIGH, MEDIUM, LOW for reports."""
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_severity(severity: str | None) -> str:
    return _normalize_severity_canonical(severity)


def _normalize_confidence(confidence: str) -> str:
    return str(confidence or "MEDIUM").upper()


def _get_category(finding: Dict[str, Any]) -> str:
    return str(finding.get("category") or "General").strip()


def _is_taint_finding(finding: Dict[str, Any]) -> bool:
    return finding.get("taint_flow") is True or (
        str(finding.get("detection_type", "")).lower() == "taint"
    )


def _is_hygiene_finding(finding: Dict[str, Any]) -> bool:
    cat = _get_category(finding)
    return cat in HYGIENE_CATEGORIES or str(finding.get("detection_type", "")).lower() == "hygiene"


def _is_secret_exposure_finding(finding: Dict[str, Any]) -> bool:
    return _get_category(finding) in SECRET_EXPOSURE_CATEGORIES


def _is_critical_category(finding: Dict[str, Any]) -> bool:
    return _get_category(finding) in CRITICAL_CATEGORIES


def _weighted_finding_score(finding: Dict[str, Any]) -> float:
    """Single finding contribution: severity_weight * confidence_weight."""
    sev = _normalize_severity(finding.get("severity", "LOW"))
    conf = _normalize_confidence(finding.get("confidence", "MEDIUM"))
    s_w = SEVERITY_WEIGHTS.get(sev, 1)
    c_w = CONFIDENCE_WEIGHTS.get(conf, 0.8)
    return s_w * c_w


# ---------------------------------------------------------------------------
# Count-based scoring (canonical formula)
# ---------------------------------------------------------------------------


def compute_risk_score(severity_counts: Dict[str, int] | RiskSummary) -> int:
    """
    Compute repository risk score from severity counts.

    Formula:
      score = critical * 10 + high * 6 + medium * 3 + low * 1

    We use this deterministic formula so that scores are explainable and
    auditable (e.g. for academic or compliance use). No randomness or ML.
    """
    if isinstance(severity_counts, RiskSummary):
        r = severity_counts
    else:
        r = RiskSummary(
            critical=int(severity_counts.get("CRITICAL", 0)),
            high=int(severity_counts.get("HIGH", 0)),
            medium=int(severity_counts.get("MEDIUM", 0)),
            low=int(severity_counts.get("LOW", 0)),
        )
    return r.critical * 10 + r.high * 6 + r.medium * 3 + r.low * 1


def get_risk_level(score: int) -> str:
    """
    Convert numeric score to human-readable risk level.

    Thresholds:
      - 0–20   → Low
      - 21–50  → Moderate
      - 51–100 → High
      - >100   → Critical
    """
    if score <= RISK_LEVEL_LOW_MAX:
        return "Low"
    if score <= RISK_LEVEL_MODERATE_MAX:
        return "Moderate"
    if score <= RISK_LEVEL_HIGH_MAX:
        return "High"
    return "Critical"


def get_risk_level_css_class(score: int) -> str:
    """Return CSS class suffix for risk level (e.g. risk-low, risk-critical)."""
    level = get_risk_level(score).lower()
    return f"risk-{level}"


# ---------------------------------------------------------------------------
# Severity counts and RiskSummary from findings
# ---------------------------------------------------------------------------


def summarize_severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Return counts per severity; keys follow canonical SEVERITY_LEVELS.

    Findings without a severity, or with an unknown value, are normalized
    to LOW (backward compatibility).
    """
    counts = {s: 0 for s in SEVERITY_LEVELS}
    for f in findings:
        sev = _normalize_severity(f.get("severity", "LOW"))
        if sev in counts:
            counts[sev] += 1
    return counts


def severity_counts_to_risk_summary(severity_counts: Dict[str, int]) -> RiskSummary:
    """Build a RiskSummary from a severity counts dict (e.g. from summarize_severity_counts)."""
    return RiskSummary(
        critical=int(severity_counts.get("CRITICAL", 0)),
        high=int(severity_counts.get("HIGH", 0)),
        medium=int(severity_counts.get("MEDIUM", 0)),
        low=int(severity_counts.get("LOW", 0)),
    )


# ---------------------------------------------------------------------------
# Repository and file scoring (CLI compatibility)
# ---------------------------------------------------------------------------


def calculate_repository_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate repository risk score from findings.

    Uses full breakdown: severity contribution + taint bonus + secret exposure
    + hygiene + concentration + unique files + critical category bonus.
    Deterministic and explainable; see compute_risk_breakdown for formula.
    """
    score, _ = compute_risk_breakdown(findings)
    return score


def compute_risk_breakdown(findings: List[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
    """
    Compute risk score and a full breakdown for reports.

    Repository score = severity_contribution + taint_flow_contribution
    + secret_exposure_contribution + critical_category_contribution
    + file_concentration_factor + unique_files_factor.
    All components are deterministic and explainable.
    """
    empty_breakdown = {
        "critical_contribution": 0,
        "high_contribution": 0,
        "medium_contribution": 0,
        "low_contribution": 0,
        "severity_contribution": 0,
        "taint_flow_contribution": 0.0,
        "secret_exposure_contribution": 0.0,
        "repository_hygiene_contribution": 0.0,
        "file_concentration_factor": 0.0,
        "unique_files_factor": 0.0,
        "critical_category_contribution": 0.0,
    }
    if not findings:
        return 0, empty_breakdown

    counts = summarize_severity_counts(findings)
    summary = severity_counts_to_risk_summary(counts)
    severity_contribution = compute_risk_score(summary)

    n_taint = sum(1 for f in findings if _is_taint_finding(f))
    n_secret = sum(1 for f in findings if _is_secret_exposure_finding(f))
    n_hygiene = sum(1 for f in findings if _is_hygiene_finding(f))
    n_critical_cat = sum(1 for f in findings if _is_critical_category(f))

    taint_flow_contribution = n_taint * TAINT_FLOW_BONUS_PER_FINDING
    secret_exposure_contribution = n_secret * SECRET_EXPOSURE_BONUS_PER_FINDING
    repository_hygiene_contribution = min(15.0, n_hygiene * 1.5)  # cap for explainability
    critical_category_contribution = n_critical_cat * CRITICAL_CATEGORY_BONUS_PER_FINDING

    grouped = group_findings_by_file(findings)
    n_files = len(grouped)
    max_in_file = max(len(flist) for flist in grouped.values()) if grouped else 0
    total_findings = len(findings)
    # Concentration: higher when many findings concentrated in few files (only if 2+ files)
    if n_files >= 2 and total_findings > 0:
        concentration_ratio = max_in_file / total_findings
        file_concentration_factor = round(min(10.0, concentration_ratio * 15), 1)
    else:
        file_concentration_factor = 0.0
    # Breadth: small factor when findings span multiple files (only if 2+ files)
    unique_files_factor = min(5.0, float(n_files)) if n_files >= 2 else 0.0

    total_score = int(
        round(
            severity_contribution
            + taint_flow_contribution
            + secret_exposure_contribution
            + repository_hygiene_contribution
            + file_concentration_factor
            + unique_files_factor
            + critical_category_contribution,
        )
    )

    breakdown = {
        "critical_contribution": summary.critical * 10,
        "high_contribution": summary.high * 6,
        "medium_contribution": summary.medium * 3,
        "low_contribution": summary.low * 1,
        "severity_contribution": severity_contribution,
        "taint_flow_contribution": round(taint_flow_contribution, 1),
        "secret_exposure_contribution": round(secret_exposure_contribution, 1),
        "repository_hygiene_contribution": round(repository_hygiene_contribution, 1),
        "file_concentration_factor": file_concentration_factor,
        "unique_files_factor": unique_files_factor,
        "critical_category_contribution": round(critical_category_contribution, 1),
    }
    return total_score, breakdown


# ---------------------------------------------------------------------------
# File-level score (same weights; used for top risky files)
# ---------------------------------------------------------------------------


def calculate_file_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate a transparent risk score for one file.

    Uses same severity/confidence weights as repository score.
    Adds taint and critical-category bonuses per finding.
    """
    if not findings:
        return 0
    raw = 0.0
    for f in findings:
        raw += _weighted_finding_score(f)
        if _is_taint_finding(f):
            raw += TAINT_FLOW_BONUS_PER_FINDING
        if _is_critical_category(f):
            raw += CRITICAL_CATEGORY_BONUS_PER_FINDING
    return int(round(raw))


# ---------------------------------------------------------------------------
# Grouping and top lists
# ---------------------------------------------------------------------------


def group_findings_by_file(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings by file path. Compatible with 'file_path' or legacy 'file'."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        file_path = finding.get("file_path") or finding.get("file") or "unknown_file"
        grouped.setdefault(file_path, []).append(finding)
    return grouped


def get_top_risky_files(
    findings: List[Dict[str, Any]],
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Return top risky files sorted by file risk score (desc), then findings count, then path.

    Each item: file_path, risk_score, findings_count, severity_counts.
    """
    grouped = group_findings_by_file(findings)
    ranked: List[Dict[str, Any]] = []
    for file_path, file_findings in grouped.items():
        risk_score = calculate_file_risk_score(file_findings)
        severity_counts = {s: 0 for s in SEVERITY_LEVELS}
        for f in file_findings:
            sev = _normalize_severity(f.get("severity", "LOW"))
            if sev in severity_counts:
                severity_counts[sev] += 1
        ranked.append(
            {
                "file_path": file_path,
                "risk_score": risk_score,
                "findings_count": len(file_findings),
                "severity_counts": severity_counts,
            }
        )
    ranked.sort(
        key=lambda x: (-x["risk_score"], -x["findings_count"], (x["file_path"] or "").lower()),
    )
    return ranked[:top_n]


def get_top_risky_categories(
    findings: List[Dict[str, Any]],
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Aggregate findings by category and return top categories by finding count.

    Each item: category, count.
    """
    counts: Dict[str, int] = {}
    for f in findings:
        cat = _get_category(f) or "General"
        counts[cat] = counts.get(cat, 0) + 1
    sorted_cats = sorted(
        counts.items(),
        key=lambda x: (-x[1], (x[0] or "").lower()),
    )
    return [{"category": cat, "count": c} for cat, c in sorted_cats[:top_n]]


def build_risk_summary(
    findings: List[Dict[str, Any]],
    top_files_n: int = 10,
    top_categories_n: int = 10,
) -> Dict[str, Any]:
    """
    Build a full risk summary for reports.

    Uses full risk score (severity + taint + secret + hygiene + concentration
    + unique files + critical category). Includes score_breakdown with all
    components, top_risky_files, top_risky_categories, severity_counts.
    """
    severity_counts = summarize_severity_counts(findings)
    summary = severity_counts_to_risk_summary(severity_counts)
    score, breakdown = compute_risk_breakdown(findings)
    return {
        "repository_risk_score": score,
        "risk_level": get_risk_level(score),
        "risk_level_css_class": get_risk_level_css_class(score),
        "score_breakdown": breakdown,
        "severity_counts": summary.to_counts_dict(),
        "top_risky_files": get_top_risky_files(findings, top_n=top_files_n),
        "top_risky_categories": get_top_risky_categories(findings, top_n=top_categories_n),
        "total_findings": len(findings),
    }
