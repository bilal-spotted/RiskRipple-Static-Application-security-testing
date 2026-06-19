"""
Canonical severity model for Risk Ripple.

All detection, risk scoring, and reporting use this single definition.
Severity levels: CRITICAL, HIGH, MEDIUM, LOW.
"""

from __future__ import annotations

from typing import Dict

# Canonical order (most to least severe); used for sorting and iteration
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Weights for risk scoring and sort order (higher = more severe).
# Used by core/risk.py for scoring and core/analyzer.py for finding sort order.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
}

# Default severity when not specified
DEFAULT_SEVERITY = "LOW"


def normalize_severity(severity: str | None) -> str:
    """
    Normalize a severity string to a canonical level.

    Returns one of SEVERITY_LEVELS; unknown values map to LOW.
    """
    if not severity or not str(severity).strip():
        return DEFAULT_SEVERITY
    s = str(severity).strip().upper()
    return s if s in SEVERITY_WEIGHTS else DEFAULT_SEVERITY


def severity_sort_key(severity: str) -> int:
    """Return numeric key for sort order (higher = more severe)."""
    return SEVERITY_WEIGHTS.get(normalize_severity(severity), 0)
