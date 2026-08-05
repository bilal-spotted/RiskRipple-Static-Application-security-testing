from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["HIGH", "MEDIUM", "LOW"]

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 1,
}


@dataclass
class RiskSummary:
    high: int
    medium: int
    low: int

    @property
    def total_findings(self) -> int:
        return self.high + self.medium + self.low

    def to_dict(self) -> dict:
        return {
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total_findings": self.total_findings,
        }


def compute_risk_score(summary: RiskSummary) -> tuple[int, str]:
    """
    Compute a simple weighted risk score and label.
    """
    score = (
        summary.high * SEVERITY_WEIGHTS["HIGH"]
        + summary.medium * SEVERITY_WEIGHTS["MEDIUM"]
        + summary.low * SEVERITY_WEIGHTS["LOW"]
    )

    if score == 0:
        label = "LOW"
    elif score <= 10:
        label = "LOW"
    elif score <= 25:
        label = "MODERATE"
    elif score <= 50:
        label = "HIGH"
    else:
        label = "CRITICAL"

    return score, label


def verbose_print(enabled: bool, message: str) -> None:
    if enabled:
        print(message)
