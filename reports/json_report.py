"""JSON report generator: structured export for automation."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Union


def generate_json_report(report_data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """
    Write a structured JSON report for automation and tooling.

    Output includes: tool metadata, scan_summary (files_scanned, total_findings,
    severity_counts, repository_risk_score, risk_level, score_breakdown),
    top_risky_files, top_risky_categories, findings, and scan_errors.
    """
    output = {
        "tool": "Risk Ripple",
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": report_data.get("target"),
        "scan_summary": {
            "files_scanned": report_data.get("files_scanned", 0),
            "total_findings": report_data.get("total_findings", 0),
            "severity_counts": report_data.get("severity_counts", {}),
            "repository_risk_score": report_data.get("repository_risk_score", 0),
            "risk_level": report_data.get("risk_level", ""),
            "score_breakdown": report_data.get("score_breakdown", {}),
        },
        "top_risky_files": report_data.get("top_risky_files", []),
        "top_risky_categories": report_data.get("top_risky_categories", []),
        "findings": report_data.get("findings", []),
        "scan_errors": report_data.get("scan_errors", []),
    }

    output_path = Path(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
