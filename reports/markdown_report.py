"""Markdown report generator: human-readable audit-style report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Union


def generate_markdown_report(report_data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """
    Generate a Markdown security report.

    Writes a single .md file with summary, risk explanation, top files/categories,
    hygiene, taint findings, and full findings list.

    report_data structure:

    {
        "target": "...",
        "files_scanned": 13,
        "total_findings": 4,
        "severity_counts": {...},
        "repository_risk_score": 34,
        "top_risky_files": [...],
        "findings": [...],
        "scan_errors": [...]
    }
    """

    target = report_data.get("target", "Unknown")
    files_scanned = report_data.get("files_scanned", 0)
    total_findings = report_data.get("total_findings", 0)
    severity_counts = report_data.get("severity_counts", {})
    risk_score = report_data.get("repository_risk_score", 0)
    risk_level = report_data.get("risk_level", "")
    score_breakdown = report_data.get("score_breakdown") or {}
    top_risky_files = report_data.get("top_risky_files", [])
    top_risky_categories = report_data.get("top_risky_categories", [])
    findings = report_data.get("findings", [])
    scan_errors = report_data.get("scan_errors", [])

    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    lines = []

    # Header
    lines.append("# Risk Ripple Report\n")
    lines.append(f"**Scan Target:** `{target}`  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Summary
    lines.append("## Scan Summary\n")

    lines.append(f"- Files scanned: **{files_scanned}**")
    lines.append(f"- Total findings: **{total_findings}**")
    lines.append(
        f"- Repository risk score: **{risk_score}** — Risk level: **{risk_level or 'N/A'}**\n"
    )

    lines.append("### Severity Breakdown\n")
    if critical:
        lines.append(f"- CRITICAL: **{critical}**")
    lines.append(f"- HIGH: **{high}**")
    lines.append(f"- MEDIUM: **{medium}**")
    lines.append(f"- LOW: **{low}**\n")

    # Top risky files
    lines.append("## Top Risky Files\n")

    if not top_risky_files:
        lines.append("_No risky files detected._\n")
    else:
        lines.append("| File | Risk Score | Findings |")
        lines.append("|------|-----------|----------|")

        for item in top_risky_files:
            file_path = item.get("file_path", "")
            score = item.get("risk_score", 0)
            count = item.get("findings_count", 0)

            lines.append(f"| `{file_path}` | {score} | {count} |")

        lines.append("")

    # Risk score explanation
    if score_breakdown:
        lines.append("## Risk Score Explanation\n")
        lines.append("| Factor | Contribution |")
        lines.append("|--------|--------------|")
        for key, label in [
            ("critical_contribution", "CRITICAL × 10"),
            ("high_contribution", "HIGH × 6"),
            ("medium_contribution", "MEDIUM × 3"),
            ("low_contribution", "LOW × 1"),
            ("severity_contribution", "Total severity score"),
            ("taint_flow_contribution", "Taint-flow bonus"),
            ("secret_exposure_contribution", "Secret exposure bonus"),
            ("repository_hygiene_contribution", "Repository hygiene"),
            ("file_concentration_factor", "File concentration"),
            ("unique_files_factor", "Unique files factor"),
            ("critical_category_contribution", "Critical category bonus"),
        ]:
            val = score_breakdown.get(key, 0)
            lines.append(f"| {label} | {val} |")
        lines.append("")

    # Top risky categories
    if top_risky_categories:
        lines.append("## Top Risky Rule Categories\n")
        lines.append("| Category | Findings |")
        lines.append("|----------|----------|")
        for item in top_risky_categories:
            cat = item.get("category", "General")
            count = item.get("count", 0)
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # Repository Hygiene (subset)
    hygiene_categories = {
        "Repository Hygiene",
        "Sensitive Artifacts",
        "Secret Exposure",
        "Secret Exposure Risks",
    }
    hygiene_findings = [f for f in findings if f.get("category") in hygiene_categories]
    if hygiene_findings:
        lines.append("## Repository Hygiene & Sensitive Artifacts\n")
        for finding in hygiene_findings:
            severity = finding.get("severity", "LOW")
            title = finding.get("title") or finding.get("type") or "Finding"
            file_path = finding.get("file_path") or finding.get("file")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation") or finding.get("suggested_fix", "")
            remediation = finding.get("remediation", "")
            lines.append(f"### {title}")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **File/Path:** `{file_path}`")
            if description:
                lines.append(f"- **Description:** {description}")
            if recommendation:
                lines.append(f"- **Recommendation:** {recommendation}")
            if remediation:
                lines.append(f"- **Remediation:** {remediation}")
            lines.append("")
        lines.append("")

    # Taint Flow Findings
    taint_findings = [f for f in findings if f.get("taint_flow")]
    if taint_findings:
        lines.append("## Taint Flow Findings\n")
        for finding in taint_findings:
            severity = finding.get("severity", "LOW")
            title = finding.get("title") or finding.get("type") or "Taint flow"
            file_path = finding.get("file_path") or finding.get("file")
            description = finding.get("description", "")
            source = finding.get("source", "")
            sink = finding.get("sink", "")
            lines.append(f"### {title}")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **File:** `{file_path}`")
            if source and sink:
                lines.append(f"- **Flow:** {source} → {sink}")
            if description:
                lines.append(f"- **Description:** {description}")
            lines.append("")
        lines.append("")

    # Findings (all)
    lines.append("## Findings\n")

    if not findings:
        lines.append("_No vulnerabilities detected._\n")
    else:
        for finding in findings:
            severity = finding.get("severity", "LOW")
            title = finding.get("title") or finding.get("type") or "Finding"
            file_path = finding.get("file_path") or finding.get("file")
            line = finding.get("line_number") or finding.get("line")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation") or finding.get("suggested_fix", "")
            snippet = finding.get("code_snippet") or finding.get("snippet") or ""

            lines.append(f"### {title}")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **File:** `{file_path}`")
            lines.append(f"- **Line:** {line}")

            if description:
                lines.append(f"- **Description:** {description}")

            if recommendation:
                lines.append(f"- **Recommendation:** {recommendation}")
            remediation = finding.get("remediation", "")
            if remediation:
                lines.append(f"- **Remediation:** {remediation}")
            cwe = finding.get("cwe", "")
            owasp = finding.get("owasp", "")
            if cwe or owasp:
                lines.append(f"- **References:** {', '.join(filter(None, [cwe, owasp]))}")

            if snippet:
                lines.append("\n```")
                lines.append(snippet)
                lines.append("```")

            lines.append("")

    # Scan errors
    lines.append("## Scan Errors\n")

    if not scan_errors:
        lines.append("_No scan errors._")
    else:
        for err in scan_errors:
            file = err.get("file", "")
            msg = err.get("error", "")
            lines.append(f"- `{file}` : {msg}")

    lines.append("")

    output_path = Path(output_path)
    output_path.write_text("\n".join(lines), encoding="utf-8")
