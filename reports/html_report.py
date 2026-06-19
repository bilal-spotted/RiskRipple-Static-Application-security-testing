"""HTML report generator: standalone security dashboard with risk summary and findings."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, Union


def generate_html_report(report_data: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """
    Generate a standalone HTML security dashboard.

    Writes a single self-contained HTML file with risk cards, severity/category
    distribution, top risky files and categories, score breakdown, and searchable findings.

    Expected report_data format:
    {
        "target": "...",
        "files_scanned": 13,
        "total_findings": 4,
        "severity_counts": {"HIGH": 4, "MEDIUM": 0, "LOW": 0},
        "repository_risk_score": 34,
        "top_risky_files": [...],
        "findings": [...],
        "scan_errors": [...]
    }
    """
    target = str(report_data.get("target", "Unknown Target"))
    files_scanned = int(report_data.get("files_scanned", 0))
    total_findings = int(report_data.get("total_findings", 0))
    severity_counts = report_data.get("severity_counts", {}) or {}
    repository_risk_score = int(report_data.get("repository_risk_score", 0))
    risk_level = str(
        report_data.get("risk_level", "") or _get_risk_label_from_score(repository_risk_score)
    )
    risk_level_css = str(
        report_data.get("risk_level_css_class", "") or _get_risk_css_class(repository_risk_score)
    )
    score_breakdown = report_data.get("score_breakdown") or {}
    top_risky_files = report_data.get("top_risky_files", []) or []
    top_risky_categories = report_data.get("top_risky_categories", []) or []
    findings = report_data.get("findings", []) or []
    scan_errors = report_data.get("scan_errors", []) or []

    critical_count = int(severity_counts.get("CRITICAL", 0))
    high_count = int(severity_counts.get("HIGH", 0))
    medium_count = int(severity_counts.get("MEDIUM", 0))
    low_count = int(severity_counts.get("LOW", 0))

    summary_cards_html = _build_summary_cards(
        files_scanned=files_scanned,
        total_findings=total_findings,
        repository_risk_score=repository_risk_score,
        risk_level=risk_level,
        risk_level_css=risk_level_css,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )

    severity_distribution_html = _build_severity_distribution(severity_counts, total_findings)
    category_distribution_html = _build_category_distribution(top_risky_categories)
    risk_explanation_html = _build_risk_explanation_panel(
        repository_risk_score, risk_level, score_breakdown
    )

    hygiene_categories = {
        "Repository Hygiene",
        "Sensitive Artifacts",
        "Secret Exposure",
        "Secret Exposure Risks",
    }
    hygiene_findings = [f for f in findings if f.get("category") in hygiene_categories]
    hygiene_section_html = (
        _build_findings_table(hygiene_findings)
        if hygiene_findings
        else '<div class="empty-state">No repository hygiene issues detected.</div>'
    )

    taint_findings = [f for f in findings if f.get("taint_flow")]
    taint_section_html = (
        _build_findings_table(taint_findings)
        if taint_findings
        else '<div class="empty-state">No taint flow findings.</div>'
    )

    risky_files_html = _build_top_risky_files_table(top_risky_files)
    findings_table_html = _build_findings_table(findings)
    scan_errors_html = _build_scan_errors_section(scan_errors)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Ripple Report</title>
    <style>
        :root {{
            --bg: #0b1020;
            --panel: #121a2b;
            --panel-2: #172033;
            --border: #27324a;
            --text: #e7ecf3;
            --muted: #95a2b8;
            --accent: #67b7ff;
            --critical: #e63946;
            --high: #ff5d73;
            --medium: #ffb84d;
            --low: #5fd0a5;
            --shadow: 0 10px 30px rgba(0, 0, 0, 0.28);
            --mono: Consolas, Menlo, Monaco, "Courier New", monospace;
            --sans: Inter, Segoe UI, Roboto, Arial, sans-serif;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            background: linear-gradient(180deg, #0a0f1d 0%, #0b1020 100%);
            color: var(--text);
            font-family: var(--sans);
            line-height: 1.5;
        }}

        .container {{
            max-width: 1320px;
            margin: 0 auto;
            padding: 28px 20px 50px;
        }}

        .header {{
            margin-bottom: 24px;
        }}

        .title {{
            margin: 0;
            font-size: 32px;
            font-weight: 800;
            letter-spacing: 0.2px;
        }}

        .subtitle {{
            margin-top: 10px;
            color: var(--muted);
            font-size: 14px;
            word-break: break-word;
        }}

        .panel {{
            background: rgba(18, 26, 43, 0.95);
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: var(--shadow);
        }}

        .section {{
            padding: 18px 18px 16px;
            margin-bottom: 18px;
        }}

        .section-title {{
            margin: 0 0 14px 0;
            font-size: 18px;
            font-weight: 700;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 14px;
        }}

        .card {{
            background: linear-gradient(180deg, rgba(23,32,51,0.98), rgba(18,26,43,0.98));
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
        }}

        .card-label {{
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 8px;
        }}

        .card-value {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: 0.3px;
        }}

        .risk-score {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}

        .risk-pill {{
            font-size: 12px;
            font-weight: 700;
            padding: 5px 10px;
            border-radius: 999px;
            border: 1px solid transparent;
        }}

        .risk-high {{
            background: rgba(255, 93, 115, 0.12);
            color: var(--high);
            border-color: rgba(255, 93, 115, 0.28);
        }}

        .risk-medium {{
            background: rgba(255, 184, 77, 0.12);
            color: var(--medium);
            border-color: rgba(255, 184, 77, 0.28);
        }}

        .risk-low {{
            background: rgba(95, 208, 165, 0.12);
            color: var(--low);
            border-color: rgba(95, 208, 165, 0.28);
        }}

        .risk-critical {{
            background: rgba(230, 57, 70, 0.15);
            color: var(--critical);
            border-color: rgba(230, 57, 70, 0.35);
        }}

        .risk-moderate {{
            background: rgba(255, 184, 77, 0.12);
            color: var(--medium);
            border-color: rgba(255, 184, 77, 0.28);
        }}

        .bar-chart {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .bar-row {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .bar-label {{
            min-width: 90px;
            font-size: 13px;
            font-weight: 600;
        }}

        .bar-track {{
            flex: 1;
            height: 24px;
            background: rgba(255,255,255,0.06);
            border-radius: 8px;
            overflow: hidden;
        }}

        .bar-fill {{
            height: 100%;
            border-radius: 8px;
            min-width: 4px;
            transition: width 0.3s ease;
        }}

        .breakdown-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        .breakdown-table th {{
            text-align: left;
            padding: 10px 12px;
            color: var(--muted);
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }}

        .breakdown-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid rgba(39, 50, 74, 0.5);
        }}

        .breakdown-table tr:last-child td {{
            border-bottom: none;
        }}

        .toolbar {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }}

        .search-box {{
            flex: 1;
            min-width: 260px;
        }}

        .search-input {{
            width: 100%;
            background: #0f1627;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 14px;
            font-size: 14px;
            outline: none;
        }}

        .search-input:focus {{
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(103, 183, 255, 0.14);
        }}

        .small-note {{
            color: var(--muted);
            font-size: 13px;
        }}

        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 14px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            min-width: 860px;
            background: rgba(18, 26, 43, 0.75);
        }}

        thead th {{
            position: sticky;
            top: 0;
            background: #101828;
            z-index: 1;
            text-align: left;
            font-size: 12px;
            letter-spacing: 0.4px;
            text-transform: uppercase;
            color: #b9c4d8;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
        }}

        tbody td {{
            padding: 12px 14px;
            border-bottom: 1px solid rgba(39, 50, 74, 0.7);
            vertical-align: top;
            font-size: 14px;
        }}

        tbody tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 68px;
            padding: 5px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 0.3px;
            border: 1px solid transparent;
        }}

        .badge-high {{
            color: var(--high);
            background: rgba(255, 93, 115, 0.12);
            border-color: rgba(255, 93, 115, 0.28);
        }}

        .badge-medium {{
            color: var(--medium);
            background: rgba(255, 184, 77, 0.12);
            border-color: rgba(255, 184, 77, 0.28);
        }}

        .badge-low {{
            color: var(--low);
            background: rgba(95, 208, 165, 0.12);
            border-color: rgba(95, 208, 165, 0.28);
        }}

        .badge-critical {{
            color: var(--critical);
            background: rgba(230, 57, 70, 0.15);
            border-color: rgba(230, 57, 70, 0.35);
        }}

        .sub-badge {{
            display: inline-block;
            padding: 4px 8px;
            font-size: 11px;
            color: #b8c4d8;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 999px;
            margin-top: 6px;
        }}

        .path {{
            font-family: var(--mono);
            font-size: 13px;
            color: #d8e1ef;
            word-break: break-word;
        }}

        .code-block {{
            margin-top: 8px;
            background: #0a1220;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px;
            color: #d8e7ff;
            font-family: var(--mono);
            font-size: 12px;
            line-height: 1.55;
            white-space: pre-wrap;
            word-break: break-word;
        }}

        details {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 12px;
            padding: 8px 10px;
        }}

        details summary {{
            cursor: pointer;
            color: #cfe0ff;
            font-weight: 600;
            outline: none;
        }}

        .muted {{
            color: var(--muted);
        }}

        .empty-state {{
            padding: 18px;
            color: var(--muted);
            text-align: center;
            border: 1px dashed var(--border);
            border-radius: 14px;
            background: rgba(255,255,255,0.02);
        }}

        .footer-note {{
            margin-top: 18px;
            color: var(--muted);
            font-size: 12px;
        }}

        .error-item {{
            padding: 12px 14px;
            background: rgba(255, 93, 115, 0.08);
            border: 1px solid rgba(255, 93, 115, 0.18);
            border-radius: 12px;
            margin-bottom: 10px;
        }}

        .error-path {{
            font-family: var(--mono);
            color: #ffd8dd;
            font-size: 13px;
            margin-bottom: 6px;
            word-break: break-word;
        }}

        .error-msg {{
            color: #f6c8cf;
            font-size: 13px;
        }}

        @media (max-width: 760px) {{
            .title {{
                font-size: 26px;
            }}

            .container {{
                padding: 20px 14px 40px;
            }}

            .section {{
                padding: 16px 14px 14px;
            }}

            .card-value {{
                font-size: 24px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">Risk Ripple</h1>
            <div class="subtitle">
                <strong>Scan Target:</strong> {escape(target)}
            </div>
        </div>

        <div class="panel section">
            <h2 class="section-title">Risk Summary</h2>
            {summary_cards_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Risk Score Explanation</h2>
            {risk_explanation_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Severity Distribution</h2>
            {severity_distribution_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Top Risky Rule Categories</h2>
            {category_distribution_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Top Risky Files</h2>
            {risky_files_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Repository Hygiene Issues</h2>
            <div class="small-note">
                Tracked sensitive files, .gitignore gaps, and remediation guidance.
            </div>
            <div style="height: 12px;"></div>
            {hygiene_section_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Taint Flow Findings</h2>
            <div class="small-note">
                Data flow from sources (e.g. input(), request.args) to dangerous sinks.
            </div>
            <div style="height: 12px;"></div>
            {taint_section_html}
        </div>

        <div class="panel section">
            <div class="toolbar">
                <h2 class="section-title" style="margin:0;">Findings</h2>
                <div class="search-box">
                    <input
                        id="findingSearch"
                        class="search-input"
                        type="text"
                        placeholder="Search by severity, rule, file, category, line, or code..."
                        onkeyup="filterFindings()"
                    >
                </div>
            </div>
            <div class="small-note">
                Total findings: <strong>{total_findings}</strong>
            </div>
            <div style="height: 12px;"></div>
            {findings_table_html}
        </div>

        <div class="panel section">
            <h2 class="section-title">Scan Errors</h2>
            {scan_errors_html}
        </div>

        <div class="footer-note">
            Generated by Risk Ripple
        </div>
    </div>

    <script>
        function filterFindings() {{
            const input = document.getElementById("findingSearch");
            const filter = input.value.toLowerCase();
            const rows = document.querySelectorAll("#findingsTable tbody tr");

            rows.forEach(function(row) {{
                const text = row.innerText.toLowerCase();
                if (text.indexOf(filter) > -1) {{
                    row.style.display = "";
                }} else {{
                    row.style.display = "none";
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    output_path = Path(output_path)
    output_path.write_text(html, encoding="utf-8")


def _get_risk_label_from_score(score):
    """Align with core/risk.py bands: 0–20 Low, 21–50 Moderate, 51–100 High, >100 Critical."""
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Moderate"
    if score <= 100:
        return "High"
    return "Critical"


def _get_risk_css_class(score):
    level = _get_risk_label_from_score(score).lower()
    return f"risk-{level}"


def _build_summary_cards(
    files_scanned,
    total_findings,
    repository_risk_score,
    risk_level="",
    risk_level_css="",
    critical_count=0,
    high_count=0,
    medium_count=0,
    low_count=0,
):
    if not risk_level:
        risk_level = _get_risk_label_from_score(repository_risk_score)
    if not risk_level_css:
        risk_level_css = _get_risk_css_class(repository_risk_score)
    critical_card = ""
    if critical_count:
        critical_card = f"""
        <div class="card">
            <div class="card-label">CRITICAL</div>
            <div class="card-value" style="color: var(--critical);">{critical_count}</div>
        </div>"""
    return f"""
    <div class="cards">
        <div class="card">
            <div class="card-label">Files Scanned</div>
            <div class="card-value">{files_scanned}</div>
        </div>
        <div class="card">
            <div class="card-label">Total Findings</div>
            <div class="card-value">{total_findings}</div>
        </div>
        <div class="card">
            <div class="card-label">Risk Score</div>
            <div class="card-value risk-score">
                {repository_risk_score}
                <span class="risk-pill {risk_level_css}">{escape(risk_level)}</span>
            </div>
        </div>
        {critical_card}
        <div class="card">
            <div class="card-label">HIGH</div>
            <div class="card-value" style="color: var(--high);">{high_count}</div>
        </div>
        <div class="card">
            <div class="card-label">MEDIUM</div>
            <div class="card-value" style="color: var(--medium);">{medium_count}</div>
        </div>
        <div class="card">
            <div class="card-label">LOW</div>
            <div class="card-value" style="color: var(--low);">{low_count}</div>
        </div>
    </div>
    """


def _build_severity_distribution(severity_counts, total_findings):
    """Horizontal bar chart of severity counts."""
    crit = int(severity_counts.get("CRITICAL", 0))
    high = int(severity_counts.get("HIGH", 0))
    med = int(severity_counts.get("MEDIUM", 0))
    low = int(severity_counts.get("LOW", 0))
    max_count = max(crit, high, med, low, 1)
    total = total_findings or 1

    def pct(c):
        return (c / total) * 100

    def bar_pct(c):
        return (c / max_count) * 100 if max_count else 0

    rows = []
    if crit:
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" style="color: var(--critical);">CRITICAL</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{bar_pct(crit)}%; background: var(--critical);"></div></div>'
            f'<span class="muted" style="min-width: 60px;">{crit} ({pct(crit):.0f}%)</span></div>'
        )
    if high:
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" style="color: var(--high);">HIGH</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{bar_pct(high)}%; background: var(--high);"></div></div>'
            f'<span class="muted" style="min-width: 60px;">{high} ({pct(high):.0f}%)</span></div>'
        )
    if med:
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" style="color: var(--medium);">MEDIUM</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{bar_pct(med)}%; background: var(--medium);"></div></div>'
            f'<span class="muted" style="min-width: 60px;">{med} ({pct(med):.0f}%)</span></div>'
        )
    if low:
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" style="color: var(--low);">LOW</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{bar_pct(low)}%; background: var(--low);"></div></div>'
            f'<span class="muted" style="min-width: 60px;">{low} ({pct(low):.0f}%)</span></div>'
        )
    if not rows:
        return '<div class="empty-state">No findings — no severity distribution.</div>'
    return f'<div class="bar-chart">{"".join(rows)}</div>'


def _build_category_distribution(top_risky_categories):
    """Table or list of top vulnerability categories by finding count."""
    if not top_risky_categories:
        return '<div class="empty-state">No categories (no findings).</div>'
    rows = []
    for item in top_risky_categories:
        cat = escape(str(item.get("category", "General")))
        count = int(item.get("count", 0))
        rows.append(
            f'<tr><td class="path">{cat}</td><td><strong>{count}</strong> findings</td></tr>'
        )
    return f"""
    <div class="table-wrap">
        <table>
            <thead>
                <tr><th>Category</th><th>Findings</th></tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _build_risk_explanation_panel(repository_risk_score, risk_level, score_breakdown):
    """Explain how the risk score was computed (breakdown table)."""
    if not score_breakdown:
        return (
            f'<p class="muted">Risk score: <strong>{repository_risk_score}</strong> — '
            f"Level: <strong>{escape(risk_level)}</strong>. "
            "Breakdown not available (upgrade scanner for full breakdown).</p>"
        )
    rows = []
    labels = {
        "critical_contribution": "CRITICAL findings × 10",
        "high_contribution": "HIGH findings × 6",
        "medium_contribution": "MEDIUM findings × 3",
        "low_contribution": "LOW findings × 1",
        "severity_contribution": "Total severity score",
        "taint_flow_contribution": "Taint-flow findings bonus",
        "secret_exposure_contribution": "Secret exposure bonus",
        "repository_hygiene_contribution": "Repository hygiene contribution",
        "file_concentration_factor": "File concentration factor",
        "unique_files_factor": "Unique vulnerable files factor",
        "critical_category_contribution": "Critical category bonus (e.g. injection, secrets)",
    }
    for key, label in labels.items():
        val = score_breakdown.get(key, 0)
        if isinstance(val, (int, float)):
            rows.append(f"<tr><td>{escape(label)}</td><td>{val}</td></tr>")
    if not rows:
        return f'<p class="muted">Risk score: <strong>{repository_risk_score}</strong> — Level: <strong>{escape(risk_level)}</strong>.</p>'
    table_body = "".join(rows)
    return f"""
    <p class="muted" style="margin-bottom: 14px;">
        The repository risk score is the sum of weighted contributions. Level: <strong>{escape(risk_level)}</strong>.
    </p>
    <div class="table-wrap">
        <table class="breakdown-table">
            <thead>
                <tr><th>Factor</th><th>Contribution</th></tr>
            </thead>
            <tbody>
                {table_body}
            </tbody>
        </table>
    </div>
    """


def _build_top_risky_files_table(top_risky_files):
    if not top_risky_files:
        return '<div class="empty-state">No risky files detected.</div>'

    rows = []

    for item in top_risky_files:
        file_path = escape(str(item.get("file_path", "unknown")))
        risk_score = int(item.get("risk_score", 0))
        findings_count = int(item.get("findings_count", 0))
        sev = item.get("severity_counts", {}) or {}

        critical = int(sev.get("CRITICAL", 0))
        high = int(sev.get("HIGH", 0))
        medium = int(sev.get("MEDIUM", 0))
        low = int(sev.get("LOW", 0))
        crit_badge = (
            f'<span class="badge badge-critical">CRIT {critical}</span>' if critical else ""
        )
        rows.append(
            f"""
        <tr>
            <td class="path">{file_path}</td>
            <td>{risk_score}</td>
            <td>{findings_count}</td>
            <td>
                {crit_badge}
                <span class="badge badge-high">HIGH {high}</span>
                <span class="badge badge-medium" style="margin-left:6px;">MED {medium}</span>
                <span class="badge badge-low" style="margin-left:6px;">LOW {low}</span>
            </td>
        </tr>
        """
        )

    return f"""
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Risk Score</th>
                    <th>Findings</th>
                    <th>Severity Breakdown</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _build_findings_table(findings):
    if not findings:
        return '<div class="empty-state">No findings detected.</div>'

    rows = []

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        confidence = str(finding.get("confidence", "MEDIUM")).upper()
        category = str(finding.get("category", "General"))
        rule_id = str(finding.get("rule_id", "N/A"))
        title = str(finding.get("title") or finding.get("type") or "Untitled Finding")
        file_path = str(finding.get("file_path") or finding.get("file") or "unknown")
        line_number = finding.get("line_number") or finding.get("line") or ""
        description = str(finding.get("description", ""))
        recommendation = str(finding.get("recommendation") or finding.get("suggested_fix") or "")
        remediation = str(finding.get("remediation", ""))
        cwe = str(finding.get("cwe", ""))
        owasp = str(finding.get("owasp", ""))
        code_snippet = str(
            finding.get("code_snippet") or finding.get("snippet") or finding.get("code") or ""
        )

        severity_badge = _build_severity_badge(severity)

        searchable_blob = " ".join(
            [
                severity,
                confidence,
                category,
                rule_id,
                title,
                file_path,
                str(line_number),
                description,
                recommendation,
                remediation,
                cwe,
                owasp,
                code_snippet,
            ]
        )

        details_html = ""
        if description or recommendation or remediation or cwe or owasp or code_snippet:
            description_html = (
                f"<div><strong>Description:</strong> {escape(description)}</div>"
                if description
                else ""
            )
            recommendation_html = (
                f"<div style='margin-top:8px;'><strong>Recommendation:</strong> {escape(recommendation)}</div>"
                if recommendation
                else ""
            )
            remediation_html = (
                f"<div style='margin-top:8px;'><strong>Remediation:</strong> {escape(remediation)}</div>"
                if remediation
                else ""
            )
            refs = ", ".join(filter(None, [cwe, owasp]))
            refs_html = (
                f"<div style='margin-top:8px;' class='muted'><strong>References:</strong> {escape(refs)}</div>"
                if refs
                else ""
            )
            snippet_html = (
                f"<div class='code-block'>{escape(code_snippet)}</div>" if code_snippet else ""
            )

            details_html = f"""
            <details>
                <summary>View details</summary>
                <div style="margin-top:10px;">
                    {description_html}
                    {recommendation_html}
                    {remediation_html if remediation else ""}
                    {refs_html}
                    {snippet_html}
                </div>
            </details>
            """

        rows.append(
            f"""
        <tr data-search="{escape(searchable_blob)}">
            <td>{severity_badge}<div class="sub-badge">Confidence: {escape(confidence)}</div></td>
            <td>
                <strong>{escape(title)}</strong>
                <div class="muted" style="margin-top:4px;">{escape(rule_id)} · {escape(category)}</div>
            </td>
            <td class="path">{escape(file_path)}</td>
            <td>{escape(str(line_number))}</td>
            <td>{details_html}</td>
        </tr>
        """
        )

    return f"""
    <div class="table-wrap">
        <table id="findingsTable">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def _build_scan_errors_section(scan_errors):
    if not scan_errors:
        return '<div class="empty-state">No scan errors encountered.</div>'

    items = []

    for item in scan_errors:
        file_path = escape(str(item.get("file", "unknown")))
        error_msg = escape(str(item.get("error", "Unknown error")))
        items.append(
            f"""
        <div class="error-item">
            <div class="error-path">{file_path}</div>
            <div class="error-msg">{error_msg}</div>
        </div>
        """
        )

    return "".join(items)


def _build_severity_badge(severity):
    severity = str(severity).upper()

    if severity == "CRITICAL":
        return '<span class="badge badge-critical">CRITICAL</span>'
    if severity == "HIGH":
        return '<span class="badge badge-high">HIGH</span>'
    if severity == "MEDIUM":
        return '<span class="badge badge-medium">MEDIUM</span>'
    return '<span class="badge badge-low">LOW</span>'


def _get_risk_label_and_class(score):
    """Align with core/risk.py: 0–20 Low, 21–50 Moderate, 51–100 High, >100 Critical."""
    label = _get_risk_label_from_score(score)
    cls = _get_risk_css_class(score)
    return label, f"risk-pill {cls}"
