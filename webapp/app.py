from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for

from core.ai_review import ai_review
from core.rule_registry import load_metadata
from io_utils.file_loader import collect_source_files, read_file_content
from tools.check_secrets import scan_repository as scan_secrets
from webapp import scan_service, storage


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("WEBAPP_SECRET_KEY", "dev-key")

    storage.ensure_storage()

    @app.template_filter("fmt_ts")
    def _fmt_ts(value: Optional[str]) -> str:
        if not value:
            return "-"
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value

    @app.template_filter("severity_class")
    def _severity_class(value: str) -> str:
        sev = str(value or "LOW").upper()
        if sev == "CRITICAL":
            return "sev-critical"
        if sev == "HIGH":
            return "sev-high"
        if sev == "MEDIUM":
            return "sev-medium"
        return "sev-low"

    @app.template_filter("status_class")
    def _status_class(value: str) -> str:
        status = str(value or "queued").lower()
        if status == "completed":
            return "status-ok"
        if status == "running":
            return "status-running"
        if status == "failed":
            return "status-error"
        return "status-queued"

    def _decorate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        decorated: List[Dict[str, Any]] = []
        for finding in findings:
            f = dict(finding)
            f["display_title"] = f.get("title") or f.get("type") or "Finding"
            f["display_file"] = f.get("file_path") or f.get("file") or "unknown"
            f["display_line"] = f.get("line_number") or f.get("line") or ""
            f["display_category"] = f.get("category") or "General"
            f["display_severity"] = str(f.get("severity") or "LOW").upper()
            f["display_confidence"] = str(f.get("confidence") or "MEDIUM").upper()
            f["display_recommendation"] = f.get("recommendation") or f.get("suggested_fix") or ""
            f["display_snippet"] = f.get("code_snippet") or f.get("snippet") or f.get("code") or ""
            refs: List[str] = []
            if f.get("cwe"):
                refs.append(str(f.get("cwe")))
            if f.get("owasp"):
                refs.append(str(f.get("owasp")))
            if isinstance(f.get("references"), list):
                refs.extend([str(r) for r in f.get("references") if r])
            f["references_text"] = ", ".join([r for r in refs if r])
            decorated.append(f)
        return decorated

    def _quote(value: str) -> str:
        if " " in value or "\t" in value:
            return f'"{value}"'
        return value

    def _build_cli_command(options: Dict[str, Any]) -> str:
        target = options.get("target") or "."
        parts = ["python", "scanner.py", _quote(str(target))]
        parts.extend(["--workers", str(options.get("workers", 8))])
        parts.extend(["--top-files", str(options.get("top_files", 5))])
        formats = options.get("formats") or ["all"]
        if formats:
            parts.append("--format")
            parts.extend([str(f) for f in formats])
        output_dir = options.get("output_dir") or "output"
        parts.extend(["--output-dir", _quote(str(output_dir))])
        if options.get("fail_on_severity"):
            parts.extend(["--fail-on-severity", str(options["fail_on_severity"])])
        if options.get("fail_on_score") is not None:
            parts.extend(["--fail-on-score", str(options["fail_on_score"])])
        if options.get("verbose"):
            parts.append("--verbose")
        if options.get("quiet"):
            parts.append("--quiet")
        return " ".join(parts)

    def _load_run_or_none(run_id: str) -> Optional[Dict[str, Any]]:
        return storage.load_meta(run_id)

    def _load_report_or_none(run_id: str) -> Optional[Dict[str, Any]]:
        return storage.load_report(run_id)

    def _get_hygiene_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        categories = {
            "Repository Hygiene",
            "Sensitive Artifacts",
            "Secret Exposure",
            "Secret Exposure Risks",
        }
        return [f for f in findings if f.get("category") in categories]

    def _get_taint_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [f for f in findings if f.get("taint_flow") or str(f.get("detection_type", "")).lower() == "taint"]

    @app.route("/")
    def home() -> str:
        runs = storage.list_runs()[:5]
        return render_template("home.html", runs=runs, active_page="home")

    @app.route("/scan", methods=["GET", "POST"])
    def scan() -> str:
        if request.method == "POST":
            options = {
                "target": request.form.get("target", "").strip(),
                "workers": request.form.get("workers", "8"),
                "top_files": request.form.get("top_files", "5"),
                "formats": request.form.getlist("formats"),
                "output_dir": request.form.get("output_dir", "output").strip(),
                "fail_on_severity": request.form.get("fail_on_severity") or None,
                "fail_on_score": request.form.get("fail_on_score"),
                "verbose": bool(request.form.get("verbose")),
                "quiet": bool(request.form.get("quiet")),
            }
            run_id = scan_service.start_scan(options)
            return redirect(url_for("run_status", run_id=run_id))

        defaults = {
            "target": str(Path.cwd()),
            "workers": 8,
            "top_files": 5,
            "formats": ["all"],
            "output_dir": "output",
            "fail_on_severity": "",
            "fail_on_score": "",
        }
        return render_template("scan_new.html", defaults=defaults, active_page="scan")

    @app.route("/runs")
    def runs() -> str:
        return render_template("run_list.html", runs=storage.list_runs(), active_page="runs")

    @app.route("/runs/<run_id>")
    def run_overview(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        report = _load_report_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        return render_template(
            "run_overview.html",
            run=run,
            report=report,
            active_page="runs",
            cli_command=_build_cli_command(run.get("options", {})),
        )

    @app.route("/runs/<run_id>/status")
    def run_status(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        return render_template("run_status.html", run=run, active_page="runs")

    @app.route("/runs/<run_id>/status.json")
    def run_status_json(run_id: str):
        run = _load_run_or_none(run_id)
        if not run:
            return jsonify({"error": "run not found"}), 404
        events = run.get("events") or []
        last_event = events[-1]["message"] if events else ""
        return jsonify(
            {
                "status": run.get("status"),
                "progress": run.get("progress", 0),
                "last_event": last_event,
                "finished_at": run.get("finished_at"),
            }
        )

    @app.route("/runs/<run_id>/findings")
    def run_findings(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        report = _load_report_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        findings = _decorate_findings(report.get("findings", []) if report else [])
        categories = sorted({f.get("display_category") for f in findings})
        return render_template(
            "run_findings.html",
            run=run,
            report=report,
            findings=findings,
            categories=categories,
            active_page="runs",
        )

    @app.route("/runs/<run_id>/hygiene")
    def run_hygiene(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        report = _load_report_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        findings = _decorate_findings(_get_hygiene_findings(report.get("findings", []) if report else []))
        return render_template(
            "run_hygiene.html",
            run=run,
            report=report,
            findings=findings,
            active_page="runs",
        )

    @app.route("/runs/<run_id>/taint")
    def run_taint(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        report = _load_report_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        findings = _decorate_findings(_get_taint_findings(report.get("findings", []) if report else []))
        return render_template(
            "run_taint.html",
            run=run,
            report=report,
            findings=findings,
            active_page="runs",
        )

    @app.route("/runs/<run_id>/reports")
    def run_reports(run_id: str) -> str:
        run = _load_run_or_none(run_id)
        report = _load_report_or_none(run_id)
        if not run:
            return render_template("run_not_found.html", active_page="runs"), 404
        reports_dir = storage.run_reports_dir(run_id)
        files = {
            "md": reports_dir / "security_report.md",
            "html": reports_dir / "security_report.html",
            "json": reports_dir / "security_report.json",
            "sarif": reports_dir / "security_report.sarif",
        }
        availability = {k: v.exists() for k, v in files.items()}
        return render_template(
            "run_reports.html",
            run=run,
            report=report,
            availability=availability,
            active_page="runs",
        )

    @app.route("/runs/<run_id>/download/<fmt>")
    def download_report(run_id: str, fmt: str):
        reports_dir = storage.run_reports_dir(run_id)
        filename_map = {
            "md": "security_report.md",
            "html": "security_report.html",
            "json": "security_report.json",
            "sarif": "security_report.sarif",
        }
        if fmt not in filename_map:
            return jsonify({"error": "unknown format"}), 400
        filename = filename_map[fmt]
        return send_from_directory(reports_dir, filename, as_attachment=(fmt != "html"))

    @app.route("/rules")
    def rules() -> str:
        rules = load_metadata()
        rules.sort(key=lambda r: (r.get("category", ""), r.get("rule_id", "")))
        return render_template("rules.html", rules=rules, active_page="rules")

    @app.route("/ai-review", methods=["GET", "POST"])
    def ai_review_page() -> str:
        target = request.args.get("target", "").strip()
        files: List[Path] = []
        file_options: List[Dict[str, str]] = []
        review_result = ""
        snippet = ""
        selected_file = ""

        if target:
            path = Path(target).expanduser().resolve()
            if path.is_dir():
                files = collect_source_files(path)
                for item in files:
                    file_options.append({"value": str(item), "label": str(item.relative_to(path))})

        if request.method == "POST":
            action = request.form.get("action")
            target = request.form.get("target", "").strip()
            selected_file = request.form.get("selected_file", "").strip()
            snippet = request.form.get("snippet", "")

            if action == "load_files" and target:
                return redirect(url_for("ai_review_page", target=target))

            if selected_file and (action == "load_file" or not snippet):
                snippet = read_file_content(Path(selected_file))

            if action == "run_review" and snippet:
                file_label = selected_file or "snippet"
                review_result = ai_review(snippet, file_label)

        return render_template(
            "ai_review.html",
            active_page="ai_review",
            target=target,
            file_options=file_options,
            selected_file=selected_file,
            snippet=snippet,
            review_result=review_result,
        )

    @app.route("/tools/secrets", methods=["GET", "POST"])
    def secret_scan() -> str:
        target = str(Path.cwd())
        include_fixtures = False
        issues: List[Dict[str, str]] = []
        status = ""

        if request.method == "POST":
            target = request.form.get("target", target).strip()
            include_fixtures = bool(request.form.get("include_fixtures"))
            root = Path(target).expanduser().resolve()
            if not root.is_dir():
                status = f"Not a directory: {root}"
            else:
                results = scan_secrets(root, include_test_fixtures=include_fixtures)
                issues = [{"path": str(path), "issue": issue} for path, issue in results]
                status = "No potential secrets found." if not issues else "Possible secrets detected."

        return render_template(
            "secret_scan.html",
            active_page="tools",
            target=target,
            include_fixtures=include_fixtures,
            issues=issues,
            status=status,
        )

    @app.route("/cli")
    def cli_page() -> str:
        runs = storage.list_runs()
        options = runs[0].get("options", {}) if runs else {}
        cli_command = _build_cli_command(options) if options else "python scanner.py . --format all"
        return render_template("cli.html", active_page="cli", cli_command=cli_command)

    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("WEBAPP_HOST", "127.0.0.1")
    port = int(os.getenv("WEBAPP_PORT", "8000"))
    debug = os.getenv("WEBAPP_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
