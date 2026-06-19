from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.normalize import normalize_and_deduplicate_findings
from core.rule_registry import enrich_findings
from core.severity import normalize_severity
from io_utils.repo_loader import get_source_files
from scanner import build_report_data, run_hygiene_checks, scan_repository, write_reports
from webapp import storage

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SCAN_STEPS = [
    ("Validating target", 5),
    ("Collecting source files", 20),
    ("Scanning repository", 55),
    ("Checking repository hygiene", 70),
    ("Enriching and normalizing findings", 85),
    ("Writing reports", 95),
    ("Completed", 100),
]


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _coerce_int(value: Any, default: Optional[int]) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text == "":
        return default
    try:
        return int(text)
    except ValueError:
        return default


def _normalize_formats(formats: List[str]) -> List[str]:
    cleaned = [f.strip() for f in formats if f and str(f).strip()]
    if not cleaned or "all" in cleaned:
        return ["all"]
    return cleaned


def _sanitize_options(raw: Dict[str, Any]) -> Dict[str, Any]:
    target = str(raw.get("target", "")).strip()
    workers = _coerce_int(raw.get("workers"), 8) or 8
    if workers < 1:
        workers = 1
    top_files = _coerce_int(raw.get("top_files"), 5)
    if top_files is None or top_files < 0:
        top_files = 5
    formats = _normalize_formats(raw.get("formats") or [])
    output_dir = str(raw.get("output_dir") or "output").strip() or "output"
    fail_on_severity = raw.get("fail_on_severity") or None
    if fail_on_severity and fail_on_severity not in SEVERITY_ORDER:
        fail_on_severity = None
    fail_on_score = _coerce_int(raw.get("fail_on_score"), None)
    verbose = bool(raw.get("verbose"))
    quiet = bool(raw.get("quiet"))
    return {
        "target": target,
        "workers": workers,
        "top_files": top_files,
        "formats": formats,
        "output_dir": output_dir,
        "fail_on_severity": fail_on_severity,
        "fail_on_score": fail_on_score,
        "verbose": verbose,
        "quiet": quiet,
    }


def should_fail_on_severity(findings: List[Dict[str, Any]], threshold: str) -> bool:
    try:
        idx = SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False
    allowed = set(SEVERITY_ORDER[idx:])
    for finding in findings:
        sev = normalize_severity(finding.get("severity"))
        if sev in allowed:
            return True
    return False


def _resolve_output_dir(output_dir: str) -> Path:
    path = Path(output_dir)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    return path


def start_scan(raw_options: Dict[str, Any]) -> str:
    storage.ensure_storage()
    run_id = uuid.uuid4().hex
    options = _sanitize_options(raw_options)
    meta = {
        "id": run_id,
        "status": "queued",
        "created_at": _now_iso(),
        "progress": 0,
        "options": options,
        "target": options.get("target"),
        "events": [],
    }
    storage.save_meta(run_id, meta)

    thread = threading.Thread(target=_execute_scan, args=(run_id, options), daemon=True)
    thread.start()
    return run_id


def _execute_scan(run_id: str, options: Dict[str, Any]) -> None:
    start_time = time.time()
    events: List[Dict[str, Any]] = []

    def log_event(message: str, progress: Optional[int] = None) -> None:
        events.append({"ts": _now_iso(), "message": message})
        updates: Dict[str, Any] = {"events": events}
        if progress is not None:
            updates["progress"] = progress
        storage.update_meta(run_id, updates)

    storage.update_meta(run_id, {"status": "running", "started_at": _now_iso()})

    try:
        log_event("Validating target", SCAN_STEPS[0][1])
        target_text = options.get("target") or ""
        if not target_text:
            raise ValueError("Target path is required")
        target = Path(target_text).expanduser().resolve()
        storage.update_meta(run_id, {"target_resolved": str(target)})

        if not target.exists():
            raise ValueError(f"Target path does not exist: {target}")
        if not target.is_dir():
            raise ValueError(f"Target is not a directory: {target}")

        log_event("Collecting source files", SCAN_STEPS[1][1])
        files = get_source_files(str(target))

        findings: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        if files:
            log_event("Scanning repository", SCAN_STEPS[2][1])
            findings, errors = scan_repository(files, workers=options["workers"])
        else:
            log_event("No source files found", SCAN_STEPS[2][1])

        log_event("Checking repository hygiene", SCAN_STEPS[3][1])
        findings = findings + run_hygiene_checks(str(target))

        log_event("Enriching and normalizing findings", SCAN_STEPS[4][1])
        findings = enrich_findings(findings)
        findings = normalize_and_deduplicate_findings(findings)

        report_data = build_report_data(
            target,
            files,
            findings,
            errors,
            top_files_n=options["top_files"],
            top_categories_n=10,
        )

        log_event("Writing reports", SCAN_STEPS[5][1])
        run_reports_dir = storage.run_reports_dir(run_id)
        formats = options["formats"]
        write_reports(report_data, run_reports_dir, list(formats), quiet=True)

        output_dir = _resolve_output_dir(options["output_dir"])
        if output_dir != run_reports_dir:
            write_reports(report_data, output_dir, list(formats), quiet=True)

        storage.save_report(run_id, report_data)

        threshold_summary: Dict[str, Any] = {
            "severity_threshold": options.get("fail_on_severity"),
            "score_threshold": options.get("fail_on_score"),
            "severity_breached": False,
            "score_breached": False,
        }
        if options.get("fail_on_severity"):
            threshold_summary["severity_breached"] = should_fail_on_severity(
                findings, options["fail_on_severity"]
            )
        if options.get("fail_on_score") is not None:
            threshold_summary["score_breached"] = (
                report_data.get("repository_risk_score", 0) >= options["fail_on_score"]
            )
        exit_code = 1 if (threshold_summary["severity_breached"] or threshold_summary["score_breached"]) else 0

        duration = round(time.time() - start_time, 2)
        storage.update_meta(
            run_id,
            {
                "status": "completed",
                "finished_at": _now_iso(),
                "duration_sec": duration,
                "progress": SCAN_STEPS[6][1],
                "summary": {
                    "files_scanned": report_data.get("files_scanned", 0),
                    "total_findings": report_data.get("total_findings", 0),
                    "risk_score": report_data.get("repository_risk_score", 0),
                    "risk_level": report_data.get("risk_level", ""),
                    "severity_counts": report_data.get("severity_counts", {}),
                },
                "output_dir": str(output_dir),
                "run_reports_dir": str(run_reports_dir),
                "formats": formats,
                "thresholds": threshold_summary,
                "exit_code": exit_code,
            },
        )
        log_event("Completed", SCAN_STEPS[6][1])
    except Exception as exc:
        duration = round(time.time() - start_time, 2)
        storage.update_meta(
            run_id,
            {
                "status": "failed",
                "finished_at": _now_iso(),
                "duration_sec": duration,
                "progress": 100,
                "error": str(exc),
                "exit_code": 1,
            },
        )
        log_event(f"Failed: {exc}", 100)
