"""
Risk Ripple — CLI entry point.

Scans a target directory for code vulnerabilities (SAST) and repository
hygiene issues (sensitive artifacts, .gitignore gaps). Produces reports
in Markdown, HTML, JSON, and SARIF.
"""

from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.analyzer import analyze_file
from core.normalize import normalize_and_deduplicate_findings
from core.repo_hygiene import check_gitignore_hygiene, scan_repository_hygiene
from core.risk import (
    build_risk_summary,
    calculate_repository_risk_score,
    get_risk_level,
    get_top_risky_files,
    summarize_severity_counts,
)
from core.rule_registry import enrich_findings
from core.severity import SEVERITY_LEVELS, normalize_severity
from io_utils.repo_loader import get_source_files
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report
from reports.sarif_report import generate_sarif_report

logger = logging.getLogger(__name__)

# Severity order for --fail-on-severity (most severe first)
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# =========================
# CLI
# =========================


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Namespace with target, workers, format, output_dir, top_files,
        fail_on_severity, fail_on_score, verbose, quiet.
    """
    parser = argparse.ArgumentParser(
        description="Risk Ripple — rule-based SAST and repository hygiene scanner. Scans a directory for vulnerabilities and produces Markdown, HTML, JSON, and SARIF reports.",
        epilog="Example: python scanner.py . --output-dir reports --format all",
    )

    parser.add_argument(
        "target",
        help="Path to repository or source directory to scan",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Number of concurrent scan workers (default: 8)",
    )

    parser.add_argument(
        "--top-files",
        type=int,
        default=5,
        metavar="N",
        help="Number of top risky files to show in summary (default: 5)",
    )

    parser.add_argument(
        "--format",
        nargs="+",
        choices=["md", "html", "json", "sarif", "all"],
        default=["all"],
        help="Report format(s): md, html, json, sarif, or all (default: all)",
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        metavar="DIR",
        help="Output directory for report files (default: output)",
    )

    parser.add_argument(
        "--fail-on-severity",
        choices=list(_SEVERITY_ORDER),
        default=None,
        metavar="LEVEL",
        help="Exit with code 1 if any finding has this severity or higher (e.g. --fail-on-severity HIGH)",
    )

    parser.add_argument(
        "--fail-on-score",
        type=int,
        default=None,
        metavar="N",
        help="Exit with code 1 if repository risk score is >= N",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only print errors and exit status; no scan summary",
    )

    return parser.parse_args()


# =========================
# Scan logic
# =========================


def scan_file_safe(file_path: str) -> Dict[str, Any]:
    """
    Run SAST on a single file without raising.

    Returns:
        Dict with keys: 'file' (str), 'findings' (list), 'error' (str or None).
    """
    try:
        findings = analyze_file(file_path)
        return {"file": file_path, "findings": findings, "error": None}
    except Exception as e:
        logger.warning(
            "Scan failed for %s: %s", file_path, e, exc_info=logger.isEnabledFor(logging.DEBUG)
        )
        return {"file": file_path, "findings": [], "error": str(e)}


def scan_repository(
    files: List[str], workers: int = 8
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    """
    Run SAST on a list of source files in parallel.

    Returns:
        Tuple of (list of finding dicts, list of error dicts with 'file' and 'error').
    """
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_file_safe, f): f for f in files}

        for future in as_completed(futures):
            result = future.result()

            if result["error"]:
                errors.append({"file": result["file"], "error": result["error"]})

            results.extend(result["findings"])

    return results, errors


def run_hygiene_checks(target_path: str) -> List[Dict[str, Any]]:
    """
    Run repository hygiene and .gitignore checks.

    Scans for sensitive files, secrets in content, and .gitignore gaps.

    Returns:
        List of finding dicts (Repository Hygiene, Sensitive Artifacts, Secret Exposure).
    """
    hygiene_findings: List[Dict[str, Any]] = []
    hygiene_findings.extend(scan_repository_hygiene(target_path))
    hygiene_findings.extend(check_gitignore_hygiene(target_path))
    return hygiene_findings


# =========================
# Terminal output
# =========================


def print_summary(
    files_scanned: int,
    findings: List[Dict[str, Any]],
    top_files_count: int,
) -> None:
    """Print scan summary to stdout: file count, finding count, severity breakdown, risk score, risk level, top risky files."""
    severity_counts = summarize_severity_counts(findings)
    repo_score = calculate_repository_risk_score(findings)
    risk_level = get_risk_level(repo_score)
    top_files = get_top_risky_files(findings, top_files_count)

    print("\nScan Summary")
    print("----------------------------")
    print(f"Files scanned: {files_scanned}")
    print(f"Total findings: {len(findings)}")
    print()

    print("Severity counts:")
    for sev in SEVERITY_LEVELS:
        print(f"  {sev}: {severity_counts.get(sev, 0)}")

    print()
    print(f"Repository risk score: {repo_score} — Risk level: {risk_level}")
    print()

    print("Top risky files:")
    for idx, item in enumerate(top_files, start=1):
        print(
            f"{idx}. {item['file_path']} "
            f"(score {item['risk_score']}, "
            f"{item['findings_count']} findings)"
        )

    print()


# =========================
# Report assembly and output
# =========================


def build_report_data(
    target: Path,
    files: List[str],
    findings: List[Dict[str, Any]],
    errors: List[Dict[str, str]],
    top_files_n: int = 5,
    top_categories_n: int = 10,
) -> Dict[str, Any]:
    """
    Build the report payload from scan results and risk summary.

    Used by main() before passing to report generators.
    """
    risk_summary = build_risk_summary(
        findings,
        top_files_n=top_files_n,
        top_categories_n=top_categories_n,
    )
    return {
        "target": str(target),
        "files_scanned": len(files),
        "total_findings": len(findings),
        "severity_counts": risk_summary["severity_counts"],
        "repository_risk_score": risk_summary["repository_risk_score"],
        "risk_level": risk_summary["risk_level"],
        "risk_level_css_class": risk_summary["risk_level_css_class"],
        "score_breakdown": risk_summary["score_breakdown"],
        "top_risky_files": risk_summary["top_risky_files"],
        "top_risky_categories": risk_summary["top_risky_categories"],
        "findings": findings,
        "scan_errors": errors,
    }


def write_reports(
    report_data: Dict[str, Any],
    output_dir: Path,
    formats: List[str],
    *,
    quiet: bool = False,
) -> None:
    """Write requested report formats to output_dir; optionally print each path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if "all" in formats:
        formats = ["md", "html", "json", "sarif"]

    if "md" in formats:
        p = output_dir / "security_report.md"
        generate_markdown_report(report_data, p)
        if not quiet:
            print("Markdown report saved to", p)
    if "html" in formats:
        p = output_dir / "security_report.html"
        generate_html_report(report_data, p)
        if not quiet:
            print("HTML report saved to", p)
    if "json" in formats:
        p = output_dir / "security_report.json"
        generate_json_report(report_data, p)
        if not quiet:
            print("JSON report saved to", p)
    if "sarif" in formats:
        p = output_dir / "security_report.sarif"
        generate_sarif_report(report_data, p)
        if not quiet:
            print("SARIF report saved to", p)


# =========================
# Main
# =========================


def _should_fail_on_severity(findings: List[Dict[str, Any]], threshold: str) -> bool:
    """Return True if any finding has severity >= threshold (in _SEVERITY_ORDER)."""
    try:
        idx = _SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False
    allowed = set(_SEVERITY_ORDER[idx:])
    for f in findings:
        sev = normalize_severity(f.get("severity"))
        if sev in allowed:
            return True
    return False


def main() -> None:
    """
    Entry point: parse args, scan target, print summary, write reports.

    Exit code 0: success. Exit code 1: target invalid, collection error,
    or fail-on-severity / fail-on-score threshold met.
    """
    args = parse_args()
    target = Path(args.target).resolve()

    # Logging
    if args.quiet:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        logger.setLevel(logging.WARNING)

    if not target.exists():
        logger.error("Target path does not exist: %s", target)
        sys.exit(1)

    if not target.is_dir():
        logger.error("Target is not a directory: %s", target)
        sys.exit(1)

    if not args.quiet:
        print("[1/5] Using local directory:", target)
        print("[2/5] Collecting source files")
    try:
        files = get_source_files(str(target))
    except Exception as e:
        logger.exception("Failed to collect files")
        print("Failed to collect files:", e, file=sys.stderr)
        sys.exit(1)

    if not files:
        if not args.quiet:
            print("No source files found.")
        sys.exit(0)

    if not args.quiet:
        print(f"Found {len(files)} files to scan.")
        print("[3/5] Scanning repository (SAST)")
    findings, errors = scan_repository(files, workers=args.workers)
    if not args.quiet:
        print("[4/5] Checking repository hygiene")
    findings = findings + run_hygiene_checks(str(target))
    findings = enrich_findings(findings)
    findings = normalize_and_deduplicate_findings(findings)

    if errors and (args.verbose or not args.quiet):
        for err in errors:
            logger.warning("Scan error: %s — %s", err.get("file"), err.get("error"))

    if not args.quiet:
        print_summary(len(files), findings, args.top_files)

    report_data = build_report_data(
        target,
        files,
        findings,
        errors,
        top_files_n=args.top_files,
        top_categories_n=10,
    )
    if not args.quiet:
        print("[5/5] Saving reports")
    write_reports(report_data, Path(args.output_dir), list(args.format), quiet=args.quiet)
    if not args.quiet:
        print("\nScan completed.")

    # Exit code by thresholds
    if args.fail_on_severity and _should_fail_on_severity(findings, args.fail_on_severity):
        sys.exit(1)
    if args.fail_on_score is not None:
        score = calculate_repository_risk_score(findings)
        if score >= args.fail_on_score:
            if args.quiet:
                print(f"Risk score {score} >= {args.fail_on_score}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
