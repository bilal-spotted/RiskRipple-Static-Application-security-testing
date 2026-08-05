from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.repo_hygiene import get_hygiene_rule_metadata
from core.rule_registry import LEGACY_RULE_ID_MAP, get_registry
from core.rules_engine import get_all_regex_rules, get_python_ast_rule_metadata
from core.taint_analysis import get_taint_rule_metadata

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def generate_sarif_report(report_data: Dict[str, Any], output_path) -> None:
    """
    Generate a lightweight SARIF 2.1.0 report.

    This is intentionally minimal but structurally correct, so it can be uploaded
    to code scanning tools (or used as a portfolio demo artifact).
    """
    findings = report_data.get("findings", []) or []
    target = str(report_data.get("target", ""))

    rules_index = _build_rules_index()
    sarif_rules = _build_sarif_rules(rules_index)
    results = _build_results(findings, rules_index)

    inv_properties: Dict[str, Any] = {"target": target}
    run_risk_score = int(report_data.get("repository_risk_score", 0))
    run_risk_level = str(report_data.get("risk_level", ""))
    score_breakdown = report_data.get("score_breakdown") or {}

    run_properties: Dict[str, Any] = {
        "repository_risk_score": run_risk_score,
        "risk_level": run_risk_level,
    }
    if score_breakdown:
        run_properties["score_breakdown"] = score_breakdown

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Risk Ripple",
                        "informationUri": "https://example.com",
                        "version": "1.0.0",
                        "rules": sarif_rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                        "properties": inv_properties,
                    }
                ],
                "results": results,
                "properties": run_properties,
            }
        ],
    }

    output_path = Path(output_path)
    output_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")


def _severity_to_level(severity: str) -> str:
    sev = str(severity).upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _build_rules_index() -> Dict[str, Dict[str, Any]]:
    """
    Index rules by rule_id. Prefer rule metadata from registry (YAML);
    fall back to module metadata for any rule not in registry.
    """
    index: Dict[str, Dict[str, Any]] = {}
    registry = get_registry()

    for rule in registry.get_all():
        rid = str(rule.get("rule_id", ""))
        if rid:
            r = dict(rule)
            if not r.get("recommendation") and r.get("remediation"):
                r["recommendation"] = r["remediation"]
            index[rid] = r
    for legacy_id, canonical_id in LEGACY_RULE_ID_MAP.items():
        if legacy_id not in index and canonical_id in index:
            index[legacy_id] = dict(index[canonical_id])

    for rule in get_python_ast_rule_metadata():
        index.setdefault(str(rule.get("rule_id", "")), rule)
    for rule in get_all_regex_rules():
        rid = str(rule.get("rule_id", ""))
        if rid:
            index.setdefault(rid, rule)
    for rule in get_hygiene_rule_metadata():
        rid = str(rule.get("rule_id", ""))
        if rid:
            index.setdefault(rid, rule)
    for rule in get_taint_rule_metadata():
        rid = str(rule.get("rule_id", ""))
        if rid:
            index.setdefault(rid, rule)

    return index


def _build_sarif_rules(rules_index: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    sarif_rules: List[Dict[str, Any]] = []
    for rule_id in sorted(rules_index.keys()):
        rule = rules_index[rule_id]
        title = str(rule.get("title", rule_id))
        description = str(rule.get("description", "")).strip()
        recommendation = str(rule.get("recommendation", "") or rule.get("remediation", "")).strip()

        full_desc_parts = []
        if description:
            full_desc_parts.append(description)
        if recommendation:
            full_desc_parts.append(f"Remediation: {recommendation}")
        cwe = rule.get("cwe")
        owasp = rule.get("owasp")
        if cwe or owasp:
            full_desc_parts.append("References: " + ", ".join(filter(None, [cwe, owasp])))

        help_text = recommendation or "Review and remediate this issue."
        if cwe:
            help_text += f" ({cwe})"
        if owasp:
            help_text += f" [{owasp}]"

        props: Dict[str, Any] = {
            "category": rule.get("category", "General"),
            "severity": rule.get("severity", "LOW"),
            "confidence": rule.get("confidence", "MEDIUM"),
        }
        if cwe:
            props["cwe"] = cwe
        if owasp:
            props["owasp"] = owasp

        sarif_rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": "\n".join(full_desc_parts) if full_desc_parts else title
                },
                "help": {"text": help_text},
                "properties": props,
            }
        )
    return sarif_rules


def _build_results(
    findings: List[Dict[str, Any]], rules_index: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = str(f.get("rule_id") or "UNKNOWN")
        severity = str(f.get("severity", "LOW"))
        title = str(f.get("title") or f.get("type") or rule_id)
        file_path = str(f.get("file_path") or f.get("file") or "")
        line_number = _safe_int(f.get("line_number") or f.get("line"))
        snippet = str(f.get("code_snippet") or f.get("snippet") or f.get("code") or "")

        message_text = title
        description = str(f.get("description", "")).strip()
        if description:
            message_text = f"{title} - {description}"

        region = None
        if line_number and line_number > 0:
            region = {"startLine": line_number}

        location = None
        if file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    **({"region": region} if region else {}),
                }
            }

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _severity_to_level(severity),
            "message": {"text": message_text},
        }

        if location:
            result["locations"] = [location]

        fingerprint = f.get("fingerprint")
        if fingerprint:
            result["fingerprints"] = {"contentHash": fingerprint}

        rule_meta = rules_index.get(rule_id, {})
        result["properties"] = {
            "severity": severity,
            "confidence": str(f.get("confidence", rule_meta.get("confidence", "MEDIUM"))),
            "category": str(f.get("category", rule_meta.get("category", "General"))),
        }

        if snippet:
            result["properties"]["code_snippet"] = snippet

        results.append(result)

    return results


def _safe_int(value: Optional[Any]) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None
