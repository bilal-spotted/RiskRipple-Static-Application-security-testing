"""
Rule metadata registry: load, validate, and lookup rule metadata.

Hybrid architecture: detection logic stays in Python; metadata lives in
rules/metadata/ (YAML). Findings are enriched with metadata at report time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

# Legacy rule_id -> canonical rule_id for enrichment when code still emits old IDs
LEGACY_RULE_ID_MAP: Dict[str, str] = {
    "PY001": "python-eval-use",
    "PY002": "python-exec-use",
    "PY003": "python-os-system",
    "PY004": "python-subprocess-shell-true",
    "PY005": "python-pickle-loads",
    "PY006": "python-yaml-load",
    "PY007": "python-compile",
    "RH001": "repo-pycache-dir",
    "RH002": "repo-env-file",
    "RH003": "repo-private-key",
    "RH004": "repo-pyc-artifact",
    "RH004b": "repo-pyo-artifact",
    "RH005": "repo-secret-in-file",
    "RH010": "repo-gitignore-missing",
    "RH011": "repo-gitignore-tracked",
    "TAINT-CMD": "command-injection-taint",
    "TAINT-SQL": "sql-injection-taint",
    "TAINT-PATH": "path-traversal-taint",
    "TAINT001": "taint-dangerous-sink",
    "SEC001": "secret-hardcoded-password",
    "SEC002": "secret-api-key",
    "SEC003": "flask-debug-true",
    "SEC004": "requests-verify-false",
    "SEC005": "insecure-md5",
    "SEC006": "insecure-sha1",
    "SEC007": "secret-bearer-token",
    "SEC008": "secret-private-key-material",
    "SEC009": "insecure-random",
    "SEC010": "insecure-ssl-protocol",
    "GEN001": "python-eval-use-regex",
    "GEN002": "python-exec-use-regex",
}

REQUIRED_FIELDS = ("rule_id", "title", "severity", "category", "detection_type")
VALID_DETECTION_TYPES = frozenset({"ast", "regex", "taint", "hygiene"})


def _metadata_dir() -> Path:
    """Directory containing rule metadata files."""
    return Path(__file__).resolve().parent.parent / "rules" / "metadata"


def _load_yaml() -> List[Dict[str, Any]]:
    """Load rules from rules/metadata/rules.yaml. Returns list of rule dicts."""
    try:
        import yaml
    except ImportError:
        return []
    path = _metadata_dir() / "rules.yaml"
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        return []
    if not data or not isinstance(data, dict):
        return []
    rules = data.get("rules")
    if not isinstance(rules, list):
        return []
    out = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("rule_id"):
            continue
        # Normalize: ensure references is list, remediation from remediation or recommendation
        r = dict(r)
        if "remediation" not in r and r.get("recommendation"):
            r["remediation"] = r["recommendation"]
        if "references" in r and not isinstance(r["references"], list):
            r["references"] = []
        out.append(r)
    return out


def _validate_rule(rule: Dict[str, Any]) -> Optional[str]:
    """Validate a rule dict. Returns None if valid, else error message."""
    for field in REQUIRED_FIELDS:
        if not rule.get(field):
            return f"missing required field: {field}"
    dt = rule.get("detection_type", "")
    if dt not in VALID_DETECTION_TYPES:
        return f"invalid detection_type: {dt}"
    return None


class RuleRegistry:
    """
    In-memory registry of rule metadata. Loads from YAML once; provides
    lookup by rule_id with safe fallback when metadata is missing.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        raw = _load_yaml()
        for rule in raw:
            rid = str(rule.get("rule_id", "")).strip()
            if not rid:
                continue
            err = _validate_rule(rule)
            if err:
                continue
            self._rules[rid] = dict(rule)

    def get(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Return metadata for rule_id. Tries canonical id first, then legacy map.
        Returns None if not found (caller should use fallback).
        """
        if not rule_id:
            return None
        rid = rule_id.strip()
        if rid in self._rules:
            return self._rules[rid].copy()
        canonical = LEGACY_RULE_ID_MAP.get(rid)
        if canonical and canonical in self._rules:
            return self._rules[canonical].copy()
        return None

    def get_all(self) -> List[Dict[str, Any]]:
        """Return all loaded rule metadata (for SARIF/reporting)."""
        return [dict(r) for r in self._rules.values()]

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a finding dict with rule metadata. Fills in missing fields from
        metadata; adds CWE, OWASP, references, remediation when present.
        Returns a new dict.
        """
        out = dict(finding)
        rule_id = finding.get("rule_id")
        meta = self.get(rule_id) if rule_id else None
        if not meta:
            return out
        if not out.get("title") and meta.get("title"):
            out["title"] = meta["title"]
        if not out.get("type") and meta.get("title"):
            out["type"] = meta["title"]
        if not out.get("description") and meta.get("description"):
            out["description"] = meta["description"]
        if not out.get("category") and meta.get("category"):
            out["category"] = meta["category"]
        if not out.get("severity") and meta.get("severity"):
            out["severity"] = meta["severity"]
        if not out.get("confidence") and meta.get("confidence"):
            out["confidence"] = meta["confidence"]
        if not out.get("recommendation") and meta.get("remediation"):
            out["recommendation"] = meta["remediation"]
        if not out.get("suggested_fix") and meta.get("remediation"):
            out["suggested_fix"] = meta["remediation"]
        if meta.get("cwe"):
            out["cwe"] = meta["cwe"]
        if meta.get("owasp"):
            out["owasp"] = meta["owasp"]
        if meta.get("references"):
            out["references"] = meta["references"]
        if meta.get("remediation"):
            out["remediation"] = meta["remediation"]
        return out


# Module-level singleton for convenience
_registry: Optional[RuleRegistry] = None


def get_registry() -> RuleRegistry:
    """Return the global rule registry (lazy init)."""
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
    return _registry


def load_metadata() -> List[Dict[str, Any]]:
    """
    Load and return all rule metadata from rules/metadata/.
    Validates required fields; invalid entries are skipped.
    """
    return get_registry().get_all()


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich each finding with rule metadata. Returns new list."""
    reg = get_registry()
    return [reg.enrich_finding(f) for f in findings]
