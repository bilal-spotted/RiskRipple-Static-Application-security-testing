from __future__ import annotations

import re
from typing import Any, Dict, List


def get_rules() -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": "SEC001",
            "title": "Potential hardcoded password",
            "pattern": re.compile(r"""(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{4,}['"]"""),
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "category": "Secrets",
            "description": "Possible hardcoded password detected.",
            "recommendation": "Move secrets to environment variables or a secure secrets manager.",
            "python_only": False,
        },
        {
            "rule_id": "SEC002",
            "title": "Potential hardcoded API key / token / secret",
            "pattern": re.compile(
                r"""(?i)\b(api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*['"][A-Za-z0-9_\-\/+=.]{8,}['"]"""
            ),
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "category": "Secrets",
            "description": "Possible hardcoded credential or token detected.",
            "recommendation": "Store credentials outside source code and inject them securely at runtime.",
            "python_only": False,
        },
        {
            "rule_id": "SEC007",
            "title": "Potential hardcoded bearer token",
            "pattern": re.compile(
                r"""(?i)\bauthorization\b\s*[:=]\s*['"]bearer\s+[A-Za-z0-9\-._~+/]+=*['"]"""
            ),
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "category": "Secrets",
            "description": "Possible hardcoded bearer token detected.",
            "recommendation": "Remove tokens from source code and load them securely (env vars / secrets manager).",
            "python_only": False,
        },
        {
            "rule_id": "SEC008",
            "title": "Potential private key material",
            "pattern": re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""),
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Secrets",
            "description": "Private key material appears to be present in source code.",
            "recommendation": "Remove the key from the repository and rotate/revoke the affected credentials.",
            "python_only": False,
        },
    ]
