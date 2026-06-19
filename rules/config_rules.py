from __future__ import annotations

import re
from typing import Any, Dict, List


def get_rules() -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": "SEC003",
            "title": "Flask debug mode enabled",
            "pattern": re.compile(r"""\bdebug\s*=\s*True\b"""),
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "category": "Insecure Configuration",
            "description": "Debug mode may expose sensitive information in production.",
            "recommendation": "Disable debug mode in production deployments.",
            "python_only": False,
        },
        {
            "rule_id": "SEC004",
            "title": "TLS certificate verification disabled",
            "pattern": re.compile(r"""\bverify\s*=\s*False\b"""),
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "TLS / SSL",
            "description": "Disabling certificate verification weakens transport security.",
            "recommendation": "Enable certificate verification and trust valid CA certificates.",
            "python_only": False,
        },
        {
            "rule_id": "SEC010",
            "title": "Insecure SSL/TLS protocol settings",
            "pattern": re.compile(
                r"""(?i)\b(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1|TLSv1)\b"""
            ),
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "category": "TLS / SSL",
            "description": "Older SSL/TLS protocol versions are insecure or deprecated.",
            "recommendation": "Use modern TLS defaults and avoid forcing legacy protocol versions.",
            "python_only": False,
        },
    ]
