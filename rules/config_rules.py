from __future__ import annotations

import re
from typing import Any, Dict, List


def get_rules() -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": "SEC003",
            "title": "Debug mode enabled",
            # Anchored to a run() call or an upper-case config constant. The
            # rule previously matched any "debug=True" anywhere, including a
            # local variable named debug in unrelated code.
            "pattern": re.compile(
                r"""(?:\.run\s*\([^)]*\bdebug\s*=\s*True\b)|(?:^\s*DEBUG\s*=\s*True\b)""",
                re.MULTILINE,
            ),
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "category": "Insecure Configuration",
            "description": "Debug mode exposes stack traces and, in Flask, an interactive console that permits code execution.",
            "recommendation": "Disable debug mode in production. Drive it from an environment variable rather than a literal.",
            "python_only": False,
        },
        {
            "rule_id": "SEC004",
            "title": "TLS certificate verification disabled",
            "pattern": re.compile(r"""\bverify\s*=\s*False\b"""),
            "severity": "HIGH",
            # A single line cannot prove this is a TLS call rather than some
            # other parameter named verify, so the finding is reported at
            # reduced confidence rather than asserted.
            "confidence": "MEDIUM",
            "category": "TLS / SSL",
            "description": "Disabling certificate verification removes protection against man-in-the-middle attacks.",
            "recommendation": "Leave verification enabled and trust a valid CA bundle. For internal certificates, pass the CA path instead of disabling checks.",
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
