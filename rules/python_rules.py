from __future__ import annotations

import re
from typing import Any, Dict, List


def get_rules() -> List[Dict[str, Any]]:
    # Non-Python fallback rules (to avoid duplicating AST detections).
    return [
        {
            "rule_id": "GEN001",
            "title": "Possible eval usage",
            "pattern": re.compile(r"""\beval\s*\("""),
            "severity": "HIGH",
            "confidence": "LOW",
            "category": "Code Injection",
            "description": "eval() may execute untrusted input.",
            "recommendation": "Avoid eval(). Use safe parsing or explicit logic.",
            "python_only": False,
            "non_python_only": True,
        },
        {
            "rule_id": "GEN002",
            "title": "Possible exec usage",
            "pattern": re.compile(r"""\bexec\s*\("""),
            "severity": "HIGH",
            "confidence": "LOW",
            "category": "Code Injection",
            "description": "exec() may execute untrusted input.",
            "recommendation": "Avoid exec(). Use safer explicit logic.",
            "python_only": False,
            "non_python_only": True,
        },
    ]
