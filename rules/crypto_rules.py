from __future__ import annotations

import re
from typing import Any, Dict, List


def get_rules() -> List[Dict[str, Any]]:
    return [
        {
            "rule_id": "SEC005",
            "title": "Possible insecure MD5 usage",
            "pattern": re.compile(r"""\bhashlib\.md5\s*\("""),
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "category": "Cryptography",
            "description": "MD5 is not suitable for security-sensitive cryptographic use.",
            "recommendation": "Use stronger algorithms such as SHA-256, or password hashing libraries where appropriate.",
            "python_only": False,
        },
        {
            "rule_id": "SEC006",
            "title": "Possible insecure SHA1 usage",
            "pattern": re.compile(r"""\bhashlib\.sha1\s*\("""),
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "category": "Cryptography",
            "description": "SHA-1 is deprecated for many security-sensitive use cases.",
            "recommendation": "Use SHA-256 or stronger modern cryptographic primitives.",
            "python_only": False,
        },
        {
            "rule_id": "SEC009",
            "title": "Insecure random for security-sensitive context",
            "pattern": re.compile(
                r"""(?i)\b(random\.(randint|randrange|random)\s*\(|\bimport\s+random\b)"""
            ),
            "severity": "LOW",
            "confidence": "LOW",
            "category": "Cryptography",
            "description": "The `random` module is not suitable for security-sensitive randomness (tokens, secrets, keys).",
            "recommendation": "Use the `secrets` module for tokens/keys, or `os.urandom` for raw bytes.",
            "python_only": True,
        },
    ]
