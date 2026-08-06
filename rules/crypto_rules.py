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
            # Matches calls only. The rule previously also matched a bare
            # "import random", which fired on every file importing the module
            # for any reason - shuffling a list, picking a sample - and had
            # nothing to do with security. Importing it is not a finding; using
            # it to generate a value might be.
            "pattern": re.compile(
                r"""\brandom\.(randint|randrange|random|choice|sample|shuffle|uniform)\s*\("""
            ),
            "severity": "LOW",
            "confidence": "LOW",
            "category": "Cryptography",
            "description": "The `random` module is not suitable for security-sensitive randomness (tokens, secrets, keys). Harmless for simulations or sampling.",
            "recommendation": "For tokens, keys or anything security-sensitive use the `secrets` module, or `os.urandom` for raw bytes.",
            "python_only": True,
        },
    ]
