"""
Prompts and response schema for AI-assisted review.

Kept here rather than inlined at the call site so the wording can be reviewed
and revised as its own artefact. The schema below is passed to the provider's
structured-output mode, so the model returns parseable JSON instead of prose we
would have to scrape.

The instructions push hard against false positives. An advisory layer that
invents issues is worse than no advisory layer: it costs reviewer time and
undermines the deterministic findings sitting next to it.
"""

from __future__ import annotations

# Categories the model may use. Constrained so AI output groups alongside
# rule-based findings instead of inventing a parallel taxonomy.
ALLOWED_CATEGORIES = (
    "Code Injection",
    "Command Injection",
    "SQL Injection",
    "Path Traversal",
    "Unsafe Deserialization",
    "Cryptography",
    "Secrets",
    "Insecure Configuration",
    "Access Control",
    "Input Validation",
    "Information Disclosure",
    "Other",
)

ALLOWED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Passed to the provider as responseSchema. Types are upper-case, which is what
# the Gemini structured-output API expects.
RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "findings": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "title": {"type": "STRING"},
                    "severity": {"type": "STRING", "enum": list(ALLOWED_SEVERITIES)},
                    "category": {"type": "STRING", "enum": list(ALLOWED_CATEGORIES)},
                    "line_number": {"type": "INTEGER"},
                    "description": {"type": "STRING"},
                    "recommendation": {"type": "STRING"},
                    "cwe": {"type": "STRING"},
                    "reasoning": {"type": "STRING"},
                },
                "required": [
                    "title",
                    "severity",
                    "category",
                    "line_number",
                    "description",
                    "recommendation",
                ],
            },
        }
    },
    "required": ["findings"],
}


SECURITY_AUDIT_PROMPT = """You are a security engineer reviewing source code for exploitable vulnerabilities.

Analyse the file below and report only issues you can justify from the code shown.

Look for:
- Injection (command, SQL, code, template, LDAP)
- Path traversal and unrestricted file access
- Unsafe deserialization
- Hardcoded credentials and secret exposure
- Weak or misused cryptography
- Missing authentication or authorisation checks
- Insecure configuration and unsafe defaults
- Information disclosure through errors or logs

Rules you must follow:
1. Report a finding only when the code shown supports it. Do not speculate about
   code you cannot see.
2. Do not report style, performance, or maintainability issues. Security only.
3. Set line_number to the actual line the issue occurs on, using the numbers
   shown in the listing.
4. If the file appears to be a test, fixture, or example, say so in the
   reasoning and lower the severity accordingly.
5. Severity reflects exploitability and impact, not how unusual the pattern is.
6. In reasoning, state briefly why this is genuinely exploitable. If you cannot
   articulate that, omit the finding.
7. Returning an empty findings array is the correct answer for secure code, and
   is strongly preferred over a speculative one.

File: {filename}

Source:
{code}
"""


def build_review_prompt(filename: str, numbered_source: str) -> str:
    """Render the audit prompt for one file."""
    return SECURITY_AUDIT_PROMPT.format(filename=filename, code=numbered_source)
