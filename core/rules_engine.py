from __future__ import annotations

from typing import Any, Dict, List

from rules import config_rules, crypto_rules, python_rules, secrets_rules

RULE_MODULES = [
    python_rules,
    secrets_rules,
    crypto_rules,
    config_rules,
]


def get_all_rules() -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for module in RULE_MODULES:
        module_rules = module.get_rules()
        rules.extend(module_rules)
    return rules


def get_all_regex_rules() -> List[Dict[str, Any]]:
    """
    Regex rules used by the analyzer for line-based scanning.
    Kept as plain dicts for readability and compatibility.
    """
    return get_all_rules()


def get_python_ast_rule_metadata() -> List[Dict[str, Any]]:
    """
    Metadata for AST-based rules.
    The analyzer performs the AST matching; this provides rule info for SARIF/reporting.
    """
    return [
        {
            "rule_id": "PY001",
            "title": "Use of eval()",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Code Injection",
            "description": "eval() executes dynamic Python code and may allow code injection.",
            "recommendation": "Avoid eval(). Use safe parsing, explicit logic, or restricted parsing libraries.",
        },
        {
            "rule_id": "PY002",
            "title": "Use of exec()",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Code Injection",
            "description": "exec() executes dynamic Python code and can introduce severe security risk.",
            "recommendation": "Avoid exec(). Replace it with explicit logic or safer alternatives.",
        },
        {
            "rule_id": "PY003",
            "title": "Use of os.system()",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Command Injection",
            "description": "os.system() may lead to command injection if arguments include untrusted input.",
            "recommendation": "Use subprocess.run() with a list of arguments and avoid shell interpretation.",
        },
        {
            "rule_id": "PY004",
            "title": "Subprocess with shell=True",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Command Injection",
            "description": "shell=True increases command injection risk when command content is not fully trusted.",
            "recommendation": "Avoid shell=True. Pass command arguments as a list instead.",
        },
        {
            "rule_id": "PY005",
            "title": "Unsafe pickle deserialization",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Unsafe Deserialization",
            "description": "pickle deserialization may execute arbitrary code when loading untrusted data.",
            "recommendation": "Do not deserialize untrusted pickle data. Use safer formats such as JSON where possible.",
        },
        {
            "rule_id": "PY006",
            "title": "Use of yaml.load()",
            "severity": "HIGH",
            "confidence": "HIGH",
            "category": "Unsafe Deserialization",
            "description": "yaml.load() may be unsafe when parsing untrusted YAML content.",
            "recommendation": "Prefer yaml.safe_load() for untrusted input.",
        },
        {
            "rule_id": "PY007",
            "title": "Use of compile()",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "category": "Code Injection",
            "description": "compile() builds code objects from strings; with untrusted input it can enable code execution.",
            "recommendation": "Avoid compiling untrusted input. Use safe parsing or restricted modes.",
        },
    ]


def group_rules_by_category() -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for rule in get_all_rules():
        category = str(rule.get("category", "General"))
        grouped.setdefault(category, []).append(rule)
    return grouped
