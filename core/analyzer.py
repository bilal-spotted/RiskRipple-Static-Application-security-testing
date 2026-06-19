from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.rules_engine import get_all_rules
from core.severity import SEVERITY_WEIGHTS, normalize_severity
from core.taint_analysis import analyze_file_taint

# 这些行更像规则定义/说明文字，不应被当成真实漏洞代码
METADATA_HINTS = (
    '"title"',
    "'title'",
    '"description"',
    "'description'",
    '"recommendation"',
    "'recommendation'",
    '"pattern"',
    "'pattern'",
    '"rule_id"',
    "'rule_id'",
    '"category"',
    "'category'",
    '"severity"',
    "'severity'",
    '"confidence"',
    "'confidence'",
)


# =========================
# Public API
# =========================
def analyze_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Analyze one file and return a list of findings.

    Output format is dict-based for compatibility with existing report generators.
    """
    path = Path(file_path)
    findings: List[Dict[str, Any]] = []

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    except OSError:
        return []

    lines = content.splitlines()
    suffix = path.suffix.lower()

    # 1) Python: AST-based detection for dangerous calls
    if suffix == ".py":
        findings.extend(_analyze_python_ast(path, content, lines))
        # 1b) Intra-procedural taint analysis
        findings.extend(analyze_file_taint(str(path), content, lines))

    # 2) Regex-based supplemental detection
    findings.extend(_analyze_with_regex(path, content, lines))

    # 3) 去重
    findings = _deduplicate_findings(findings)

    # 4) Sort: line number, then severity (high first), then rule_id
    findings.sort(
        key=lambda f: (
            f.get("line_number", 0),
            -SEVERITY_WEIGHTS.get(normalize_severity(f.get("severity")), 0),
            f.get("rule_id", ""),
        )
    )
    return findings


# =========================
# AST analysis
# =========================
class DangerousCallVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> Any:
        func_name = _get_call_name(node)

        # eval(...)
        if func_name == "eval":
            self._add_finding(
                node=node,
                rule_id="PY001",
                title="Use of eval()",
                severity="HIGH",
                confidence="HIGH",
                category="Code Injection",
                description="eval() executes dynamic Python code and may allow code injection.",
                recommendation="Avoid eval(). Use safe parsing, explicit logic, or restricted parsing libraries.",
            )

        # exec(...)
        elif func_name == "exec":
            self._add_finding(
                node=node,
                rule_id="PY002",
                title="Use of exec()",
                severity="HIGH",
                confidence="HIGH",
                category="Code Injection",
                description="exec() executes dynamic Python code and can introduce severe security risk.",
                recommendation="Avoid exec(). Replace it with explicit logic or safer alternatives.",
            )

        # compile(...) with untrusted input can lead to code execution
        elif func_name == "compile":
            self._add_finding(
                node=node,
                rule_id="PY007",
                title="Use of compile()",
                severity="HIGH",
                confidence="MEDIUM",
                category="Code Injection",
                description="compile() builds code objects from strings; with untrusted input it can enable code execution (e.g. via exec()).",
                recommendation="Avoid compiling untrusted input. Use safe parsing or restricted modes; prefer structured data over code strings.",
            )

        # os.system(...)
        elif func_name == "os.system":
            self._add_finding(
                node=node,
                rule_id="PY003",
                title="Use of os.system()",
                severity="HIGH",
                confidence="HIGH",
                category="Command Injection",
                description="os.system() may lead to command injection if arguments include untrusted input.",
                recommendation="Use subprocess.run() with a list of arguments and avoid shell interpretation.",
            )

        # subprocess.run / Popen / call with shell=True
        elif func_name in {"subprocess.run", "subprocess.Popen", "subprocess.call"}:
            shell_true = _call_has_keyword_true(node, "shell")
            if shell_true:
                self._add_finding(
                    node=node,
                    rule_id="PY004",
                    title=f"Use of {func_name}() with shell=True",
                    severity="HIGH",
                    confidence="HIGH",
                    category="Command Injection",
                    description="shell=True increases command injection risk when command content is not fully trusted.",
                    recommendation="Avoid shell=True. Pass command arguments as a list instead.",
                )

        # pickle.load / pickle.loads
        elif func_name in {"pickle.load", "pickle.loads"}:
            self._add_finding(
                node=node,
                rule_id="PY005",
                title=f"Use of {func_name}()",
                severity="HIGH",
                confidence="HIGH",
                category="Unsafe Deserialization",
                description="pickle deserialization may execute arbitrary code when loading untrusted data.",
                recommendation="Do not deserialize untrusted pickle data. Use safer formats such as JSON where possible.",
            )

        # yaml.load(...)
        elif func_name == "yaml.load":
            self._add_finding(
                node=node,
                rule_id="PY006",
                title="Use of yaml.load()",
                severity="HIGH",
                confidence="HIGH",
                category="Unsafe Deserialization",
                description="yaml.load() may be unsafe when parsing untrusted YAML content.",
                recommendation="Prefer yaml.safe_load() for untrusted input.",
            )

        self.generic_visit(node)

    def _add_finding(
        self,
        node: ast.AST,
        rule_id: str,
        title: str,
        severity: str,
        confidence: str,
        category: str,
        description: str,
        recommendation: str,
    ) -> None:
        line_number = getattr(node, "lineno", 0)
        snippet = _build_snippet(self.lines, line_number)

        self.findings.append(
            _make_finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                confidence=confidence,
                category=category,
                file_path=self.file_path,
                line_number=line_number,
                code_snippet=snippet,
                description=description,
                recommendation=recommendation,
            )
        )


def _analyze_python_ast(path: Path, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    visitor = DangerousCallVisitor(str(path), lines)
    visitor.visit(tree)
    return visitor.findings


# =========================
# Regex analysis
# =========================
def _analyze_with_regex(path: Path, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    is_python = path.suffix.lower() == ".py"

    comment_only_lines = _get_python_comment_only_lines(content) if is_python else set()

    rules = get_all_rules()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped:
            continue

        # Python 注释行直接忽略
        if line_number in comment_only_lines:
            continue

        # 明显是规则说明元数据时，不要报危险函数类误报
        if _looks_like_metadata_line(line):
            continue

        for rule in rules:
            if rule.get("non_python_only") and is_python:
                continue
            if rule.get("python_only") and not is_python:
                continue

            if rule["pattern"].search(line):
                findings.append(
                    _make_finding(
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        category=rule["category"],
                        file_path=str(path),
                        line_number=line_number,
                        code_snippet=_build_snippet(lines, line_number),
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                    )
                )

    return findings


# =========================
# Helpers
# =========================
def _make_finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    category: str,
    file_path: str,
    line_number: int,
    code_snippet: str,
    description: str,
    recommendation: str,
) -> Dict[str, Any]:
    """
    返回兼容性更好的 finding dict。
    保留多组常见字段名，尽量适配现有 report / html / json 模块。
    """
    one_line_code = _extract_main_line_from_snippet(code_snippet, line_number)

    return {
        "rule_id": rule_id,
        "title": title,
        "type": title,  # 兼容旧字段
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "file_path": file_path,
        "file": file_path,  # 兼容旧字段
        "line_number": line_number,
        "line": line_number,  # 兼容旧字段
        "code_snippet": code_snippet,
        "snippet": code_snippet,  # 兼容旧字段
        "code": one_line_code,  # 兼容旧字段
        "description": description,
        "recommendation": recommendation,
        "suggested_fix": recommendation,  # 兼容旧字段
    }


def _get_call_name(node: ast.Call) -> Optional[str]:
    func = node.func

    if isinstance(func, ast.Name):
        return func.id

    if isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))

    return None


def _call_has_keyword_true(node: ast.Call, keyword_name: str) -> bool:
    for kw in node.keywords:
        if kw.arg == keyword_name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _build_snippet(lines: List[str], line_number: int, context: int = 1) -> str:
    """
    返回上下文 snippet，包含前后各 1 行，便于报告展示。
    """
    if not lines or line_number <= 0:
        return ""

    start = max(1, line_number - context)
    end = min(len(lines), line_number + context)

    snippet_lines = []
    for ln in range(start, end + 1):
        prefix = ">>" if ln == line_number else "  "
        snippet_lines.append(f"{prefix} {ln:>4}: {lines[ln - 1]}")
    return "\n".join(snippet_lines)


def _extract_main_line_from_snippet(snippet: str, line_number: int) -> str:
    target = f">> {line_number:>4}:"
    for line in snippet.splitlines():
        if line.startswith(target):
            return line.split(":", 1)[1].strip()
    return ""


def _looks_like_metadata_line(line: str) -> bool:
    """
    过滤明显不是可执行代码、而是规则说明/报告元数据的文本行。
    重点解决：
    "title": "Use of eval()"
    "recommendation": "Avoid exec()"
    这类误报
    """
    lowered = line.lower()
    if any(hint.lower() in lowered for hint in METADATA_HINTS):
        return True

    # 规则定义中常见的纯说明性键值
    if re.search(r"""^\s*["']?[a-zA-Z_]+["']?\s*:\s*["'].*["']\s*,?\s*$""", line):
        return True

    return False


def _get_python_comment_only_lines(content: str) -> set:
    """
    找出 Python 中纯注释行，便于 regex 阶段忽略。
    """
    comment_lines = set()

    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                line_no = tok.start[0]
                line_text = content.splitlines()[line_no - 1].strip()
                if line_text.startswith("#"):
                    comment_lines.add(line_no)
    except (tokenize.TokenError, IndentationError):
        return set()

    return comment_lines


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []

    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("file_path"),
            finding.get("line_number"),
            finding.get("title"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique
