"""
Intra-procedural taint analysis for Python.

Tracks flows: source -> assignment/concatenation -> sink.
Supports sanitizers to lower severity when tainted data is sanitized before reaching a sink.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Source patterns: call names or (module, attr) that introduce tainted data
# ---------------------------------------------------------------------------
SOURCE_CALL_NAMES = frozenset(
    {
        "input",
    }
)
# Attribute-style: "request.args", "request.form", "sys.argv", "os.environ", etc.
SOURCE_ATTR_PATTERNS = frozenset(
    {
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.data",
        "request.get_json",
        "sys.argv",
        "os.environ",
    }
)
# Call-style: request.args.get('x'), request.form.get('y')
SOURCE_REQUEST_GET = frozenset(
    {
        "request.args.get",
        "request.form.get",
        "request.values.get",
    }
)

# ---------------------------------------------------------------------------
# Sink patterns: (call_name, arg_index_for_tainted_arg, category, severity, message_key)
# ---------------------------------------------------------------------------
SINKS: List[Tuple[str, int, str, str, str]] = [
    ("os.system", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.run", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.Popen", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.call", 0, "Command Injection", "HIGH", "command"),
    ("cursor.execute", 0, "SQL Injection", "HIGH", "sql"),
    ("open", 0, "Path Traversal", "MEDIUM", "path"),
    ("file", 0, "Path Traversal", "MEDIUM", "path"),
]
# Any .execute(...) on a variable (conn.execute, db.execute) - match by attr only for first arg
SINK_EXECUTE_ATTR = "execute"

# Subprocess with shell=True: check keyword; arg index 0 is the command
SINKS_SHELL_TRUE = frozenset({"subprocess.run", "subprocess.Popen", "subprocess.call"})

# ---------------------------------------------------------------------------
# Sanitizers: if tainted data passes through these, lower severity or suppress
# ---------------------------------------------------------------------------
SANITIZER_CALL_NAMES = frozenset(
    {
        "shlex.quote",
        "markupsafe.escape",
        "werkzeug.escape",
        "html.escape",
    }
)

_AST_LITERAL_NODES = [ast.Constant]
if hasattr(ast, "Num"):
    _AST_LITERAL_NODES.append(ast.Num)
if hasattr(ast, "Str"):
    _AST_LITERAL_NODES.append(ast.Str)
AST_LITERAL_NODES = tuple(_AST_LITERAL_NODES)


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Return qualified name for a call, e.g. 'os.system', 'request.args.get'."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        current: ast.expr = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _get_attr_pattern(node: ast.expr) -> Optional[str]:
    """Return 'module.attr' for Attribute(Value(Name), attr), else None."""
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node.value, ast.Attribute):
            inner = _get_attr_pattern(node.value)
            if inner:
                return f"{inner}.{node.attr}"
    return None


def _names_in_expr(node: ast.expr) -> Set[str]:
    """Collect all Name ids used in an expression (for taint check)."""
    out: Set[str] = set()

    def visit(n: ast.AST) -> None:
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Call):
            for arg in n.args:
                visit(arg)
            for kw in n.keywords:
                visit(kw.value)
        elif isinstance(n, ast.BinOp):
            visit(n.left)
            visit(n.right)
        elif isinstance(n, ast.JoinedStr):
            for v in n.values:
                if isinstance(v, ast.FormattedValue):
                    visit(v.value)
                elif isinstance(v, ast.Constant):
                    pass
        elif isinstance(n, ast.Subscript):
            visit(n.value)
            if isinstance(n.slice, ast.Constant):
                pass
            elif hasattr(n.slice, "value"):
                visit(getattr(n.slice, "value"))
        elif isinstance(n, ast.Attribute):
            visit(n.value)
        elif isinstance(n, ast.UnaryOp):
            visit(n.operand)
        elif isinstance(n, AST_LITERAL_NODES):
            pass
        else:
            for child in ast.iter_child_nodes(n):
                visit(child)

    visit(node)
    return out


def _assign_target_names(node: ast.Assign) -> List[str]:
    """Return list of variable names assigned to (single name or tuple of names)."""
    names: List[str] = []

    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
    return names


def _is_source_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in SOURCE_CALL_NAMES
    name = _get_call_name(node)
    if not name:
        return False
    if name in SOURCE_CALL_NAMES or name in SOURCE_REQUEST_GET:
        return True
    if name.startswith("request.") or name.startswith("flask.request."):
        return True
    return False


def _is_source_subscript(node: ast.Subscript) -> bool:
    """request.args['x'], request.form['name'], etc."""
    pattern = _get_attr_pattern(node.value)
    if pattern:
        for p in SOURCE_ATTR_PATTERNS:
            if pattern == p or pattern.startswith(p + "."):
                return True
    return False


def _is_sanitizer_call(node: ast.Call) -> bool:
    name = _get_call_name(node)
    return name in SANITIZER_CALL_NAMES if name else False


def _call_has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


class _TaintVisitor(ast.NodeVisitor):
    """Per-function taint state and statement processing."""

    def __init__(self, file_path: str, lines: List[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Dict[str, Any]] = []
        self._tainted: Set[str] = set()
        self._sanitized: Set[str] = set()

    def _snippet(self, line_no: int, context: int = 1) -> str:
        if not self.lines or line_no <= 0:
            return ""
        start = max(0, line_no - 1 - context)
        end = min(len(self.lines), line_no - 1 + context + 1)
        out = []
        for i in range(start, end):
            prefix = ">>" if i == line_no - 1 else "  "
            out.append(f"{prefix} {i + 1:>4}: {self.lines[i]}")
        return "\n".join(out)

    def _add_finding(
        self,
        line_no: int,
        source_desc: str,
        sink_desc: str,
        category: str,
        severity: str,
        message_key: str,
        sanitized: bool,
    ) -> None:
        if sanitized:
            severity = "LOW"
        rule_id = "TAINT001"
        if "command" in message_key:
            rule_id = "TAINT-CMD"
        elif "sql" in message_key:
            rule_id = "TAINT-SQL"
        elif "path" in message_key:
            rule_id = "TAINT-PATH"
        msg = f"Tainted data from {source_desc} flows into {sink_desc}, which may allow {message_key} injection."
        if sanitized:
            msg = f"Tainted data (sanitized) from {source_desc} reaches {sink_desc}. Verify sanitization is sufficient."
        self.findings.append(
            {
                "rule_id": rule_id,
                "title": f"Taint flow: {source_desc} -> {sink_desc}",
                "type": f"Taint flow: {source_desc} -> {sink_desc}",
                "severity": severity,
                "confidence": "MEDIUM",
                "category": category,
                "file_path": self.file_path,
                "file": self.file_path,
                "line_number": line_no,
                "line": line_no,
                "code_snippet": self._snippet(line_no),
                "snippet": self._snippet(line_no),
                "code": self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else "",
                "description": msg,
                "recommendation": "Validate and sanitize user input; use parameterized queries for SQL; avoid shell=True.",
                "suggested_fix": "Validate and sanitize user input; use parameterized queries for SQL; avoid shell=True.",
                "source": source_desc,
                "sink": sink_desc,
                "explanation": msg,
                "taint_flow": True,
            }
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._tainted = set()
        self._sanitized = set()
        for stmt in node.body:
            self._visit_stmt(stmt)
        self.generic_visit(node)

    def _visit_stmt(self, node: ast.AST) -> None:
        if isinstance(node, ast.Assign):
            self._visit_assign(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            self._visit_sink_call(node.value, node.value.lineno)
        elif isinstance(node, ast.AugAssign):
            self._visit_aug_assign(node)
        elif isinstance(node, ast.If):
            for s in node.body:
                self._visit_stmt(s)
            for s in node.orelse:
                self._visit_stmt(s)
        elif isinstance(node, (ast.For, ast.While)):
            for s in node.body:
                self._visit_stmt(s)
            for s in node.orelse:
                self._visit_stmt(s)
        elif isinstance(node, ast.With):
            for s in node.body:
                self._visit_stmt(s)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.AST):
                    self._visit_stmt(child)

    def _visit_assign(self, node: ast.Assign) -> None:
        targets = _assign_target_names(node)
        if not targets:
            return
        value = node.value

        # Source: a = input(), a = request.args['x']
        if isinstance(value, ast.Call) and _is_source_call(value):
            for t in targets:
                self._tainted.add(t)
                self._sanitized.discard(t)
            return
        if isinstance(value, ast.Subscript) and _is_source_subscript(value):
            for t in targets:
                self._tainted.add(t)
                self._sanitized.discard(t)
            return

        # Sanitizer: a = shlex.quote(b)
        if isinstance(value, ast.Call) and _is_sanitizer_call(value):
            if value.args and _names_in_expr(value.args[0]) & self._tainted:
                for t in targets:
                    self._sanitized.add(t)
                    # Still consider it tainted but sanitized (so we report LOW at sink)
                    self._tainted.add(t)
            return

        # Propagation: a = b, a = "x" + b, a = f"{b}"
        names_in_val = _names_in_expr(value)
        if names_in_val & self._tainted:
            for t in targets:
                self._tainted.add(t)
            if names_in_val & self._sanitized:
                for t in targets:
                    self._sanitized.add(t)
            return

        # Unassign: if RHS has no tainted, targets become untainted (overwrite)
        for t in targets:
            self._tainted.discard(t)
            self._sanitized.discard(t)

    def _visit_aug_assign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            names_in_val = _names_in_expr(node.value)
            if node.target.id in self._tainted or names_in_val & self._tainted:
                self._tainted.add(node.target.id)
            if node.target.id in self._sanitized or names_in_val & self._sanitized:
                self._sanitized.add(node.target.id)

    def _visit_sink_call(self, node: ast.Call, line_no: int) -> None:
        name = _get_call_name(node)
        if not name:
            return

        # subprocess with shell=True: only consider first arg as sink when shell=True
        if name in SINKS_SHELL_TRUE and not _call_has_shell_true(node):
            return

        arg_index = 0
        category, severity, message_key = "Taint Analysis", "HIGH", "sink"
        for sink_name, idx, cat, sev, key in SINKS:
            if name == sink_name:
                arg_index = idx
                category, severity, message_key = cat, sev, key
                break
        else:
            # cursor.execute / conn.execute etc.
            if isinstance(node.func, ast.Attribute) and node.func.attr == SINK_EXECUTE_ATTR:
                arg_index = 0
                category, severity, message_key = "SQL Injection", "HIGH", "sql"
            else:
                return

        if arg_index >= len(node.args):
            return
        arg = node.args[arg_index]
        names = _names_in_expr(arg)
        tainted_reach = names & self._tainted
        if not tainted_reach:
            return
        sanitized_reach = names & self._sanitized
        source_desc = "user input"
        sink_desc = name
        self._add_finding(
            line_no,
            source_desc,
            sink_desc,
            category,
            severity,
            message_key,
            sanitized=bool(sanitized_reach),
        )


def analyze_file_taint(file_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    """
    Run intra-procedural taint analysis on a Python file.

    Returns list of finding dicts compatible with the main report format.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = _TaintVisitor(file_path, lines)
    visitor.visit(tree)
    return visitor.findings


def get_taint_rule_metadata() -> List[Dict[str, Any]]:
    """Rule metadata for SARIF and reporting."""
    return [
        {
            "rule_id": "TAINT-CMD",
            "title": "Taint flow to command execution",
            "severity": "HIGH",
            "category": "Command Injection",
            "description": "Tainted user input flows into shell/process execution.",
            "recommendation": "Use allowlists and avoid shell=True; prefer subprocess with list args.",
        },
        {
            "rule_id": "TAINT-SQL",
            "title": "Taint flow to SQL execution",
            "severity": "HIGH",
            "category": "SQL Injection",
            "description": "Tainted user input flows into SQL execution.",
            "recommendation": "Use parameterized queries.",
        },
        {
            "rule_id": "TAINT-PATH",
            "title": "Taint flow to file path",
            "severity": "MEDIUM",
            "category": "Path Traversal",
            "description": "Tainted user input flows into file open path.",
            "recommendation": "Validate and sanitize paths; avoid user-controlled paths.",
        },
        {
            "rule_id": "TAINT001",
            "title": "Taint flow to dangerous sink",
            "severity": "HIGH",
            "category": "Taint Analysis",
            "description": "Tainted data reaches a dangerous sink.",
            "recommendation": "Validate and sanitize user input.",
        },
    ]
