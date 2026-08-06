"""
Intra-procedural taint analysis for Python.

Tracks the flow of untrusted data from a *source* to a security-sensitive
*sink* within a single function body. Each function is analysed in isolation:
no call graph is constructed and no data is tracked across function
boundaries. This limitation is deliberate and is reported in all output.

Sources fall into two classes:

* **Direct** - expressions that are untrusted by definition: ``input()``,
  ``request.*``, ``sys.argv``, ``os.environ``.
* **Parameter** - function parameters. A parameter *may* carry untrusted data,
  but because callers are outside the analysis scope we cannot prove it does.

That distinction is recorded as **confidence**, not severity. A SQL injection
is equally severe wherever the string originated; what differs is how certain
we are that an attacker controls it. Severity therefore comes from the sink,
and confidence from the source.

Two mechanisms reduce false positives:

* **Sanitizers** (e.g. ``shlex.quote``) downgrade a finding to LOW rather than
  suppressing it, keeping the flow visible for review.
* **Validators** remove taint entirely. These are constructs that genuinely
  neutralise the threat, such as ``secure_filename`` or a path-containment
  guard. Note that ``os.path.normpath`` is *not* a validator: normalising
  ``/data/../etc/passwd`` yields ``/etc/passwd``, so it resolves traversal
  rather than preventing it. Only an explicit containment check does that.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

SOURCE_DIRECT = "direct"
SOURCE_PARAMETER = "parameter"

# Confidence reported for a finding, by the class of source that fed it.
_CONFIDENCE_BY_SOURCE = {
    SOURCE_DIRECT: "HIGH",
    SOURCE_PARAMETER: "MEDIUM",
}

# Ranking used when several tainted values combine: the strongest wins.
_SOURCE_RANK = {SOURCE_PARAMETER: 1, SOURCE_DIRECT: 2}


class TaintSource(NamedTuple):
    """Provenance of a tainted value: how it entered, and under what name."""

    kind: str
    origin: str

    def describe(self) -> str:
        if self.kind == SOURCE_PARAMETER:
            return f"function parameter '{self.origin}'"
        return "user input"


# Call names that introduce untrusted data
SOURCE_CALL_NAMES = frozenset({"input"})

# Attribute-style: "request.args", "sys.argv", "os.environ", etc.
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

# Parameter names that are never untrusted input
IMPLICIT_PARAMETERS = frozenset({"self", "cls"})

# ---------------------------------------------------------------------------
# Sinks: (call_name, tainted_arg_index, category, severity, message_key)
# ---------------------------------------------------------------------------

SINKS: List[Tuple[str, int, str, str, str]] = [
    ("os.system", 0, "Command Injection", "HIGH", "command"),
    ("os.popen", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.run", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.Popen", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.call", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.check_call", 0, "Command Injection", "HIGH", "command"),
    ("subprocess.check_output", 0, "Command Injection", "HIGH", "command"),
    ("cursor.execute", 0, "SQL Injection", "HIGH", "sql"),
    ("open", 0, "Path Traversal", "MEDIUM", "path"),
]

# Any .execute(...) on an object (conn.execute, db.execute): matched by attribute
SINK_EXECUTE_ATTR = "execute"

# Subprocess calls are only shell-injection sinks when shell=True
SINKS_SHELL_TRUE = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)

# ---------------------------------------------------------------------------
# Sanitizers and validators
# ---------------------------------------------------------------------------

# Reduce severity to LOW but keep the finding visible for review.
SANITIZER_CALL_NAMES = frozenset(
    {
        "shlex.quote",
        "markupsafe.escape",
        "werkzeug.escape",
        "html.escape",
    }
)

# Remove taint entirely: these genuinely neutralise the threat by discarding
# any attacker-controlled directory component.
VALIDATOR_CALL_NAMES = frozenset(
    {
        "secure_filename",
        "werkzeug.utils.secure_filename",
        "os.path.basename",
    }
)

# Methods and functions that assert a path stays inside a known base directory.
CONTAINMENT_CHECKS = frozenset({"startswith", "is_relative_to"})
CONTAINMENT_FUNCTIONS = frozenset({"os.path.commonpath", "os.path.commonprefix"})

_AST_LITERAL_NODES: List[Any] = [ast.Constant]
if hasattr(ast, "Num"):  # pragma: no cover - removed in newer Python
    _AST_LITERAL_NODES.append(ast.Num)
if hasattr(ast, "Str"):  # pragma: no cover - removed in newer Python
    _AST_LITERAL_NODES.append(ast.Str)
AST_LITERAL_NODES = tuple(_AST_LITERAL_NODES)

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPE_BOUNDARY_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _get_call_name(node: ast.Call) -> Optional[str]:
    """Return the qualified name of a call, e.g. 'os.system', 'request.args.get'."""
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
    """Return 'module.attr' for a dotted attribute chain, else None."""
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node.value, ast.Attribute):
            inner = _get_attr_pattern(node.value)
            if inner:
                return f"{inner}.{node.attr}"
    return None


def _names_in_expr(node: Optional[ast.expr]) -> Set[str]:
    """Collect every variable name referenced in an expression."""
    out: Set[str] = set()
    if node is None:
        return out

    def visit(n: ast.AST) -> None:
        if isinstance(n, _SCOPE_BOUNDARY_NODES):
            return
        if isinstance(n, ast.Name):
            out.add(n.id)
            return
        if isinstance(n, AST_LITERAL_NODES):
            return
        for child in ast.iter_child_nodes(n):
            visit(child)

    visit(node)
    return out


def _iter_calls(node: Optional[ast.AST]) -> Iterator[ast.Call]:
    """
    Yield every Call in an expression, including nested ones.

    Nested function and lambda bodies are skipped: they form their own taint
    scope and are analysed separately.
    """
    if node is None:
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_BOUNDARY_NODES):
            continue
        yield from _iter_calls(child)


def _parameter_names(node: ast.AST) -> List[str]:
    """Return every parameter name of a function definition, minus self/cls."""
    args = getattr(node, "args", None)
    if args is None:
        return []
    collected: List[str] = []
    for group in ("posonlyargs", "args", "kwonlyargs"):
        for arg in getattr(args, group, []) or []:
            collected.append(arg.arg)
    for solo in (getattr(args, "vararg", None), getattr(args, "kwarg", None)):
        if solo is not None:
            collected.append(solo.arg)
    return [name for name in collected if name not in IMPLICIT_PARAMETERS]


def _is_source_call(node: ast.Call) -> bool:
    """True if this call returns untrusted data by definition."""
    if isinstance(node.func, ast.Name):
        return node.func.id in SOURCE_CALL_NAMES
    name = _get_call_name(node)
    if not name:
        return False
    if name in SOURCE_CALL_NAMES or name in SOURCE_REQUEST_GET:
        return True
    return name.startswith("request.") or name.startswith("flask.request.")


def _is_source_subscript(node: ast.Subscript) -> bool:
    """True for request.args['x'], request.form['name'], and similar."""
    pattern = _get_attr_pattern(node.value)
    if not pattern:
        return False
    return any(pattern == p or pattern.startswith(p + ".") for p in SOURCE_ATTR_PATTERNS)


def _is_sanitizer_call(node: ast.Call) -> bool:
    name = _get_call_name(node)
    return name in SANITIZER_CALL_NAMES if name else False


def _is_validator_call(node: ast.Call) -> bool:
    name = _get_call_name(node)
    if not name:
        return False
    return name in VALIDATOR_CALL_NAMES or name.split(".")[-1] == "secure_filename"


def _call_has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _contains_direct_source(node: Optional[ast.expr]) -> bool:
    """True if an expression embeds an untrusted-input call or subscript."""
    if node is None:
        return False
    if isinstance(node, ast.Call) and _is_source_call(node):
        return True
    if isinstance(node, ast.Subscript) and _is_source_subscript(node):
        return True
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_BOUNDARY_NODES):
            continue
        if isinstance(child, ast.expr) and _contains_direct_source(child):
            return True
    return False


def _body_bails_out(body: List[ast.stmt]) -> bool:
    """True if a branch terminates the flow via return, raise, continue or break."""
    return any(isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)) for stmt in body)


# ---------------------------------------------------------------------------
# Taint visitor
# ---------------------------------------------------------------------------


class _TaintVisitor:
    """Analyses one function body at a time, holding per-function taint state."""

    def __init__(self, file_path: str, lines: List[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: List[Dict[str, Any]] = []
        self._tainted: Dict[str, TaintSource] = {}
        self._sanitized: Set[str] = set()
        self._reported: Set[Tuple[int, str]] = set()

    # -- public entry point -------------------------------------------------

    def analyze_function(self, node: ast.AST) -> None:
        """Analyse a single function body with a fresh taint scope."""
        self._tainted = {
            name: TaintSource(SOURCE_PARAMETER, name) for name in _parameter_names(node)
        }
        self._sanitized = set()
        self._visit_body(getattr(node, "body", []))

    # -- taint state --------------------------------------------------------

    def _expr_taint(self, node: Optional[ast.expr]) -> Optional[TaintSource]:
        """Return the strongest taint reaching an expression, or None if clean."""
        if node is None:
            return None
        if _contains_direct_source(node):
            return TaintSource(SOURCE_DIRECT, "user input")
        best: Optional[TaintSource] = None
        for name in _names_in_expr(node):
            source = self._tainted.get(name)
            if source is None:
                continue
            if best is None or _SOURCE_RANK[source.kind] > _SOURCE_RANK[best.kind]:
                best = source
        return best

    def _expr_is_sanitized(self, node: Optional[ast.expr]) -> bool:
        return bool(_names_in_expr(node) & self._sanitized)

    def _assign_taint(self, targets: List[str], source: Optional[TaintSource]) -> None:
        for target in targets:
            if source is None:
                self._tainted.pop(target, None)
                self._sanitized.discard(target)
            else:
                self._tainted[target] = source

    # -- statement dispatch -------------------------------------------------

    def _visit_body(self, body: List[ast.stmt]) -> None:
        for stmt in body:
            self._visit_stmt(stmt)

    def _visit_stmt(self, node: ast.stmt) -> None:
        # Nested definitions form their own scope and are analysed separately.
        if isinstance(node, _SCOPE_BOUNDARY_NODES):
            return

        if isinstance(node, ast.Assign):
            self._check_sinks(node.value)
            self._visit_assign(node.targets, node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._check_sinks(node.value)
                self._visit_assign([node.target], node.value)
        elif isinstance(node, ast.AugAssign):
            self._check_sinks(node.value)
            self._visit_aug_assign(node)
        elif isinstance(node, ast.Expr):
            self._check_sinks(node.value)
        elif isinstance(node, ast.Return):
            self._check_sinks(node.value)
        elif isinstance(node, ast.If):
            self._visit_if(node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._check_sinks(node.iter)
            self._visit_assign([node.target], node.iter)
            self._visit_body(node.body)
            self._visit_body(node.orelse)
        elif isinstance(node, ast.While):
            self._check_sinks(node.test)
            self._visit_body(node.body)
            self._visit_body(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._check_sinks(item.context_expr)
                if item.optional_vars is not None:
                    self._visit_assign([item.optional_vars], item.context_expr)
            self._visit_body(node.body)
        elif isinstance(node, ast.Try):
            self._visit_body(node.body)
            for handler in node.handlers:
                self._visit_body(handler.body)
            self._visit_body(node.orelse)
            self._visit_body(node.finalbody)
        elif isinstance(node, ast.Raise):
            self._check_sinks(node.exc)
        elif isinstance(node, ast.Assert):
            self._check_sinks(node.test)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._check_sinks(child)

    def _visit_if(self, node: ast.If) -> None:
        """
        Handle an if-statement, recognising path-containment guards.

        Two defensive shapes are understood::

            if not path.startswith(base):   # guard clause
                return None
            open(path)                      # validated from here on

            if path.startswith(base):       # positive guard
                open(path)                  # validated inside the branch
        """
        self._check_sinks(node.test)
        guarded = self._containment_guarded_names(node.test)

        if guarded and not _body_bails_out(node.body):
            # Positive guard: the value is validated only inside the branch.
            saved = {n: self._tainted[n] for n in guarded if n in self._tainted}
            for name in guarded:
                self._tainted.pop(name, None)
            self._visit_body(node.body)
            self._tainted.update(saved)
            self._visit_body(node.orelse)
            return

        self._visit_body(node.body)
        self._visit_body(node.orelse)

        if guarded and _body_bails_out(node.body):
            # Guard clause: execution only continues when the check passed.
            for name in guarded:
                self._tainted.pop(name, None)
                self._sanitized.discard(name)

    def _containment_guarded_names(self, test: Optional[ast.expr]) -> Set[str]:
        """
        Return names proven to sit inside a known base directory by this test.

        Recognises ``value.startswith(base)``, ``value.is_relative_to(base)``
        and ``os.path.commonpath(...)`` comparisons. Only the receiver of the
        check is treated as validated.
        """
        names: Set[str] = set()
        if test is None:
            return names
        for call in _iter_calls(test):
            func = call.func
            if isinstance(func, ast.Attribute) and func.attr in CONTAINMENT_CHECKS:
                if isinstance(func.value, ast.Name):
                    names.add(func.value.id)
            elif _get_call_name(call) in CONTAINMENT_FUNCTIONS:
                names.update(_names_in_expr(call))
        return names

    # -- assignments --------------------------------------------------------

    def _visit_assign(self, targets: List[ast.expr], value: ast.expr) -> None:
        names = _target_names(targets)
        if not names:
            return

        # A validator strips taint entirely.
        if isinstance(value, ast.Call) and _is_validator_call(value):
            for name in names:
                self._tainted.pop(name, None)
                self._sanitized.discard(name)
            return

        # A sanitizer keeps taint but marks it for severity downgrade.
        if isinstance(value, ast.Call) and _is_sanitizer_call(value):
            source = self._expr_taint(value.args[0]) if value.args else None
            if source is not None:
                for name in names:
                    self._tainted[name] = source
                    self._sanitized.add(name)
            return

        source = self._expr_taint(value)
        propagate_sanitized = source is not None and self._expr_is_sanitized(value)
        self._assign_taint(names, source)
        for name in names:
            if propagate_sanitized:
                self._sanitized.add(name)
            elif source is None:
                self._sanitized.discard(name)

    def _visit_aug_assign(self, node: ast.AugAssign) -> None:
        if not isinstance(node.target, ast.Name):
            return
        target = node.target.id
        source = self._expr_taint(node.value) or self._tainted.get(target)
        if source is not None:
            self._tainted[target] = source
        if self._expr_is_sanitized(node.value) or target in self._sanitized:
            self._sanitized.add(target)

    # -- sinks --------------------------------------------------------------

    def _check_sinks(self, expr: Optional[ast.expr]) -> None:
        for call in _iter_calls(expr):
            self._visit_sink_call(call)

    def _visit_sink_call(self, node: ast.Call) -> None:
        name = _get_call_name(node)
        if not name:
            return

        # Subprocess calls only expose a shell when shell=True.
        if name in SINKS_SHELL_TRUE and not _call_has_shell_true(node):
            return

        arg_index = 0
        category = severity = message_key = ""
        for sink_name, idx, cat, sev, key in SINKS:
            if name == sink_name:
                arg_index, category, severity, message_key = idx, cat, sev, key
                break
        else:
            if isinstance(node.func, ast.Attribute) and node.func.attr == SINK_EXECUTE_ATTR:
                arg_index, category, severity, message_key = 0, "SQL Injection", "HIGH", "sql"
            else:
                return

        if arg_index >= len(node.args):
            return

        arg = node.args[arg_index]
        source = self._expr_taint(arg)
        if source is None:
            return

        self._add_finding(
            line_no=getattr(node, "lineno", 0),
            source=source,
            sink_desc=name,
            category=category,
            severity=severity,
            message_key=message_key,
            sanitized=self._expr_is_sanitized(arg),
        )

    def _add_finding(
        self,
        line_no: int,
        source: TaintSource,
        sink_desc: str,
        category: str,
        severity: str,
        message_key: str,
        sanitized: bool,
    ) -> None:
        key = (line_no, sink_desc)
        if key in self._reported:
            return
        self._reported.add(key)

        if sanitized:
            severity = "LOW"

        rule_id = "TAINT001"
        if "command" in message_key:
            rule_id = "TAINT-CMD"
        elif "sql" in message_key:
            rule_id = "TAINT-SQL"
        elif "path" in message_key:
            rule_id = "TAINT-PATH"

        source_desc = source.describe()
        if sanitized:
            msg = (
                f"Tainted data (sanitized) from {source_desc} reaches {sink_desc}. "
                "Verify the sanitization is sufficient for this sink."
            )
        else:
            msg = (
                f"Tainted data from {source_desc} flows into {sink_desc}, "
                f"which may allow {message_key} injection."
            )
        if source.kind == SOURCE_PARAMETER:
            msg += (
                " The parameter may carry untrusted data; confirm what callers pass. "
                "Taint analysis is intra-procedural and does not inspect call sites."
            )

        snippet = self._snippet(line_no)
        title = f"Taint flow: {source_desc} -> {sink_desc}"
        recommendation = (
            "Validate and sanitize untrusted input. Use parameterized queries for SQL, "
            "pass command arguments as a list instead of using shell=True, and confine "
            "file paths to an allowed base directory."
        )

        self.findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "type": title,
                "severity": severity,
                "confidence": _CONFIDENCE_BY_SOURCE.get(source.kind, "MEDIUM"),
                "category": category,
                "file_path": self.file_path,
                "file": self.file_path,
                "line_number": line_no,
                "line": line_no,
                "code_snippet": snippet,
                "snippet": snippet,
                "code": self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else "",
                "description": msg,
                "recommendation": recommendation,
                "suggested_fix": recommendation,
                "source": source_desc,
                "source_kind": source.kind,
                "sink": sink_desc,
                "explanation": msg,
                "taint_flow": True,
            }
        )

    def _snippet(self, line_no: int, context: int = 1) -> str:
        if not self.lines or line_no <= 0:
            return ""
        start = max(0, line_no - 1 - context)
        end = min(len(self.lines), line_no + context)
        out = []
        for i in range(start, end):
            prefix = ">>" if i == line_no - 1 else "  "
            out.append(f"{prefix} {i + 1:>4}: {self.lines[i]}")
        return "\n".join(out)


def _target_names(targets: List[ast.expr]) -> List[str]:
    """Return the variable names bound by a list of assignment targets."""
    names: List[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                if isinstance(element, ast.Name):
                    names.append(element.id)
    return names


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_file_taint(file_path: str, content: str, lines: List[str]) -> List[Dict[str, Any]]:
    """
    Run intra-procedural taint analysis over every function in a Python file.

    Each function is analysed independently with a fresh taint scope, which is
    what makes the analysis intra-procedural. Module-level statements are not
    analysed, since they have no parameters and run once at import.

    Returns a list of finding dicts in the standard report format.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    visitor = _TaintVisitor(file_path, lines)
    for node in ast.walk(tree):
        if isinstance(node, _FUNCTION_NODES):
            visitor.analyze_function(node)
    visitor.findings.sort(key=lambda f: (f.get("line_number", 0), f.get("rule_id", "")))
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
