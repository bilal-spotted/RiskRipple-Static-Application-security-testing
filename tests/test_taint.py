"""
Tests for intra-procedural taint analysis.

Covers: command injection flow, SQL injection flow, path traversal,
and sanitized flows (reduced severity or suppression).
"""

from core.taint_analysis import analyze_file_taint, get_taint_rule_metadata


def _run_taint(code: str) -> list:
    """Run taint analysis on code string; return list of findings."""
    lines = code.splitlines()
    return analyze_file_taint("test.py", code, lines)


def test_command_injection_flow():
    """user = input(); os.system(user) -> taint finding."""
    code = """
def main():
    user = input()
    os.system(user)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) >= 1
    f = taint_findings[0]
    assert f.get("severity") == "HIGH"
    assert "command" in f.get("description", "").lower() or "os.system" in f.get("sink", "")
    assert f.get("category") == "Command Injection"
    assert f.get("line_number") == 4  # os.system(user) line


def test_sql_injection_flow():
    """name = request.args['name']; query = ... + name; cursor.execute(query) -> finding."""
    code = """
def get_user():
    name = request.args["name"]
    query = "SELECT * FROM users WHERE name=" + name
    cursor.execute(query)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) >= 1
    f = taint_findings[0]
    assert f.get("severity") == "HIGH"
    assert "sql" in f.get("description", "").lower() or "execute" in f.get("sink", "")
    assert f.get("category") == "SQL Injection"


def test_safe_case_with_sanitizer():
    """cmd = shlex.quote(input()); os.system(cmd) -> LOW or suppressed."""
    code = """
def run_safe():
    cmd = shlex.quote(input())
    os.system(cmd)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    # Should still report but with reduced severity when sanitizer is used
    if taint_findings:
        f = taint_findings[0]
        # Sanitized flow: severity should be LOW
        assert f.get("severity") == "LOW", "Sanitized flow should be LOW severity"


def test_path_traversal_flow():
    """path = request.args['file']; open(path) or open(os.path.join(..., path))."""
    code = """
def read_file():
    path = request.args["file"]
    full = "/tmp/" + path
    open(full)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) >= 1
    f = taint_findings[0]
    assert f.get("category") == "Path Traversal"
    assert f.get("severity") in ("MEDIUM", "HIGH")


def test_request_args_get_source():
    """request.args.get('name') as source."""
    code = """
def handler():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name=" + name
    cursor.execute(query)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) >= 1
    assert any("execute" in f.get("sink", "") for f in taint_findings)


def test_subprocess_shell_true_sink():
    """subprocess.run(user_cmd, shell=True) with tainted user_cmd."""
    code = """
def run_cmd():
    user_cmd = input()
    subprocess.run(user_cmd, shell=True)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) >= 1
    f = taint_findings[0]
    assert "subprocess" in f.get("sink", "") or f.get("category") == "Command Injection"


def test_subprocess_shell_false_not_sink():
    """subprocess.run([...], shell=False) should not be taint sink (no shell)."""
    code = """
def run_cmd():
    user_cmd = input()
    subprocess.run(["/bin/echo", user_cmd], shell=False)
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    # We only treat first arg as sink when shell=True; with shell=False we don't report
    assert len(taint_findings) == 0


def test_findings_have_required_fields():
    """Taint findings include rule_id, category, severity, source, sink, file_path, line_number."""
    code = """
def f():
    x = input()
    os.system(x)
"""
    findings = _run_taint(code)
    assert len(findings) >= 1
    for f in findings:
        assert "rule_id" in f
        assert "category" in f
        assert "severity" in f
        assert "file_path" in f
        assert "line_number" in f
        assert f.get("taint_flow") is True
        assert "source" in f or "sink" in f


def test_taint_rule_metadata():
    """get_taint_rule_metadata returns list of rule dicts."""
    meta = get_taint_rule_metadata()
    assert isinstance(meta, list)
    assert len(meta) >= 1
    for rule in meta:
        assert "rule_id" in rule
        assert "title" in rule
        assert "category" in rule


def test_no_finding_when_no_flow():
    """No taint finding when sink gets constant (no source flow)."""
    code = """
def f():
    os.system("echo hello")
"""
    findings = _run_taint(code)
    taint_findings = [f for f in findings if f.get("taint_flow")]
    assert len(taint_findings) == 0


def test_analyzer_integration_taint_included():
    """Full analyze_file() includes taint findings for Python files."""
    import tempfile
    from pathlib import Path

    from core.analyzer import analyze_file

    code = """
def main():
    user = input()
    os.system(user)
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        findings = analyze_file(path)
        taint_findings = [x for x in findings if x.get("taint_flow")]
        assert len(taint_findings) >= 1
        assert taint_findings[0].get("rule_id", "").startswith("TAINT")
    finally:
        Path(path).unlink(missing_ok=True)
