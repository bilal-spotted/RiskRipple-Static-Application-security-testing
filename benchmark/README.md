# Benchmark Suite

Small example files used to demonstrate scanner behavior. Each category has:

- **Vulnerable**: Code that the scanner should flag (e.g. command injection, SQL injection, unsafe deserialization).
- **Safe**: Intentionally safe alternatives (parameterized queries, `yaml.safe_load`, etc.).

| Category | Vulnerable | Safe |
|----------|------------|------|
| Command injection | `command_injection_vulnerable.py` | `command_injection_safe.py` |
| SQL injection | `sql_injection_vulnerable.py` | `sql_injection_safe.py` |
| Path traversal | `path_traversal_vulnerable.py` | `path_traversal_safe.py` |
| Unsafe deserialization | `deserialization_vulnerable.py` | `deserialization_safe.py` |
| Weak crypto | `weak_crypto_vulnerable.py` | `weak_crypto_safe.py` |
| Secret exposure | `secret_exposure_vulnerable.py` | `secret_exposure_safe.py` |

Run the scanner on this directory:

```bash
python scanner.py benchmark --output-dir output --format all
```

Then open `output/security_report.html` to view findings and risk score.
