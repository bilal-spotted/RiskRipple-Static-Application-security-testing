# Documentation

**Report preview:** Run `python scanner.py samples --output-dir output --format all` and open `output/security_report.html` in a browser to see the dashboard. Use this for demos or to capture a screenshot for portfolio or talks.

**Entrypoints:**

- Main scanner: `python scanner.py <path>`
- Web GUI: `python -m webapp.app` (open http://127.0.0.1:8000)
- Pre-commit secret check: `python tools/check_secrets.py`
