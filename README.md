# Risk Ripple

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/bilal-spotted/RiskRipple-Static-Application-security-testing/actions/workflows/tests.yml/badge.svg)](https://github.com/bilal-spotted/RiskRipple-Static-Application-security-testing/actions/workflows/tests.yml)
[![Lint](https://github.com/bilal-spotted/RiskRipple-Static-Application-security-testing/actions/workflows/lint.yml/badge.svg)](https://github.com/bilal-spotted/RiskRipple-Static-Application-security-testing/actions/workflows/lint.yml)

**Rule-based SAST and repository hygiene for local Python projects.** Combines AST analysis, regex rules, intra-procedural taint tracking, and repo hygiene checks to produce **explainable** risk scores and reports (Markdown, HTML, JSON, SARIF). No black-box ML—every finding and score is traceable. Built for clarity, demos, and security-tool discussions.

---

## Table of Contents

- [Quickstart](#quickstart)
- [Web GUI](#web-gui)
- [Why this project](#why-this-project)
- [Key features](#key-features)
- [Detection capabilities](#detection-capabilities)
- [Risk scoring](#risk-scoring)
- [Report formats](#report-formats)
- [60-second demo](#60-second-demo)
- [Installation & usage](#installation--usage)
- [Architecture](#architecture)
- [Benchmark & samples](#benchmark--samples)
- [Example output](#example-output)
- [JSON output schema](#json-output-schema)
- [Limitations](#limitations)
- [Development & testing](#development--testing)
- [Future work](#future-work)
- [License](#license)

---

## Quickstart

```bash
git clone https://github.com/bilal-spotted/RiskRipple-Static-Application-security-testing.git
cd RiskRipple-Static-Application-security-testing
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

python scanner.py samples --output-dir output --format all
```

Reports are written to `output/`. Open **`output/security_report.html`** for the dashboard. Console output shows file count, finding counts by severity, risk score, and top risky files.

**CI-style run** (exit 1 if HIGH+ findings or score ≥ 50):

```bash
python scanner.py . --fail-on-severity HIGH --fail-on-score 50 -q
```

## Web GUI

Run the full dashboard locally (scan configuration, results, reports, tools):

```bash
pip install -r requirements.txt
python -m webapp.app
```

Open http://127.0.0.1:8000 in a browser. The GUI stores run data under `webapp/data/`.

Optional environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `WEBAPP_HOST` | Bind address | `127.0.0.1` |
| `WEBAPP_PORT` | Port | `8000` |
| `WEBAPP_DEBUG` | Werkzeug debug mode | off |
| `WEBAPP_SECRET_KEY` | Session signing key; a random per-process key is generated when unset | *(random)* |
| `WEBAPP_OUTPUT_ROOT` | Directory that scan output must stay inside | current working directory |

The CLI remains available and unchanged: `python scanner.py <path>`.

### Security posture of the web GUI

The GUI is a **single-user local tool**. It has no authentication and it reads
the local filesystem by design, so it is built for loopback use only.

Within that model it enforces:

- **CSRF tokens** on every state-changing request, so another site you have open
  cannot drive the interface on your behalf.
- **Path confinement** on file reads. The AI review page only reads files that
  the loaded target directory actually enumerated — a request naming an
  arbitrary path is refused. This matters most when an API key is configured,
  since reviewed content leaves your machine.
- **Output confinement.** Report writing cannot escape `WEBAPP_OUTPUT_ROOT`;
  absolute paths and `..` traversal outside it are refused.
- **No shared default secret.** When `WEBAPP_SECRET_KEY` is unset a random key
  is generated per process rather than falling back to a constant.

Do not expose it on a network. Setting `WEBAPP_HOST` to a non-loopback address
prints a warning; combining that with `WEBAPP_DEBUG=1` exposes the Werkzeug
debugger, which permits arbitrary code execution.

---

## AI-assisted review (optional)

An optional layer that asks a language model to review selected files and
returns **advisory** findings alongside the rule-based ones.

**The scanner is fully functional without it.** No API key, no network, no
degraded behaviour — AI is an extra, never a dependency. Every test in the
suite passes with no key configured.

### Enabling it

1. Get a free API key from [Google AI Studio](https://aistudio.google.com/apikey).
2. Put it in your environment (never in the repository):

```bash
set GEMINI_API_KEY=your-key-here
```

3. Add `--ai-review` to a scan:

```bash
python scanner.py . --ai-review --format all
```

The default model runs on Gemini's **free tier**, so demonstrating the feature
costs nothing.

### Advisory findings never affect the risk score

This is deliberate. The project's central claim is that every point of the risk
score traces to a documented rule and weight. A model's judgement is not a rule,
so AI findings are:

- carried in their own report section, clearly attributed
- excluded from the risk score and severity counts
- always reported at LOW confidence

You get the extra perspective without losing the deterministic guarantee.

### Cost controls

| Setting | Purpose | Default |
|---------|---------|---------|
| `RISKRIPPLE_AI_MAX_FILES` | Files sent per run | 10 |
| `RISKRIPPLE_AI_MAX_CHARS` | Characters sent per file | 12000 |
| `RISKRIPPLE_AI_CACHE_DIR` | Response cache location | `~/.cache/riskripple/ai` |

Responses are cached by content hash, so re-scanning unchanged files costs
nothing.

### Using a different model or provider

Change the model with an environment variable — no code edit:

```bash
set RISKRIPPLE_AI_MODEL=gemini-2.5-flash-lite
```

To use a **different provider entirely**, implement one method in
[`core/ai_provider.py`](core/ai_provider.py) and register it:

```python
class MyProvider:
    name = "myprovider"
    model = "some-model"

    def generate_json(self, prompt: str, schema: dict):
        """Call your API and return parsed JSON matching `schema`.
        Raise AIProviderError(kind, message) on failure."""
        ...

_PROVIDERS = {"gemini": _build_gemini, "myprovider": _build_myprovider}
```

Then set `RISKRIPPLE_AI_PROVIDER=myprovider`. Nothing else in the pipeline
changes — it only knows about the `generate_json` contract. The Gemini
implementation uses the standard library rather than a vendor SDK, so adding a
provider adds no dependency.

The prompt and the response schema live in
[`prompts/security_prompts.py`](prompts/security_prompts.py).

---

## Why this project

- **Explainable**: Every finding links to a rule; every score component is documented. No ML—auditable and interview-friendly.
- **Deterministic**: Same repo → same results. Reproducible for triage and baselines.
- **Low-noise**: Fewer, higher-confidence rules over pattern spraying. Quality over quantity.
- **Python-first**: AST and taint target Python; regex and hygiene apply to supported file types.
- **Portfolio-grade**: Clear layout, tests, CI, and docs so the project is easy to run, extend, and discuss.

**Engineering trade-offs** (useful for interviews):

- **Taint is intra-procedural** by design: we track flows inside a single function. Cross-function/cross-file taint would improve coverage but add major complexity; we document the limit and keep the implementation understandable.
- **Scoring is additive and explicit**: severity + taint/secret/hygiene/concentration bonuses. We prefer a transparent formula over a single opaque number.
- **Rules are curated**: we avoid adding weak regexes that would inflate counts. Each rule has metadata (CWE/OWASP, remediation) and is intended to be defensible.

---

## Key features

- **AST checks**: Dangerous Python calls (`eval`, `exec`, `compile`, `os.system`, `subprocess` with `shell=True`, `pickle.loads`, unsafe `yaml.load`).
- **Regex rules**: Hardcoded secrets, weak crypto (MD5/SHA1, insecure random), TLS/SSL misconfig, debug mode.
- **Intra-procedural taint**: Source → sink within one function (command injection, SQL injection, path traversal).
- **Repository hygiene**: Tracked sensitive files (`.env`, keys, `.pyc`), `.gitignore` gaps, secret patterns in content.
- **Deterministic risk score**: Severity + taint/secret/hygiene/concentration bonuses; full breakdown in reports.
- **Outputs**: Markdown, HTML dashboard, JSON, SARIF 2.1.0 (with fingerprints). Normalization and fingerprint-based dedup before reporting.

---

## Detection capabilities

| Method | What it does |
|--------|--------------|
| **AST** | Dangerous Python constructs: `eval()`, `exec()`, `compile()`, `os.system()`, `subprocess` with `shell=True`, `pickle.loads()`, unsafe `yaml.load()`. |
| **Regex** | Secrets, API keys, weak crypto (MD5/SHA1, insecure random), `verify=False`, debug mode. |
| **Taint** | **Intra-procedural only**: user input (e.g. `input()`, `request.args`) → sinks (shell, SQL, file path) within the same function. No cross-function or cross-file flow. |
| **Hygiene** | Tracked `.env`/keys/`.pyc`, missing `.gitignore` patterns, secret patterns in file content. Remediation explains that `.gitignore` does not untrack already-committed files. |

---

## Risk scoring

Score = **severity contribution** (CRITICAL×10, HIGH×6, MEDIUM×3, LOW×1) + **taint bonus** + **secret-exposure bonus** + **hygiene contribution** + **file concentration** (when 2+ files) + **unique-files factor** + **critical-category bonus**. All components are in the report breakdown.

**Bands:** 0–20 Low · 21–50 Moderate · 51–100 High · >100 Critical.

Use `--fail-on-severity` and `--fail-on-score` in CI to enforce thresholds.

---

## Report formats

| Format | Use |
|--------|-----|
| **Markdown** | Human-readable audit: summary, severity breakdown, top files, findings. |
| **HTML** | Standalone dashboard: risk cards, severity/category distribution, top files/categories, score breakdown, searchable findings table. |
| **JSON** | Structured export for tooling; stable schema (see [JSON output schema](#json-output-schema)). |
| **SARIF 2.1.0** | For CI/code-scanning; includes fingerprints and run-level risk summary. |

**What the HTML report shows:** Risk summary cards (files scanned, total findings, risk score with level badge), score breakdown table, severity bar chart, top risky categories and files, repository hygiene section, taint findings section, and a searchable full findings table with severity, rule, file, line, and expandable details (description, recommendation, CWE/OWASP, code snippet). Generate it with the [Quickstart](#quickstart) and open `output/security_report.html`; see `docs/README.md` for a short reference.

---

## 60-second demo

1. **Scan the samples:** `python scanner.py samples --output-dir output --format all`
2. **Read the console:** Note files scanned, finding counts by severity, risk score, top risky files.
3. **Open the dashboard:** Open `output/security_report.html` in a browser.
4. **Use in CI:** `python scanner.py . --fail-on-severity HIGH --fail-on-score 50 -q` (exits 1 if thresholds are met).

---

## Installation & usage

**Requirements:** Python 3.10+

1. Clone, create a venv, and install: `pip install -r requirements.txt`
2. Run: `python scanner.py <path_to_repo_or_folder>`
3. Reports go to `output/` by default. Use `--output-dir` and `--format` to change.

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Path to scan | (required) |
| `--workers` | Concurrent scan workers | 8 |
| `--top-files` | Top risky files in summary | 5 |
| `--format` | `md`, `html`, `json`, `sarif`, or `all` | `all` |
| `--output-dir` | Report output directory | `output` |
| `--fail-on-severity` | Exit 1 if any finding has this severity or higher | — |
| `--fail-on-score` | Exit 1 if risk score ≥ N | — |
| `-v`, `--verbose` | Debug logging | — |
| `-q`, `--quiet` | Only errors; no summary | — |

**Exit codes:** 0 = success. 1 = invalid target, collection error, or threshold met.

**Pre-commit secret scanner:** `python tools/check_secrets.py` (optionally `--include-test-fixtures` for tests/benchmark/samples).

---

## Architecture

| Directory | Role |
|-----------|------|
| **`core/`** | Analyzer (AST + regex), taint analysis, repo hygiene, risk scoring, rule registry, finding normalization. |
| **`rules/`** | Regex rule definitions; **`rules/metadata/`** YAML for rule metadata (CWE, OWASP, remediation, detection_type). |
| **`reports/`** | Markdown, HTML, JSON, SARIF generators. |
| **`io_utils/`** | File discovery and path handling. |
| **`tools/`** | e.g. `check_secrets.py` for pre-commit. |

**Pipeline:** Discover files → run AST + regex + taint per file → run hygiene on repo → enrich findings from rule metadata → normalize and deduplicate by fingerprint → compute risk and breakdown → write reports.

---

## Benchmark & samples

**`benchmark/`** — Pairs of vulnerable vs safe examples (command injection, SQL injection, path traversal, deserialization, weak crypto, secret exposure). Run: `python scanner.py benchmark --output-dir output --format all`, then open `output/security_report.html`.

**`samples/`** — Single file with multiple issue types for a quick demo (`python scanner.py samples`).

See `benchmark/README.md` for the file list.

---

## Example output

**Console summary:**

```
Scan Summary
----------------------------
Files scanned: 1
Total findings: 9

Severity counts:
  CRITICAL: 0
  HIGH: 8
  MEDIUM: 1
  LOW: 0

Repository risk score: 100 — Risk level: High

Top risky files:
1. vulnerable_sample.py (score 83, 8 findings)
2. .gitignore (score 3, 1 findings)
...
```

**JSON** (excerpt): `scan_summary` includes `repository_risk_score`, `risk_level`, and `score_breakdown` (all contribution components). Full structure below.

---

## JSON output schema

| Field | Description |
|-------|-------------|
| `tool`, `version`, `generated_at` | Tool identity and timestamp. |
| `target` | Scanned path. |
| `scan_summary` | `files_scanned`, `total_findings`, `severity_counts`, `repository_risk_score`, `risk_level`, `score_breakdown`. |
| `top_risky_files` | `{ file_path, risk_score, findings_count, severity_counts }`. |
| `top_risky_categories` | `{ category, count }`. |
| `findings` | Finding objects (rule_id, title, severity, confidence, category, file_path, line_number, description, recommendation, remediation, cwe, owasp, fingerprint). |
| `scan_errors` | `{ file, error }` for scan failures. |

---

## Limitations

- **Taint**: Intra-procedural only. No inter-procedural or cross-file data flow.
- **Rule-based**: AST + regex + taint. False positives (e.g. test code) and false negatives (e.g. obfuscation, indirect flows) are possible.
- **Coverage**: Fixed set of sources, sinks, and patterns. Not a replacement for a full audit or commercial SAST.
- **Advisory**: Validate findings in context before treating as confirmed vulnerabilities.

---

## Development & testing

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

**Lint:**

```bash
pip install ruff
ruff check .
ruff format --check .
```

CI runs tests and lint on push/PR (`.github/workflows/tests.yml`, `.github/workflows/lint.yml`). Optional: `pre-commit install` (see `.pre-commit-config.yaml`).

Pytest configuration lives in `pyproject.toml` under `[tool.pytest.ini_options]`.

---

## Future work

- More taint sources/sinks and AST rules (e.g. subprocess/YAML) with low-noise criteria.
- Inter-procedural or cross-file taint (larger effort).
- Baseline/regression tests for rule changes.
- SARIF path normalization and optional GitHub Code Scanning upload.

---

## License

MIT. See [LICENSE](LICENSE).
