# RiskRipple: AI-assisted SAST for repositories

A lightweight, context-aware Static Application Security Testing (SAST) engine designed to detect vulnerabilities in codebases without overwhelming developers with false positives. 

I developed this tool to address a massive gap in the DevSecOps tooling landscape: traditional scanners generate too much noise and provide zero context. By utilizing Python's built-in `ast` module, RiskRipple performs deep structural analysis, intra-procedural taint tracking, and dynamic risk scoring to highlight real, exploitable threats while automatically generating plain-English remediation guidance.

## Innovations

* **Dynamic Exploitability Scoring (0.0 - 10.0):** Instead of assigning static severity labels, the engine calculates a dynamic risk score. It applies a "taint bonus" if the vulnerable code is reachable from user-controlled input and an "exposure bonus" if it resides in a publicly accessible web route (e.g., Flask `@app.route`). It also applies a context penalty to downgrade findings located in test files or dead code.
* **Intelligent Noise Filtering:** Combats alert fatigue through deterministic fingerprinting. It de-duplicates repeated findings (such as a copy-pasted database query) and suppresses low-impact alerts below a customizable minimum score threshold.
* **Inline Fix-Hint Generator:** Every finding is paired with a specific, plain-English remediation hint and a secure code replacement example, allowing developers to patch vulnerabilities without breaking their workflow to read external documentation.

## Vulnerability Coverage

The rule engine currently evaluates Abstract Syntax Trees (AST) and string patterns to detect 10 critical vulnerability classes:
1. **SQL Injection (SQLi)** - Tracks tainted data into database execution sinks.
2. **Cross-Site Scripting (XSS)** - Detects unsanitized input in template rendering functions.
3. **Command Injection** - Flags unsafe `subprocess` calls configured with `shell=True`.
4. **Hardcoded Secrets** - Regex-based detection for API keys, passwords, and tokens.
5. **Insecure Deserialization** - Flags unsafe `pickle.loads()` or `yaml.load()` executions.
6. **Weak Cryptography** - Detects deprecated algorithms like MD5, SHA1, and DES.
7. **Path Traversal** - Identifies user-controlled input in file path construction.
8. **Insecure Randomness** - Flags non-cryptographic random number generators.
9. **Debug/Logging Leaks** - Detects active production debug flags (e.g., `app.run(debug=True)`).
10. **Unsafe File Handling** - Highlights risky file write and open operations.

##  Technical Architecture

* **Repo Loader:** Recursively traverses the target directory, automatically filtering out virtual environments (`venv/`) and cache directories (`__pycache__/`).
* **AST Analyzer:** Parses source code into abstract syntax trees, building context-sensitive **Taint Maps** (tracking user input flow) and **Exposure Maps** (identifying exposed web endpoints).
* **Rule Engine:** Evaluates AST nodes against structural security rules and pattern matches.
* **Report Generator:** Outputs findings in a structured `findings.json` (ideal for pipeline gating) and an interactive, color-coded `report.html` dashboard.

## ⚙️ Quick Start & Integration

Designed for speed and simplicity, the scanner runs locally with zero external network dependencies and analyzes thousands of lines of code in seconds.

**Run a local scan:**
```bash
smart_sast --path ./my_project_src --min-score 4.0
```
## CI/CD Pipeline Integration (GitHub Actions / GitLab CI):

RiskRipple is built for DevSecOps automation. Use the --fail-on-critical flag to enforce strict security gates. If a vulnerability scores an 8.0 or higher, the engine exits with code 1, automatically blocking the pull request or merge.

## Development Journey & Technical Hurdles
Building a custom SAST tool from scratch was an intense dive into program analysis and compiler theory. Moving beyond simple regex string matching to actual AST traversal required mapping out exactly how Python handles variable assignments and function scopes.

The biggest technical hurdle was implementing the intra-procedural taint analysis. Tracking how a variable changes state from the moment it enters a function as a request parameter until it hits a dangerous sink like cursor.execute() taught me how critical context is in security engineering. This project proved to me that effective security tooling doesn't just find bugs—it must genuinely understand the developer's environment to be useful.
