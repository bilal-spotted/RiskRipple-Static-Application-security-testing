# RiskRipple: Smart SAST for Python

[cite_start]I built this lightweight Static Application Security Testing (SAST) tool to solve the widely documented problems with traditional security scanners: they generate an overwhelming volume of alerts, cause alert fatigue, and provide little context about what a developer should actually do to fix the code[cite: 866, 918]. 

[cite_start]RiskRipple analyzes Python source code to detect 10 distinct classes of vulnerabilities (including SQLi, XSS, and Command Injection), but instead of just dumping a list of errors, it ranks them by true risk and provides plain-English remediation guidance directly in the workflow[cite: 867, 869, 871].

## 🚀 Core Novel Features

* [cite_start]**Exploitability Scoring Engine:** Instead of static High/Medium/Low labels, the engine calculates a dynamic risk score (0.0 to 10.0)[cite: 931]. [cite_start]It tracks data flows to see if vulnerable code is reachable from user-controlled input (taint bonus) and checks if it resides in a publicly exposed API endpoint (exposure bonus)[cite: 931].
* [cite_start]**Intelligent Noise Filter:** Reduces output clutter by fingerprinting and de-duplicating repeated findings across the codebase[cite: 936]. [cite_start]It also suppresses low-impact alerts below a configurable threshold, helping developers focus only on critical threats[cite: 870, 936].
* [cite_start]**Fix-Hint Generator:** Every single finding is accompanied by a plain-English remediation hint and a concrete replacement code example, allowing developers to patch the code without leaving their IDE to search documentation[cite: 933, 934].

## 🛠️ Technical Architecture

* [cite_start]**Language & Parsing:** Built entirely in Python, utilizing the built-in `ast` module to construct and traverse Abstract Syntax Trees (AST)[cite: 871, 1092].
* [cite_start]**Analysis Engine:** Implements intra-procedural taint analysis to map sources to dangerous sinks, alongside regex-based pattern matching for hardcoded secrets and weak cryptography[cite: 871, 979, 1111].
* [cite_start]**CI/CD Integration:** The tool runs locally via CLI and generates both a structured `findings.json` for pipeline quality gating and an interactive, color-coded `report.html` dashboard[cite: 872, 1154, 1155].

## ⚙️ How to Run

1. Clone the repository and navigate to the project root.
2. Run the CLI command against your target directory:
   [cite_start]`smart_sast --path ./your_project --min-score 3` [cite: 1052, 1053]
3. [cite_start]The engine will parse the `.py` files, apply the rules, and generate the security reports[cite: 1162, 1163, 1167].

## 🧠 Technical Hurdles & Lessons Learned

Developing this scanner forced me to think deeply about how code is structurally executed. 
* [cite_start]**AST Traversal:** Building the `AST Analyzer` taught me how to break down Python scripts into hierarchical grammar nodes, which was a massive step up from basic regex matching[cite: 1092, 1093].
* [cite_start]**Context Matters:** I learned that a vulnerability in dead code is not the same as a vulnerability in a live Flask `@app.route`[cite: 920, 1099]. [cite_start]Implementing the context-sensitive exposure map was the most challenging but rewarding part of the project, as it proved that security tools must prioritize developer workflow to actually be useful[cite: 924, 1099].
