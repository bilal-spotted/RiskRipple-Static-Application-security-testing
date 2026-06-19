# Risk Ripple Report

**Scan Target:** `C:\Users\happy\Desktop\ai-repo-security-scanner-main\samples`  
**Generated:** 2026-06-03 16:52:07

## Scan Summary

- Files scanned: **1**
- Total findings: **8**
- Repository risk score: **86** — Risk level: **High**

### Severity Breakdown

- HIGH: **7**
- MEDIUM: **1**
- LOW: **0**

## Top Risky Files

| File | Risk Score | Findings |
|------|-----------|----------|
| `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py` | 68 | 7 |
| `.gitignore` | 3 | 1 |

## Risk Score Explanation

| Factor | Contribution |
|--------|--------------|
| CRITICAL × 10 | 0 |
| HIGH × 6 | 42 |
| MEDIUM × 3 | 3 |
| LOW × 1 | 0 |
| Total severity score | 45 |
| Taint-flow bonus | 10 |
| Secret exposure bonus | 0 |
| Repository hygiene | 1.5 |
| File concentration | 10.0 |
| Unique files factor | 2.0 |
| Critical category bonus | 18 |

## Top Risky Rule Categories

| Category | Findings |
|----------|----------|
| Command Injection | 3 |
| Unsafe Deserialization | 2 |
| Code Injection | 1 |
| Repository Hygiene | 1 |
| SQL Injection | 1 |

## Repository Hygiene & Sensitive Artifacts

### Verify sensitive files are not tracked
- **Severity:** MEDIUM
- **File/Path:** `.gitignore`
- **Description:** .gitignore only prevents untracked files from being added; it does not untrack or remove files already in the index. Sensitive or cache files already committed remain in repository history until explicitly removed.
- **Recommendation:** Run 'git ls-files' to list tracked files. For any .env, __pycache__, *.pyc, or venv paths: use 'git rm --cached <file>' to stop tracking. Rotate any exposed secrets.
- **Remediation:** Run git ls-files and use git rm --cached for any .env, __pycache__, *.pyc, venv.


## Taint Flow Findings

### Taint flow: user input -> os.system
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Flow:** user input → os.system
- **Description:** Tainted data from user input flows into os.system, which may allow command injection.

### Taint flow: user input -> cursor.execute
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Flow:** user input → cursor.execute
- **Description:** Tainted data from user input flows into cursor.execute, which may allow sql injection.


## Findings

### Use of os.system()
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 9
- **Description:** os.system() may lead to command injection if arguments include untrusted input.
- **Recommendation:** Use subprocess.run() with a list of arguments and avoid shell interpretation.
- **Remediation:** Use subprocess.run() with a list of arguments and avoid shell interpretation.
- **References:** CWE-78, A03:2021-Injection

```
      8: def run(cmd):
>>    9:     os.system(cmd)
     10: 
```

### Use of pickle.loads()
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 13
- **Description:** pickle deserialization may execute arbitrary code when loading untrusted data.
- **Recommendation:** Do not deserialize untrusted pickle data. Use safer formats such as JSON where possible.
- **Remediation:** Do not deserialize untrusted pickle data. Use JSON or other safe formats.
- **References:** CWE-502, A08:2021-Software and Data Integrity Failures

```
     12: def load_data(data):
>>   13:     return pickle.loads(data)
     14: 
```

### Use of yaml.load()
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 17
- **Description:** yaml.load() may be unsafe when parsing untrusted YAML content.
- **Recommendation:** Prefer yaml.safe_load() for untrusted input.
- **Remediation:** Prefer yaml.safe_load() for untrusted input.
- **References:** CWE-502, A08:2021-Software and Data Integrity Failures

```
     16: def parse_yaml(text):
>>   17:     return yaml.load(text)
     18: 
```

### Use of eval()
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 21
- **Description:** eval() executes dynamic Python code and may allow code injection.
- **Recommendation:** Avoid eval(). Use safe parsing, explicit logic, or restricted parsing libraries.
- **Remediation:** Avoid eval(). Use safe parsing, explicit logic, or restricted parsing libraries.
- **References:** CWE-94, A03:2021-Injection

```
     20: def unsafe_eval(x):
>>   21:     eval(x)
     22: 
```

### Use of os.system()
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 27
- **Description:** os.system() may lead to command injection if arguments include untrusted input.
- **Recommendation:** Use subprocess.run() with a list of arguments and avoid shell interpretation.
- **Remediation:** Use subprocess.run() with a list of arguments and avoid shell interpretation.
- **References:** CWE-78, A03:2021-Injection

```
     26:     user = input()
>>   27:     os.system(user)
     28: 
```

### Taint flow: user input -> os.system
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 27
- **Description:** Tainted data from user input flows into os.system, which may allow command injection.
- **Recommendation:** Validate and sanitize user input; use parameterized queries for SQL; avoid shell=True.
- **Remediation:** Use allowlists and avoid shell=True; prefer subprocess with list args.
- **References:** CWE-78, A03:2021-Injection

```
     26:     user = input()
>>   27:     os.system(user)
     28: 
```

### Taint flow: user input -> cursor.execute
- **Severity:** HIGH
- **File:** `C:/Users/happy/Desktop/ai-repo-security-scanner-main/samples/vulnerable_sample.py`
- **Line:** 34
- **Description:** Tainted data from user input flows into cursor.execute, which may allow sql injection.
- **Recommendation:** Validate and sanitize user input; use parameterized queries for SQL; avoid shell=True.
- **Remediation:** Use parameterized queries or prepared statements.
- **References:** CWE-89, A03:2021-Injection

```
     33:     query = "SELECT * FROM users WHERE name=" + name
>>   34:     cursor.execute(query)
```

### Verify sensitive files are not tracked
- **Severity:** MEDIUM
- **File:** `.gitignore`
- **Line:** None
- **Description:** .gitignore only prevents untracked files from being added; it does not untrack or remove files already in the index. Sensitive or cache files already committed remain in repository history until explicitly removed.
- **Recommendation:** Run 'git ls-files' to list tracked files. For any .env, __pycache__, *.pyc, or venv paths: use 'git rm --cached <file>' to stop tracking. Rotate any exposed secrets.
- **Remediation:** Run git ls-files and use git rm --cached for any .env, __pycache__, *.pyc, venv.

## Scan Errors

_No scan errors._
