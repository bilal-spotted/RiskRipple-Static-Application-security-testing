def suggest_patch(rule_name):
    suggestions = {
        "eval": "Avoid eval(). Replace with safer parsing logic.",
        "exec": "Avoid exec(). Refactor code to remove dynamic execution.",
        "os_system": "Use subprocess.run with argument list instead of os.system.",
        "subprocess_shell": "Avoid shell=True. Pass arguments as a list.",
        "pickle_load": "Avoid pickle for untrusted data. Use JSON instead.",
        "yaml_load": "Use yaml.safe_load instead of yaml.load.",
        "hardcoded_secret": "Move secrets to environment variables or config files.",
    }

    return suggestions.get(rule_name, "Review code manually.")
