import re
from core.models import CUSTOM_RULES


class CustomRuleEngine:
    def __init__(self, config: dict = None):
        self.config = config or CUSTOM_RULES

    def evaluate(self, code: str, ast_info: dict, filename: str = "code.py",
                 language: str = "python") -> list:
        findings = []
        lines = code.splitlines()

        for rule in self.config.get("rules", []):
            if not rule.get("enabled", True):
                continue
            if any(ex in filename for ex in rule.get("exclude_files", [])):
                continue
            langs = rule.get("languages")
            if langs and language not in langs:
                continue

            rid = rule["id"]
            sev = rule.get("severity", "LOW")
            rtype = rule["type"]
            name = rule["name"]

            if rtype == "max_function_lines":
                thr = rule.get("threshold", 50)
                for fn in ast_info.get("functions", []):
                    start = fn["lineno"] - 1
                    indent = len(lines[start]) - len(lines[start].lstrip())
                    count = 0
                    for ln in lines[start:]:
                        stripped = ln.strip()
                        if not stripped:
                            count += 1
                            continue
                        cur_indent = len(ln) - len(ln.lstrip())
                        if count > 0 and cur_indent <= indent and stripped:
                            break
                        count += 1
                    if count > thr:
                        findings.append({
                            "rule_id": rid,
                            "severity": sev,
                            "title": f"{name}: `{fn['name']}` ({count} lines)",
                            "description": f"Function has {count} lines, limit is {thr}.",
                            "line_number": fn["lineno"],
                            "suggestion": "Break into smaller, focused functions.",
                        })

            elif rtype == "forbidden_pattern":
                pat = rule.get("pattern", "")
                if not pat:
                    continue
                scan_comments = rule.get("scan_comments", False) or pat in ("TODO", "FIXME")
                for idx, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    is_comment = stripped.startswith(("#", "//", "/*", "*"))
                    if is_comment and not scan_comments:
                        continue
                    if not scan_comments and stripped.startswith(('"""', "'''", '"', "'")):
                        continue
                    if pat in line:
                        findings.append({
                            "rule_id": rid,
                            "severity": sev,
                            "title": f"{name}: `{pat}` at line {idx}",
                            "description": stripped[:100],
                            "line_number": idx,
                            "suggestion": rule.get("suggestion", f"Remove or replace `{pat}`"),
                        })

            elif rtype == "max_class_methods":
                thr = rule.get("threshold", 20)
                for cls in ast_info.get("classes", []):
                    if cls["num_methods"] > thr:
                        findings.append({
                            "rule_id": rid,
                            "severity": sev,
                            "title": f"{name}: `{cls['name']}` ({cls['num_methods']} methods)",
                            "description": f"Class has {cls['num_methods']} methods, limit is {thr}.",
                            "line_number": cls["lineno"],
                            "suggestion": "Split into smaller, cohesive classes.",
                        })

            elif rtype == "naming_convention":
                conv = rule.get("convention", "snake_case")
                for fn in ast_info.get("functions", []):
                    fn_name = fn["name"]
                    if fn_name.startswith("__"):
                        continue
                    if conv == "snake_case" and not re.match(r"^[a-z_][a-z0-9_]*$", fn_name):
                        findings.append({
                            "rule_id": rid,
                            "severity": sev,
                            "title": f"{name}: `{fn_name}` violates {conv}",
                            "description": f"Function name `{fn_name}` does not follow {conv}.",
                            "line_number": fn["lineno"],
                            "suggestion": f"Rename to {conv}.",
                        })

        return findings
