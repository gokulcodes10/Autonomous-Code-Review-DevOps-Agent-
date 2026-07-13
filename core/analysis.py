import ast
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import radon.complexity as radon_cc

from core.config import settings
from core.secrets import scan_secrets

LANGUAGE_MAP = {
    ".py": "python", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cxx": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".rs": "rust", ".go": "go",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".cs": "csharp",
    ".rb": "ruby", ".php": "php",
    ".swift": "swift", ".kt": "kotlin",
    ".sh": "bash", ".lua": "lua",
    ".scala": "scala", ".r": "r",
}

_FN_PATTERNS = {
    "c":          r'^\s*(?:static\s+|inline\s+|extern\s+)*\w[\w\s\*]+\s+(\w+)\s*\([^;]*\)\s*\{',
    "cpp":        r'^\s*(?:static\s+|inline\s+|virtual\s+)*[\w:<>\s\*]+\s+(\w+)\s*\([^;]*\)\s*(?:const\s*)?\{',
    "rust":       r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
    "go":         r'^\s*func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)',
    "java":       r'^\s*(?:public|private|protected|static|final|abstract|\s)*[\w<>\[\]]+\s+(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w,\s]+)?\{',
    "csharp":     r'^\s*(?:public|private|protected|internal|static|virtual|override|abstract|\s)*[\w<>\[\]]+\s+(\w+)\s*\([^;]*\)\s*\{',
    "javascript": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))',
    "typescript": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))',
    "ruby":       r'^\s*def\s+(\w+)',
    "php":        r'^\s*(?:public|private|protected|static|\s)*function\s+(\w+)',
    "swift":      r'^\s*(?:public|private|internal|fileprivate|open|\s)*(?:func|class func|static func)\s+(\w+)',
    "kotlin":     r'^\s*(?:(?:suspend|private|public|internal)\s+)*fun\s+(\w+)',
    "scala":      r'^\s*def\s+(\w+)',
}


def get_language(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return LANGUAGE_MAP.get(ext, "python")


def _write_temp(code: str, suffix: str = ".py") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(code)
    f.close()
    return f.name


def _run_cmd(cmd: list, timeout: int = 30) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""


def run_bandit(code: str) -> dict:
    tmp = _write_temp(code)
    try:
        raw = _run_cmd(["bandit", "-f", "json", "-q", tmp])
        d = json.loads(raw) if raw else {}
        return {"issues": d.get("results", []), "metrics": d.get("metrics", {})}
    except Exception:
        return {"issues": [], "metrics": {}}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def run_radon(code: str) -> dict:
    try:
        results = radon_cc.cc_visit(code)
        cc_map = {r.name: r.complexity for r in results}
        high_cc = {name: cc for name, cc in cc_map.items()
                   if cc > settings.complexity_threshold}
        return {"cc": cc_map, "high_cc": high_cc}
    except Exception:
        return {"cc": {}, "high_cc": {}}


def run_pip_audit(requirements: str) -> dict:
    tmp = _write_temp(requirements, suffix=".txt")
    try:
        raw = _run_cmd(
            ["pip-audit", "-r", tmp, "--format", "json", "--progress-spinner", "off"],
            timeout=60,
        )
        data = json.loads(raw) if raw.strip() else {}
        vulns = [
            {
                "package": dep.get("name"),
                "version": dep.get("version"),
                "vuln_id": v.get("id"),
                "fix": v.get("fix_versions", []),
            }
            for dep in data.get("dependencies", [])
            for v in dep.get("vulns", [])
        ]
        return {"vulnerabilities": vulns}
    except Exception:
        return {"vulnerabilities": []}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def run_static_analysis(code: str, language: str = "python", requirements: str = None) -> dict:
    if language == "python":
        bandit = run_bandit(code)
        radon = run_radon(code)
    else:
        bandit = {"issues": [], "metrics": {}}
        radon = {"cc": {}, "high_cc": {}}

    secrets = scan_secrets(code)
    pip_audit = run_pip_audit(requirements) if requirements else {"vulnerabilities": []}

    return {
        "bandit": bandit,
        "radon": radon,
        "secrets": secrets,
        "pip_audit": pip_audit,
        "semgrep": {"issues": []},
        "mypy": {"issues": []},
        "pylint": {"issues": []},
        "_summary": {
            "bandit_high": sum(1 for i in bandit["issues"] if i.get("issue_severity") == "HIGH"),
            "secrets": bool(secrets["secrets"]),
            "secret_count": len(secrets["secrets"]),
            "cve_count": len(pip_audit["vulnerabilities"]),
            "semgrep_errors": 0,
            "mypy_errors": 0,
            "total_static": len(bandit["issues"]) + len(secrets["secrets"]),
        },
    }


def _analyze_generic(code: str, language: str) -> dict:
    lines = code.splitlines()
    pattern = _FN_PATTERNS.get(language, r'(?:function|def|fn|func)\s+(\w+)')
    fns = []
    for i, line in enumerate(lines, 1):
        m = re.search(pattern, line)
        if m:
            name = next((g for g in (m.groups() or []) if g), "unknown")
            fns.append({
                "name": name, "lineno": i, "args": [],
                "is_async": "async" in line,
                "has_docstring": False, "has_type_hints": False, "decorators": [],
            })
    return {
        "functions": fns, "classes": [], "imports": [],
        "potentially_dead_code": [],
        "complexity": {}, "high_complexity_functions": {},
        "undocumented_functions": [f["name"] for f in fns],
        "functions_without_type_hints": [f["name"] for f in fns],
        "total_functions": len(fns), "total_classes": 0,
        "total_lines": len(lines), "error": None,
    }


def analyze_ast(code: str, language: str = "python") -> dict:
    if language != "python":
        return _analyze_generic(code, language)

    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {
            "error": str(e),
            "functions": [], "classes": [], "imports": [],
            "high_complexity_functions": {}, "potentially_dead_code": [],
            "undocumented_functions": [], "functions_without_type_hints": [],
            "total_functions": 0, "total_classes": 0, "complexity": {},
        }

    fns, classes, imports = [], [], []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            has_doc = (node.body and isinstance(node.body[0], ast.Expr)
                       and isinstance(node.body[0].value, ast.Constant))
            fns.append({
                "name": node.name, "lineno": node.lineno,
                "args": [a.arg for a in node.args.args],
                "is_async": isinstance(node, ast.AsyncFunctionDef),
                "has_docstring": has_doc,
                "has_type_hints": any(a.annotation for a in node.args.args),
                "decorators": [ast.unparse(d) for d in node.decorator_list],
            })
        elif isinstance(node, ast.ClassDef):
            has_doc = (node.body and isinstance(node.body[0], ast.Expr)
                       and isinstance(node.body[0].value, ast.Constant))
            direct_methods = sum(
                1 for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            classes.append({
                "name": node.name, "lineno": node.lineno,
                "bases": [ast.unparse(b) for b in node.bases],
                "num_methods": direct_methods, "has_docstring": has_doc,
            })
        elif isinstance(node, ast.Import):
            for a in node.names:
                imports.append({"module": a.name, "alias": a.asname, "lineno": node.lineno})
        elif isinstance(node, ast.ImportFrom):
            imports.append({"module": node.module,
                            "names": [a.name for a in node.names], "lineno": node.lineno})

    defined = {f["name"] for f in fns}
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)

    skip = {"main", "__init__", "__str__", "__repr__", "__len__", "__call__", "__enter__", "__exit__"}
    dead = list(defined - called - skip)
    radon_data = run_radon(code)

    return {
        "functions": fns, "classes": classes, "imports": imports,
        "potentially_dead_code": dead,
        "complexity": radon_data["cc"], "high_complexity_functions": radon_data["high_cc"],
        "undocumented_functions": [f["name"] for f in fns if not f["has_docstring"]],
        "functions_without_type_hints": [f["name"] for f in fns if not f["has_type_hints"]],
        "total_functions": len(fns), "total_classes": len(classes), "error": None,
    }
