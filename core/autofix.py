import ast
import difflib
import textwrap
from typing import List

from core.models import Finding


def _validate(original: str, fixed: str, language: str) -> dict:
    if language == "python":
        try:
            ast.parse(fixed)
        except SyntaxError as e:
            return {"valid": False, "reason": f"fix produced invalid Python: {e}"}

    if len(fixed) > len(original) * 3:
        return {"valid": False, "reason": "fix output suspiciously large"}

    return {"valid": True}


def _unified_diff(original: str, fixed: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        n=2,
    ))


def apply_fixes(code: str, findings: List[Finding], filename: str = "code.py",
                language: str = "python") -> dict:
    current = code
    applied, failed = [], []

    fixable = [f for f in findings if f.auto_fixable and f.fix_code and f.code_snippet]

    for f in fixable:
        snippet = textwrap.dedent(f.code_snippet).strip()
        fix_code = textwrap.dedent(f.fix_code).strip()

        if snippet not in current:
            failed.append({"id": f.id, "title": f.title,
                           "reason": "snippet not found in current code"})
            continue

        candidate = current.replace(snippet, fix_code, 1)
        verdict = _validate(current, candidate, language)

        if verdict["valid"]:
            diff = _unified_diff(current, candidate, filename)
            current = candidate
            applied.append({"id": f.id, "title": f.title, "diff": diff})
        else:
            failed.append({"id": f.id, "title": f.title, "reason": verdict["reason"]})

    return {
        "patched_code": current,
        "applied": applied,
        "failed": failed,
        "num_applied": len(applied),
        "num_failed": len(failed),
        "changed": current != code,
    }
