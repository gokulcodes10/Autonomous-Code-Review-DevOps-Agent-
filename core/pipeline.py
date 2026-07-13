from core.config import settings
from core.models import Gate, GateStatus, HEALTH_WEIGHTS


def compute_health_score(counts: dict, ast_info: dict, static: dict) -> dict:
    score = 100.0
    w = HEALTH_WEIGHTS

    score += counts.get("CRITICAL", 0) * w["CRITICAL"]
    score += counts.get("HIGH", 0) * w["HIGH"]
    score += counts.get("MEDIUM", 0) * w["MEDIUM"]
    score += counts.get("LOW", 0) * w["LOW"]

    if static.get("_summary", {}).get("secrets"):
        score += w["secret"]

    total_fn = max(ast_info.get("total_functions", 1), 1)
    undoc = len(ast_info.get("undocumented_functions", []))
    untyped = len(ast_info.get("functions_without_type_hints", []))
    typed = total_fn - untyped
    high_cc = len(ast_info.get("high_complexity_functions", {}))

    score += high_cc * w["complexity_penalty"]
    score += (undoc / total_fn) * 10 * w["undocumented_penalty"]
    score += (typed / total_fn) * 10 * w["type_hint_bonus"]

    score = round(max(0.0, min(100.0, score)), 1)
    grade = (
        "A" if score >= 90 else
        "B" if score >= 80 else
        "C" if score >= 70 else
        "D" if score >= 60 else "F"
    )

    return {
        "score": score,
        "grade": grade,
        "breakdown": {
            "severity_deduct": round(
                counts.get("CRITICAL", 0) * w["CRITICAL"] +
                counts.get("HIGH", 0) * w["HIGH"], 1
            ),
            "complexity": round(high_cc * w["complexity_penalty"], 1),
            "docs": round((undoc / total_fn) * 10 * w["undocumented_penalty"], 1),
            "type_hints": round((typed / total_fn) * 10 * w["type_hint_bonus"], 1),
            "final": score,
        },
    }


def run_cicd_pipeline(static: dict, agent_results: dict, ast_info: dict) -> dict:
    gates = []
    counts = agent_results.get("counts", {})
    summ = static.get("_summary", {})

    n_secrets = len(static.get("secrets", {}).get("secrets", []))
    gates.append(Gate(
        "Secrets Detection",
        GateStatus.BLOCK if n_secrets else GateStatus.PASS,
        f"{n_secrets} hardcoded secret(s) detected" if n_secrets else "Clean",
    ))

    n_cve = len(static.get("pip_audit", {}).get("vulnerabilities", []))
    if n_cve:
        gates.append(Gate(
            "Dependency CVEs",
            GateStatus.BLOCK if n_cve >= 3 else GateStatus.WARN,
            f"{n_cve} known CVE(s) in dependencies",
        ))

    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    if crit:
        gates.append(Gate("Security Gate", GateStatus.BLOCK,
                          f"{crit} CRITICAL issue(s) must be fixed"))
    elif high > settings.max_high_severity:
        gates.append(Gate("Security Gate", GateStatus.WARN,
                          f"{high} HIGH issue(s) flagged"))
    else:
        gates.append(Gate("Security Gate", GateStatus.PASS, "Clean"))

    bh = summ.get("bandit_high", 0)
    gates.append(Gate(
        "Bandit Scan",
        GateStatus.WARN if bh > settings.max_high_severity else GateStatus.PASS,
        f"{bh} high bandit finding(s)" if bh > settings.max_high_severity else "Clean",
    ))

    high_cc = ast_info.get("high_complexity_functions", {})
    gates.append(Gate(
        "Complexity",
        GateStatus.WARN if len(high_cc) > 3 else GateStatus.PASS,
        f"{len(high_cc)} function(s) exceed CC={settings.complexity_threshold}"
        if len(high_cc) > 3 else "Clean",
    ))

    verdict_map = {
        "PASS": GateStatus.PASS,
        "WARN": GateStatus.WARN,
        "BLOCK": GateStatus.BLOCK,
    }
    v = agent_results.get("arbitration", {}).get("final_verdict", "WARN")
    gates.append(Gate(
        "AI Consensus",
        verdict_map.get(v, GateStatus.WARN),
        f"Multi-agent verdict: {v}",
    ))

    if any(g.status == GateStatus.BLOCK for g in gates):
        decision = "BLOCK"
        message = "Pipeline BLOCKED — critical issues must be resolved before merge."
    elif any(g.status == GateStatus.WARN for g in gates):
        decision = "WARN"
        message = "Pipeline WARNED — review flagged issues before merging."
    else:
        decision = "PASS"
        message = "Pipeline PASSED — code is clear for merge."

    return {
        "gates": gates,
        "decision": decision,
        "message": message,
        "passed": sum(1 for g in gates if g.status == GateStatus.PASS),
        "warned": sum(1 for g in gates if g.status == GateStatus.WARN),
        "blocked": sum(1 for g in gates if g.status == GateStatus.BLOCK),
    }
