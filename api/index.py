import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from core.agents import ReviewOrchestrator
from core.analysis import run_static_analysis, analyze_ast, get_language, LANGUAGE_MAP
from core.autofix import apply_fixes
from core.rules import CustomRuleEngine
from core.pipeline import run_cicd_pipeline, compute_health_score
from core.models import Finding
from core.config import settings
from core import github_integration as gh

MAX_UPLOAD_BYTES = 1_000_000

_template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

app = Flask(__name__, template_folder=_template_dir)
CORS(app)

_orchestrator = ReviewOrchestrator()
_rule_engine = CustomRuleEngine()


def _secret_findings(static: dict) -> list:
    findings = []
    for i, s in enumerate(static.get("secrets", {}).get("secrets", []), 1):
        findings.append(Finding(
            id=f"SECRET-{i:03d}",
            severity="CRITICAL",
            category="security",
            title=f"Hardcoded secret: {s['type']}",
            description=f"A {s['type']} ({s['preview']}, entropy {s['entropy']}) is hardcoded in the source.",
            line_number=s.get("line_number"),
            code_snippet=None,
            suggestion="Move the secret to an environment variable or secrets manager and rotate it.",
            auto_fixable=False,
            fix_code=None,
            agent="SecretScanner",
            confidence=0.95,
            cwe_id="CWE-798",
            owasp_category="A07:2021",
        ))
    return findings


def _cve_findings(static: dict) -> list:
    findings = []
    for i, v in enumerate(static.get("pip_audit", {}).get("vulnerabilities", []), 1):
        fix = ", ".join(v["fix"]) if v.get("fix") else "no fix available"
        findings.append(Finding(
            id=f"CVE-{i:03d}",
            severity="HIGH",
            category="security",
            title=f"Vulnerable dependency: {v['package']} {v['version']}",
            description=f"{v['vuln_id']} affects {v['package']} {v['version']}.",
            line_number=None,
            code_snippet=None,
            suggestion=f"Upgrade {v['package']} (fixed in: {fix}).",
            auto_fixable=False,
            fix_code=None,
            agent="DependencyAudit",
            confidence=0.9,
            cwe_id=None,
            owasp_category="A06:2021",
        ))
    return findings


def _perform_review(code: str, filename: str, language: str, requirements: str = None) -> dict:
    static = run_static_analysis(code, language, requirements)
    ast_info = analyze_ast(code, language)
    custom_findings = _rule_engine.evaluate(code, ast_info, filename, language)
    agent_results = _orchestrator.run(code, static, ast_info, language)

    findings = agent_results["final_findings"]
    findings.extend(_secret_findings(static))
    findings.extend(_cve_findings(static))

    for cr in custom_findings:
        findings.append(Finding(
            id=cr["rule_id"],
            severity=cr["severity"],
            category="custom",
            title=cr["title"],
            description=cr["description"],
            line_number=cr.get("line_number"),
            code_snippet=None,
            suggestion=cr["suggestion"],
            auto_fixable=False,
            fix_code=None,
            agent="CustomRules",
            confidence=1.0,
        ))

    counts = {
        "total": len(findings),
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity in ("LOW", "INFO")),
        "auto_fixable": sum(1 for f in findings if f.auto_fixable),
    }
    agent_results["counts"] = counts

    health = compute_health_score(counts, ast_info, static)
    pipeline = run_cicd_pipeline(static, agent_results, ast_info)

    return {
        "filename": filename,
        "language": language,
        "health_score": health,
        "pipeline": {
            "decision": pipeline["decision"],
            "message": pipeline["message"],
            "gates": [g.to_dict() for g in pipeline["gates"]],
            "passed": pipeline["passed"],
            "warned": pipeline["warned"],
            "blocked": pipeline["blocked"],
        },
        "counts": counts,
        "arbitration": {
            "risk_grade": agent_results["arbitration"].get("risk_grade", "?"),
            "overall_summary": agent_results["arbitration"].get("overall_summary", ""),
            "final_verdict": agent_results["arbitration"].get("final_verdict", "WARN"),
        },
        "findings": [f.to_dict() for f in findings],
        "static_summary": static.get("_summary", {}),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model": settings.groq_model,
        "github_enabled": bool(settings.github_token),
    })


@app.route("/api/languages")
def languages():
    seen = {}
    for ext, lang in LANGUAGE_MAP.items():
        seen.setdefault(lang, ext)
    return jsonify({"languages": sorted(seen.keys()), "extensions": LANGUAGE_MAP})


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "empty filename"}), 400

    raw = f.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "file exceeds 1 MB limit"}), 413

    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        code = raw.decode("latin-1")

    return jsonify({
        "filename": f.filename,
        "language": get_language(f.filename),
        "code": code,
    })


@app.route("/api/review", methods=["POST"])
def review():
    if not settings.groq_api_key:
        return jsonify({"error": "GROQ_API_KEY is not configured"}), 503

    data = request.get_json(silent=True)
    if not data or not data.get("code", "").strip():
        return jsonify({"error": "code is required"}), 400

    code = data["code"]
    filename = data.get("filename", "code.py")
    language = data.get("language") or get_language(filename)
    requirements = data.get("requirements")

    try:
        return jsonify(_perform_review(code, filename, language, requirements))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/autofix", methods=["POST"])
def autofix():
    data = request.get_json(silent=True)
    if not data or not data.get("code", "").strip():
        return jsonify({"error": "code is required"}), 400

    code = data["code"]
    filename = data.get("filename", "code.py")
    language = data.get("language") or get_language(filename)
    raw_findings = data.get("findings", [])

    findings = [
        Finding(
            id=f.get("id", ""),
            severity=f.get("severity", "MEDIUM"),
            category=f.get("category", "general"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            line_number=f.get("line_number"),
            code_snippet=f.get("code_snippet"),
            suggestion=f.get("suggestion", ""),
            auto_fixable=bool(f.get("auto_fixable", False)),
            fix_code=f.get("fix_code"),
            agent=f.get("agent", ""),
            confidence=float(f.get("confidence", 0.7)),
        )
        for f in raw_findings
    ]

    result = apply_fixes(code, findings, filename, language)
    return jsonify(result)


@app.route("/api/review-pr", methods=["POST"])
def review_pr():
    if not settings.groq_api_key:
        return jsonify({"error": "GROQ_API_KEY is not configured"}), 503
    if not settings.github_token:
        return jsonify({"error": "GITHUB_TOKEN is not configured"}), 503

    data = request.get_json(silent=True)
    pr_url = (data or {}).get("pr_url", "").strip()
    post_comment = bool((data or {}).get("post_comment", True))
    if not pr_url:
        return jsonify({"error": "pr_url is required"}), 400

    try:
        files = gh.fetch_pr_files(pr_url)
    except gh.GitHubError as e:
        return jsonify({"error": str(e)}), 400

    if not files:
        return jsonify({"error": "no reviewable source files found in this PR"}), 422

    reviews = []
    for f in files:
        try:
            reviews.append(_perform_review(f["code"], f["filename"], f["language"]))
        except Exception:
            continue

    if not reviews:
        return jsonify({"error": "review failed for all files"}), 500

    comment_body = gh.build_pr_comment(reviews)
    posted = False
    post_error = None
    if post_comment:
        try:
            posted = gh.post_pr_comment(pr_url, comment_body)
        except gh.GitHubError as e:
            post_error = str(e)

    overall = "PASS"
    for r in reviews:
        d = r["pipeline"]["decision"]
        if d == "BLOCK":
            overall = "BLOCK"
            break
        if d == "WARN" and overall != "BLOCK":
            overall = "WARN"

    return jsonify({
        "pr_url": pr_url,
        "overall_decision": overall,
        "files_reviewed": len(reviews),
        "comment_posted": posted,
        "post_error": post_error,
        "comment_markdown": comment_body,
        "reviews": reviews,
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
