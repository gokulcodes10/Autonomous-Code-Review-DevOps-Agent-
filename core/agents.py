import json
import re
import time
from typing import List

from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from core.config import settings
from core.models import Finding, AgentResult, ESCALATION

_SCHEMA = (
    '{"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","title":"...",'
    '"description":"...","line_number":null,'
    '"code_snippet":"exact snippet 5 lines max",'
    '"suggestion":"...","auto_fixable":false,"fix_code":null,'
    '"confidence":0.85,"cwe_id":"CWE-XX","owasp_category":"AXX:2021"}'
)


def _get_llm() -> ChatGroq:
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=settings.groq_model,
        temperature=0.05,
        max_tokens=settings.max_tokens,
    )


def _truncate(text: str) -> str:
    if len(text) <= settings.max_code_chars:
        return text
    h = settings.max_code_chars // 2
    return text[:h] + f"\n# ... [{len(text) - settings.max_code_chars} chars truncated]\n" + text[-h:]


def _parse(text: str) -> dict:
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text).strip()

    depth, start = 0, -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                candidate = text[start:i + 1]
                try:
                    parsed = json.loads(candidate)
                    if "findings" in parsed or "fixes" in parsed or "valid_finding_ids" in parsed:
                        return parsed
                except Exception:
                    pass
                start = -1

    m = re.search(r'"findings"\s*:\s*(\[.*?\])', text, re.DOTALL)
    if m:
        try:
            return {"findings": json.loads(m.group(1)), "summary": "", "verdict": "WARN"}
        except Exception:
            pass

    return {"findings": [], "summary": "parse error", "verdict": "WARN"}


def _make_findings(data: dict, category: str, agent_name: str) -> List[Finding]:
    prefix_map = {
        "security": "SEC", "quality": "QUA", "performance": "PERF",
        "documentation": "DOC", "type_safety": "TYPE",
    }
    prefix = prefix_map.get(category, "GEN")
    findings = []
    for i, f in enumerate(data.get("findings", [])[:12]):
        if not f.get("title"):
            continue
        findings.append(Finding(
            id=f"{prefix}-{i + 1:03d}-{agent_name[:3].upper()}",
            severity=f.get("severity", "MEDIUM"),
            category=category,
            title=f.get("title", ""),
            description=f.get("description", ""),
            line_number=f.get("line_number"),
            code_snippet=f.get("code_snippet"),
            suggestion=f.get("suggestion", ""),
            auto_fixable=bool(f.get("auto_fixable", False)),
            fix_code=f.get("fix_code"),
            agent=agent_name,
            confidence=float(f.get("confidence", 0.7)),
            cwe_id=f.get("cwe_id"),
            owasp_category=f.get("owasp_category"),
        ))
    return findings


class BaseReviewAgent:
    NAME = ""
    SYSTEM = ""
    CATEGORY = ""

    def __init__(self, llm: ChatGroq):
        self._chain = (
            ChatPromptTemplate.from_messages([
                ("system", self.SYSTEM),
                ("human", "{input}"),
            ])
            | llm
        )

    def _call(self, prompt: str) -> str:
        for attempt in range(settings.agent_retry_limit):
            try:
                response = self._chain.invoke({"input": _truncate(prompt)})
                return response.content
            except Exception:
                if attempt < settings.agent_retry_limit - 1:
                    time.sleep(2)
        return '{"findings":[],"summary":"error","verdict":"WARN"}'

    def analyze(self, code: str, static: dict, ast_info: dict, language: str = "python") -> AgentResult:
        raise NotImplementedError


class SecurityAuditorAgent(BaseReviewAgent):
    NAME = "SecurityAuditor"
    CATEGORY = "security"
    SYSTEM = (
        "You are an OWASP-certified security engineer reviewing code in the language "
        "the user specifies. Find ALL vulnerabilities relevant to that language: "
        "injection, broken auth, hardcoded secrets, insecure deserialization, SSRF, "
        "path traversal, command injection, buffer overflows, use-after-free, integer "
        "overflows, unsafe memory access, race conditions, CWE-classified weaknesses. "
        "Respond ONLY with a single valid JSON object."
    )

    def analyze(self, code: str, static: dict, ast_info: dict, language: str = "python") -> AgentResult:
        bandit = json.dumps(static['bandit']['issues'][:8], indent=2) if static['bandit']['issues'] else "none"
        prompt = (
            f"Security-audit this {language} code.\n\n"
            f"CODE:\n```{language}\n{code}\n```\n\n"
            f"STATIC SCANNER ISSUES:\n{bandit}\n\n"
            f'Return ONLY: {{"findings":[{_SCHEMA}],'
            f'"summary":"2-3 sentences","verdict":"PASS|WARN|BLOCK"}}'
        )
        d = _parse(self._call(prompt))
        return AgentResult(self.NAME, _make_findings(d, self.CATEGORY, self.NAME),
                           d.get("summary", ""), d.get("verdict", "WARN"))


class CodeQualityAgent(BaseReviewAgent):
    NAME = "CodeQualityReviewer"
    CATEGORY = "quality"
    SYSTEM = (
        "You are a principal engineer. Review for SOLID violations, design smells, "
        "god classes, long methods, feature envy, dead code, and idioms specific to "
        "the language under review. Respond ONLY with a single valid JSON object."
    )

    def analyze(self, code: str, static: dict, ast_info: dict, language: str = "python") -> AgentResult:
        prompt = (
            f"Review code quality of this {language} code.\n\n"
            f"CODE:\n```{language}\n{code}\n```\n\n"
            f"HIGH COMPLEXITY FUNCTIONS: {json.dumps(ast_info.get('high_complexity_functions', {}))}\n"
            f"DEAD CODE: {ast_info.get('potentially_dead_code', [])}\n\n"
            f'Return ONLY: {{"findings":[{_SCHEMA}],'
            f'"summary":"2-3 sentences","verdict":"PASS|WARN|BLOCK"}}'
        )
        d = _parse(self._call(prompt))
        return AgentResult(self.NAME, _make_findings(d, self.CATEGORY, self.NAME),
                           d.get("summary", ""), d.get("verdict", "PASS"))


class PerformanceAnalystAgent(BaseReviewAgent):
    NAME = "PerformanceAnalyst"
    CATEGORY = "performance"
    SYSTEM = (
        "You are a performance expert. Find O(n²/n³) algorithms, N+1 DB queries, "
        "memory leaks, redundant computation, missing caching, unnecessary allocations, "
        "and language-specific performance pitfalls. "
        "Always provide the improved code snippet in fix_code. "
        "Respond ONLY with a single valid JSON object."
    )

    def analyze(self, code: str, static: dict, ast_info: dict, language: str = "python") -> AgentResult:
        prompt = (
            f"Find performance issues in this {language} code.\n\n"
            f"CODE:\n```{language}\n{code}\n```\n\n"
            f"COMPLEXITY MAP: {json.dumps(ast_info.get('complexity', {}))}\n\n"
            f'Return ONLY: {{"findings":[{_SCHEMA}],'
            f'"summary":"2-3 sentences","verdict":"PASS|WARN|BLOCK"}}'
        )
        d = _parse(self._call(prompt))
        return AgentResult(self.NAME, _make_findings(d, self.CATEGORY, self.NAME),
                           d.get("summary", ""), d.get("verdict", "PASS"))


class CriticAgent:
    NAME = "CriticAgent"
    SYSTEM = (
        "You are a principal engineer doing final code review arbitration. "
        "Remove false positives, escalate issues confirmed by 2+ agents, "
        "assign an overall risk grade A-F. Be strict but fair. "
        "Respond ONLY with a single valid JSON object."
    )

    def __init__(self, llm: ChatGroq):
        self._chain = (
            ChatPromptTemplate.from_messages([
                ("system", self.SYSTEM),
                ("human", "{input}"),
            ])
            | llm
        )

    def arbitrate(self, code: str, results: List[AgentResult], language: str = "python") -> dict:
        all_findings = [
            {
                "id": f.id,
                "agent": f.agent,
                "severity": f.severity,
                "title": f.title,
                "description": f.description[:80],
            }
            for r in results for f in r.findings
        ][:40]

        prompt = (
            f"Arbitrate {len(all_findings)} findings from multiple agents for this {language} code.\n\n"
            f"CODE SNIPPET:\n```{language}\n{code[:1000]}\n```\n\n"
            f"FINDINGS:\n{json.dumps(all_findings, indent=2)}\n\n"
            f'Return ONLY: {{'
            f'"valid_finding_ids":["all genuine finding ids"],'
            f'"escalated_finding_ids":["ids confirmed by 2+ agents"],'
            f'"false_positive_ids":["ids that are wrong"],'
            f'"final_verdict":"PASS|WARN|BLOCK",'
            f'"overall_summary":"2-3 sentences for the developer",'
            f'"risk_grade":"A|B|C|D|F"}}'
        )
        try:
            response = self._chain.invoke({"input": _truncate(prompt)})
            return _parse(response.content)
        except Exception:
            return {
                "valid_finding_ids": [f["id"] for f in all_findings],
                "escalated_finding_ids": [],
                "false_positive_ids": [],
                "final_verdict": "WARN",
                "overall_summary": "Review completed with errors.",
                "risk_grade": "C",
            }


class ReviewOrchestrator:
    def __init__(self):
        llm = _get_llm()
        self._agents: List[BaseReviewAgent] = [
            SecurityAuditorAgent(llm),
            CodeQualityAgent(llm),
            PerformanceAnalystAgent(llm),
        ]
        self._critic = CriticAgent(llm)

    def run(self, code: str, static: dict, ast_info: dict, language: str = "python") -> dict:
        all_results: List[AgentResult] = []
        all_findings: List[Finding] = []

        for agent in self._agents:
            try:
                result = agent.analyze(code, static, ast_info, language)
                all_results.append(result)
                all_findings.extend(result.findings)
            except Exception:
                pass

        arb = self._critic.arbitrate(code, all_results, language)

        valid_ids = set(arb.get("valid_finding_ids", [f.id for f in all_findings]))
        escalate_ids = set(arb.get("escalated_finding_ids", []))
        fp_ids = set(arb.get("false_positive_ids", []))
        use_allowlist = bool(valid_ids)

        final: List[Finding] = []
        for f in all_findings:
            if f.id in fp_ids:
                continue
            if use_allowlist and f.id not in valid_ids:
                continue
            if f.id in escalate_ids:
                f.severity = ESCALATION.get(f.severity, f.severity)
            final.append(f)

        counts = {
            "total": len(final),
            "CRITICAL": sum(1 for f in final if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in final if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in final if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in final if f.severity in ("LOW", "INFO")),
            "auto_fixable": sum(1 for f in final if f.auto_fixable),
            "fp_removed": len(fp_ids),
            "escalated": len(escalate_ids),
        }

        return {
            "agent_results": all_results,
            "final_findings": final,
            "arbitration": arb,
            "counts": counts,
        }
