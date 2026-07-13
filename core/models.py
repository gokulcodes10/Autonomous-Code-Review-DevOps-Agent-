from dataclasses import dataclass
from typing import Optional, List
from enum import Enum


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    description: str
    line_number: Optional[int]
    code_snippet: Optional[str]
    suggestion: str
    auto_fixable: bool
    fix_code: Optional[str]
    agent: str
    confidence: float
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "suggestion": self.suggestion,
            "auto_fixable": self.auto_fixable,
            "fix_code": self.fix_code,
            "agent": self.agent,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


@dataclass
class AgentResult:
    agent_name: str
    findings: List[Finding]
    summary: str
    verdict: str


class GateStatus(Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class Gate:
    name: str
    status: GateStatus
    message: str

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status.value, "message": self.message}


SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
ESCALATION = {
    "INFO": "LOW", "LOW": "MEDIUM", "MEDIUM": "HIGH",
    "HIGH": "CRITICAL", "CRITICAL": "CRITICAL",
}

CUSTOM_RULES = {
    "rules": [
        {"id": "CR-001", "name": "Max Function Lines", "type": "max_function_lines",
         "threshold": 50, "severity": "MEDIUM", "enabled": True, "languages": ["python"]},
        {"id": "CR-002", "name": "No print() in production", "type": "forbidden_pattern",
         "pattern": "print(", "severity": "LOW", "enabled": True, "languages": ["python"]},
        {"id": "CR-003", "name": "No bare except", "type": "forbidden_pattern",
         "pattern": "except:", "severity": "MEDIUM", "enabled": True, "languages": ["python"]},
        {"id": "CR-005", "name": "Max class methods", "type": "max_class_methods",
         "threshold": 20, "severity": "MEDIUM", "enabled": True, "languages": ["python"]},
        {"id": "CR-010", "name": "No TODO comments", "type": "forbidden_pattern",
         "pattern": "TODO", "severity": "INFO", "enabled": True},
        {"id": "CR-011", "name": "No FIXME comments", "type": "forbidden_pattern",
         "pattern": "FIXME", "severity": "INFO", "enabled": True},
        {"id": "CR-020", "name": "Avoid gets() (buffer overflow)", "type": "forbidden_pattern",
         "pattern": "gets(", "severity": "HIGH", "enabled": True, "languages": ["c", "cpp"]},
        {"id": "CR-021", "name": "Prefer snprintf over sprintf", "type": "forbidden_pattern",
         "pattern": "sprintf(", "severity": "MEDIUM", "enabled": True, "languages": ["c", "cpp"]},
        {"id": "CR-022", "name": "Use strncpy over strcpy", "type": "forbidden_pattern",
         "pattern": "strcpy(", "severity": "MEDIUM", "enabled": True, "languages": ["c", "cpp"]},
        {"id": "CR-030", "name": "Avoid unwrap() in production", "type": "forbidden_pattern",
         "pattern": ".unwrap()", "severity": "LOW", "enabled": True, "languages": ["rust"]},
        {"id": "CR-031", "name": "Avoid unsafe blocks", "type": "forbidden_pattern",
         "pattern": "unsafe ", "severity": "MEDIUM", "enabled": True, "languages": ["rust"]},
        {"id": "CR-040", "name": "Check error returns", "type": "forbidden_pattern",
         "pattern": "_ = ", "severity": "INFO", "enabled": True, "languages": ["go"]},
        {"id": "CR-050", "name": "No console.log in production", "type": "forbidden_pattern",
         "pattern": "console.log", "severity": "LOW", "enabled": True,
         "languages": ["javascript", "typescript"]},
        {"id": "CR-051", "name": "Avoid == (use ===)", "type": "forbidden_pattern",
         "pattern": " == ", "severity": "LOW", "enabled": True,
         "languages": ["javascript", "typescript"]},
    ]
}

HEALTH_WEIGHTS = {
    "CRITICAL": -20, "HIGH": -10, "MEDIUM": -3, "LOW": -1,
    "secret": -25, "complexity_penalty": -2,
    "undocumented_penalty": -0.5, "type_hint_bonus": 0.5,
}
