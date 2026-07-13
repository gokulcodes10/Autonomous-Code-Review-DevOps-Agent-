import math
import re

_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("GitHub Fine-grained Token", re.compile(r"github_pat_[0-9A-Za-z_]{60,}")),
    ("Groq API Key", re.compile(r"gsk_[0-9A-Za-z]{40,}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Key", re.compile(r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{20,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Generic Secret Assignment",
     re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|placeholder|xxxx|<.*>|changeme|dummy|test[_-]?key|insert[_-]?)"
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def scan_secrets(code: str) -> dict:
    found = []
    for line_no, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        matched_line = False
        for name, pattern in _PATTERNS:
            is_generic = name == "Generic Secret Assignment"
            if is_generic and matched_line:
                continue
            for match in pattern.finditer(line):
                value = match.group(0)
                if _PLACEHOLDER.search(value):
                    continue
                matched_line = True
                found.append({
                    "type": name,
                    "line_number": line_no,
                    "preview": value[:6] + "…" + value[-4:] if len(value) > 12 else "***",
                    "entropy": round(_shannon_entropy(value), 2),
                })
                break
    return {"secrets": found}
