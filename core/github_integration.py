from typing import List, Optional, Tuple

from github import Auth, Github, GithubException

from core.analysis import get_language
from core.config import settings

_REVIEWABLE = {
    "python", "c", "cpp", "rust", "go", "javascript", "typescript",
    "java", "csharp", "ruby", "php", "swift", "kotlin",
}


class GitHubError(Exception):
    pass


def _client() -> Github:
    if not settings.github_token:
        raise GitHubError("GITHUB_TOKEN is not configured")
    return Github(auth=Auth.Token(settings.github_token))


def parse_pr_url(url: str) -> Tuple[str, str, int]:
    parts = url.rstrip("/").split("/")
    try:
        owner, repo, number = parts[-4], parts[-3], int(parts[-1])
    except (IndexError, ValueError):
        raise GitHubError("invalid PR URL — expected .../owner/repo/pull/<number>")
    return owner, repo, number


def fetch_pr_files(url: str, max_files: int = 10) -> List[dict]:
    owner, repo_name, number = parse_pr_url(url)
    gh = _client()
    try:
        repo = gh.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(number)
    except GithubException as e:
        raise GitHubError(f"could not load PR: {e.data.get('message', e) if e.data else e}")

    files = []
    for pf in pr.get_files():
        if pf.status == "removed":
            continue
        language = get_language(pf.filename)
        if language not in _REVIEWABLE:
            continue
        try:
            content = repo.get_contents(pf.filename, ref=pr.head.sha)
            code = content.decoded_content.decode("utf-8")
        except Exception:
            continue
        files.append({"filename": pf.filename, "language": language, "code": code})
        if len(files) >= max_files:
            break

    return files


def post_pr_comment(url: str, body: str) -> bool:
    owner, repo_name, number = parse_pr_url(url)
    gh = _client()
    try:
        repo = gh.get_repo(f"{owner}/{repo_name}")
        pr = repo.get_pull(number)
        pr.create_issue_comment(body)
        return True
    except GithubException as e:
        raise GitHubError(f"could not post comment: {e.data.get('message', e) if e.data else e}")


def build_pr_comment(reviews: List[dict]) -> str:
    overall = "PASS"
    for r in reviews:
        decision = r["pipeline"]["decision"]
        if decision == "BLOCK":
            overall = "BLOCK"
            break
        if decision == "WARN" and overall != "BLOCK":
            overall = "WARN"

    emoji = {"PASS": "✅", "WARN": "⚠️", "BLOCK": "🚫"}[overall]
    lines = [
        f"## {emoji} DRDO Code Review — {overall}",
        "",
        f"Reviewed **{len(reviews)} file(s)** across the changed set.",
        "",
        "| File | Lang | Decision | Grade | Health | Crit | High | Med | Low |",
        "|------|------|----------|-------|--------|------|------|-----|-----|",
    ]
    for r in reviews:
        c = r["counts"]
        lines.append(
            f"| `{r['filename']}` | {r['language']} | "
            f"{r['pipeline']['decision']} | {r['health_score']['grade']} | "
            f"{r['health_score']['score']}/100 | "
            f"{c.get('CRITICAL', 0)} | {c.get('HIGH', 0)} | "
            f"{c.get('MEDIUM', 0)} | {c.get('LOW', 0)} |"
        )

    for r in reviews:
        top = sorted(
            r["findings"],
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f["severity"], 5),
        )[:5]
        if not top:
            continue
        lines += ["", f"### `{r['filename']}`"]
        for f in top:
            line = f" (L{f['line_number']})" if f.get("line_number") else ""
            lines.append(f"- **[{f['severity']}]** {f['title']}{line}")
            if f.get("suggestion"):
                lines.append(f"  - → {f['suggestion']}")

    lines += ["", "<sub>🤖 Autonomous DRDO Code Review Agent · Groq · LangChain</sub>"]
    return "\n".join(lines)
