# CI/CD Code Review Agent

A code review tool that reads a file (or a whole GitHub pull request) and tells you whether it's safe to merge. It runs the usual static analyzers, scans for hardcoded secrets, then hands the code to a small panel of LLM agents that argue about it before a "critic" agent settles the final verdict. The result is a PASS / WARN / BLOCK decision plus a health grade, the same way a CI gate would behave.

It ships as a single Flask app with a dark web UI, and it's set up to deploy to Vercel as a serverless function.

## What it actually does

When you submit code, a few things happen in sequence:

1. **Static analysis** — Bandit (Python security linting) and Radon (cyclomatic complexity) run on Python files. For other languages these are skipped, since the tools don't apply.
2. **Secret scanning** — a regex + Shannon-entropy pass looks for AWS keys, GitHub/Groq/OpenAI tokens, Stripe keys, private key blocks, JWTs, and generic `password = "..."` assignments. Obvious placeholders like `your_key_here` are ignored so you don't get flooded with false alarms.
3. **Dependency audit** — if you paste a `requirements.txt`, it's run through `pip-audit` to flag known CVEs.
4. **AST / structure analysis** — for Python it uses the real `ast` module to find functions without docstrings, missing type hints, dead code, and oversized classes. For other languages it falls back to regex-based function detection (rougher, but workable).
5. **Custom rules** — a small built-in rule set catches things like bare `except:`, `print()` left in production, `gets()`/`strcpy()` in C/C++, `.unwrap()` in Rust, `console.log` in JS, and so on. Rules are language-aware.
6. **The agents** — three LLM reviewers (Security, Code Quality, Performance) look at the code independently, each returning structured findings. A fourth **Critic** agent then arbitrates: it drops false positives, escalates anything two or more agents agreed on, and assigns an overall A–F risk grade.
7. **Scoring + gates** — everything feeds into a 0–100 health score and a set of pipeline gates (secrets, CVEs, security, Bandit, complexity, AI consensus). If any gate blocks, the whole pipeline blocks.

The LLM work runs on Groq (default model `llama-3.3-70b-versatile`) through LangChain.

## Endpoints

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | The web interface |
| `/api/health` | GET | Quick check — model name, whether GitHub is wired up |
| `/api/languages` | GET | Supported languages and their file extensions |
| `/api/upload` | POST | Upload a file (≤ 1 MB), get back its detected language and contents |
| `/api/review` | POST | Run the full review on a chunk of code |
| `/api/autofix` | POST | Apply any auto-fixable findings and return a diff |
| `/api/review-pr` | POST | Pull a GitHub PR's changed files, review them, optionally post a summary comment |

A `/api/review` call expects JSON like:

```json
{
  "code": "def foo(): ...",
  "filename": "example.py",
  "language": "python",
  "requirements": "flask==2.0.0\n..."
}
```

`language` and `requirements` are optional — language is inferred from the filename if you leave it out.

## Languages

Python gets the full treatment (Bandit, Radon, real AST). These others are reviewed by the LLM agents and custom rules, with regex-based structure detection: C, C++, Rust, Go, JavaScript, TypeScript, Java, C#, Ruby, PHP, Swift, Kotlin, Bash, Lua, Scala, R.

## Running it locally

You'll need Python 3.11 and a Groq API key. The static tools (`bandit`, `pip-audit`) are installed as part of the requirements but are invoked as command-line subprocesses, so they need to be on your `PATH`.

```bash
pip install -r requirements.txt
# create a .env file in the project root (see the table below)
python api/index.py
```

That starts the dev server on `http://localhost:5000`.

### Environment variables

Copy these into a `.env` file in the project root:

| Variable | Default | Notes |
|----------|---------|-------|
| `GROQ_API_KEY` | — | Required. The review endpoints return 503 without it. |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Any Groq-hosted model |
| `GITHUB_TOKEN` | — | Only needed for `/api/review-pr` |
| `COMPLEXITY_THRESHOLD` | `10` | Cyclomatic complexity above this is flagged |
| `MAX_HIGH_SEVERITY` | `3` | More HIGH findings than this triggers a WARN gate |
| `MAX_TOKENS` | `2048` | Per-agent response limit |
| `MAX_CODE_CHARS` | `4000` | Code longer than this gets truncated (head + tail) before going to the LLM |
| `AGENT_RETRY_LIMIT` | `2` | Retries per agent on an API error |

The `.env` file is gitignored, so your keys won't get committed.

## Reviewing a GitHub PR

With `GITHUB_TOKEN` set, POST a PR URL to `/api/review-pr`:

```json
{
  "pr_url": "https://github.com/owner/repo/pull/42",
  "post_comment": true
}
```

It fetches up to 10 changed source files, reviews each one, and (if `post_comment` is true) posts a Markdown summary table back on the PR with the verdict, grade, and top findings per file. The overall decision is the worst decision across all files — one BLOCK blocks the lot.

## Deploying to Vercel

`vercel.json` routes everything to `api/index.py` as a single serverless function with a 60-second max duration. Push the repo to a Vercel project and set the same environment variables in the dashboard. Keep in mind the serverless runtime may not have `bandit` or `pip-audit` available on `PATH` — those steps degrade gracefully and just return empty results when the binaries aren't found, so the LLM review and secret scan still run.

## Notes and limits

- Uploads are capped at 1 MB; the LLM only sees the first and last ~2000 characters of anything longer.
- The agents return JSON, but LLMs being LLMs, the parser is deliberately forgiving — it digs the first valid JSON object out of the response and falls back to a WARN verdict if it can't.
- Auto-fix is conservative. It only touches findings the agents explicitly marked auto-fixable, checks the patched Python still parses, and rejects anything that balloons the file size. You get a unified diff back, not a silently rewritten file.
- This is a review aid, not a guarantee. A PASS means nothing obvious tripped the gates — it doesn't mean the code is correct.

## Project layout

```
api/
  index.py            Flask app + all routes
core/
  agents.py           The LLM reviewers and the critic/orchestrator
  analysis.py         Bandit, Radon, pip-audit, AST + regex structure analysis
  secrets.py          Secret scanning (regex + entropy)
  rules.py            Custom rule engine
  pipeline.py         Health score + CI/CD gate logic
  github_integration.py   PR fetching and comment building
  autofix.py          Diff-based fix application
  models.py           Dataclasses, rule config, scoring weights
  config.py           Settings loaded from env
templates/
  index.html          The web UI
```
