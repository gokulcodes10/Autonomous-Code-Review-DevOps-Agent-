import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    complexity_threshold: int = int(os.getenv("COMPLEXITY_THRESHOLD", "10"))
    max_high_severity: int = int(os.getenv("MAX_HIGH_SEVERITY", "3"))
    max_tokens: int = int(os.getenv("MAX_TOKENS", "2048"))
    max_code_chars: int = int(os.getenv("MAX_CODE_CHARS", "4000"))
    agent_retry_limit: int = int(os.getenv("AGENT_RETRY_LIMIT", "2"))


settings = Settings()
