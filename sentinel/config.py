from __future__ import annotations
import os
from dotenv import load_dotenv
from dataclasses import dataclass
from pathlib import Path


def _load_env() -> None:
    home_hint = os.getenv("SENTINEL_HOME")
    candidates = []
    if home_hint:
        candidates.append(Path(home_hint).expanduser() / ".env")
    candidates.append(_project_root() / ".env")
    candidates.append(Path.cwd() / ".env")
    for candidate in candidates:
        if candidate.exists():
            load_dotenv(candidate, override=False)
            break


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _root() -> Path:
    value = os.getenv("SENTINEL_HOME")
    return Path(value).expanduser().resolve() if value else _project_root()


def _path_from_env(name: str, default: Path) -> Path:
    value = os.getenv(name)
    if not value:
        return default
    if value.startswith("file://"):
        value = value.removeprefix("file://")
    return Path(value).expanduser().resolve()


@dataclass(frozen=True)
class Settings:
    home: Path
    duckdb_path: Path
    coral_data_dir: Path
    github_webhook_secret: str
    github_token: str
    github_access_tier: str
    github_org: str
    supply_chain_provider: str
    socket_api_key: str
    socket_org_slug: str
    phylum_api_key: str
    discord_webhook_url: str
    slack_bot_token: str
    slack_channel_id: str
    jira_base_url: str
    jira_email: str
    jira_api_token: str
    jira_project_key: str
    llm_provider: str
    gemini_api_key: str
    anthropic_api_key: str
    ollama_base_url: str
    alert_threshold: int
    triage_buffer_seconds: int
    debounce_window_seconds: int
    otlp_endpoint: str
    discord_application_id: str = ""
    discord_public_key: str = ""
    discord_bot_token: str = ""
    discord_security_role_id: str = ""
    discord_guild_id: str = ""
    core_maintainers: set[str] | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        _load_env()
        home = _root()
        runtime = home / "runtime"
        return cls(
            home=home,
            duckdb_path=_path_from_env("SENTINEL_DUCKDB_PATH", runtime / "sentinel.duckdb"),
            coral_data_dir=_path_from_env("SENTINEL_CORAL_DATA_DIR", runtime / "coral-data"),
            github_webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
            github_token=os.getenv("GITHUB_TOKEN", ""),
            github_access_tier=os.getenv("GITHUB_ACCESS_TIER", "free").lower(),
            github_org=os.getenv("GITHUB_ORG", ""),
            supply_chain_provider=os.getenv("SUPPLY_CHAIN_PROVIDER", "socket").lower(),
            socket_api_key=os.getenv("SOCKET_API_KEY", ""),
            socket_org_slug=os.getenv("SOCKET_ORG_SLUG", ""),
            phylum_api_key=os.getenv("PHYLUM_API_KEY", ""),
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),
            discord_application_id=os.getenv("DISCORD_APPLICATION_ID", ""),
            discord_public_key=os.getenv("DISCORD_PUBLIC_KEY", ""),
            discord_bot_token=os.getenv("DISCORD_BOT_TOKEN", ""),
            discord_security_role_id=os.getenv("DISCORD_SECURITY_ROLE_ID", ""),
            discord_guild_id=os.getenv("DISCORD_GUILD_ID", ""),
            slack_bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
            slack_channel_id=os.getenv("SLACK_CHANNEL_ID", ""),
            jira_base_url=os.getenv("JIRA_BASE_URL", "").rstrip("/"),
            jira_email=os.getenv("JIRA_EMAIL", ""),
            jira_api_token=os.getenv("JIRA_API_TOKEN", ""),
            jira_project_key=os.getenv("JIRA_PROJECT_KEY", ""),
            llm_provider=os.getenv("LLM_PROVIDER", "gemini").lower(),
            gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            alert_threshold=int(os.getenv("ALERT_THRESHOLD", "60")),
            triage_buffer_seconds=int(os.getenv("TRIAGE_BUFFER_SECONDS", "180")),
            debounce_window_seconds=int(os.getenv("DEBOUNCE_WINDOW_SECONDS", "10")),
            otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
            core_maintainers={item.strip() for item in os.getenv("CORE_MAINTAINERS", "").split(",") if item.strip()},
        )
