from pathlib import Path

from sentinel.config import Settings
from sentinel.integrations.jira import JiraClient


def test_jira_client_builds_project_scoped_approval_jql():
    settings = Settings(
        home=Path("."),
        duckdb_path=Path("runtime/sentinel.duckdb"),
        coral_data_dir=Path("runtime/coral-data"),
        github_webhook_secret="",
        github_token="",
        github_access_tier="free",
        github_org="",
        supply_chain_provider="socket",
        socket_api_key="",
        socket_org_slug="",
        phylum_api_key="",
        discord_webhook_url="",
        slack_bot_token="",
        slack_channel_id="",
        jira_base_url="https://example.atlassian.net",
        jira_email="security@example.com",
        jira_api_token="token",
        jira_project_key="SEC",
        llm_provider="gemini",
        gemini_api_key="",
        anthropic_api_key="",
        ollama_base_url="http://localhost:11434",
        alert_threshold=60,
        triage_buffer_seconds=180,
        debounce_window_seconds=10,
        otlp_endpoint="",
    )

    assert JiraClient(settings)._approval_jql("org/repo") == 'project = SEC AND summary ~ "org/repo" ORDER BY created DESC'
