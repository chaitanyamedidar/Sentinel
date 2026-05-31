from pathlib import Path

import pytest

from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore
from sentinel.demo import reset_demo_data, seed_demo_scenario


@pytest.mark.anyio
async def test_demo_reset_removes_demo_rows(tmp_path: Path):
    settings = Settings(
        home=tmp_path,
        duckdb_path=tmp_path / "runtime" / "sentinel.duckdb",
        coral_data_dir=tmp_path / "runtime" / "coral-data",
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
        jira_base_url="",
        jira_email="",
        jira_api_token="",
        jira_project_key="",
        llm_provider="gemini",
        gemini_api_key="",
        anthropic_api_key="",
        ollama_base_url="http://localhost:11434",
        alert_threshold=60,
        triage_buffer_seconds=180,
        debounce_window_seconds=10,
        otlp_endpoint="",
    )
    store = SentinelStore(settings)
    await store.init()
    await seed_demo_scenario(store, "supply_chain")

    assert await store.fetch_scalar("SELECT COUNT(*) FROM alert_events WHERE commit_sha LIKE 'demo%'") == 1

    deleted = await reset_demo_data(store)

    assert deleted["alert_events"] == 1
    assert await store.fetch_scalar("SELECT COUNT(*) FROM alert_events WHERE commit_sha LIKE 'demo%'") == 0
    assert "demo001" not in (settings.coral_data_dir / "alert_events.jsonl").read_text()
