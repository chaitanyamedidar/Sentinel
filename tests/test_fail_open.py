import asyncio
from pathlib import Path
from types import SimpleNamespace

import sentinel.main as main_module
from sentinel.github_client import PullRequestFiles


class FakeStore:
    def __init__(self):
        self.rows = []

    async def insert(self, table, row, lock_key=None):
        self.rows.append((table, row, lock_key))

    async def fetch_supply_chain(self, commit_sha):
        return []

    async def fetch_enriched_packages(self, commit_sha):
        return []

    async def fetch_mcp_findings(self, actor):
        return []


def test_external_enrichment_failure_does_not_abort_deterministic_alert(monkeypatch):
    store = FakeStore()
    dispatched = []
    monkeypatch.setattr(
        main_module.state,
        "settings",
        SimpleNamespace(alert_threshold=60, core_maintainers=set(), home=Path.cwd()),
    )
    monkeypatch.setattr(main_module.state, "store", store)

    async def empty_files(payload, repository, head_sha):
        return PullRequestFiles(paths=[], contents={}, patches={})

    async def empty_reviews(payload, repository):
        return []

    async def failing_enrichment(*args, **kwargs):
        raise RuntimeError("provider unavailable")

    async def dispatch(alert, repository):
        dispatched.append((alert, repository))

    monkeypatch.setattr(main_module, "_fetch_github_files", empty_files)
    monkeypatch.setattr(main_module, "_fetch_github_reviews", empty_reviews)
    monkeypatch.setattr(main_module, "scan_packages", failing_enrichment)
    monkeypatch.setattr(main_module, "scan_osv", failing_enrichment)
    monkeypatch.setattr(main_module, "enrich_packages", failing_enrichment)
    monkeypatch.setattr(main_module, "_dispatch_alert", dispatch)
    monkeypatch.setattr(main_module, "record_score", lambda *args, **kwargs: None)

    payload = {
        "action": "opened",
        "sender": {"login": "alice"},
        "repository": {"full_name": "org/repo"},
        "pull_request": {"head": {"sha": "abc1234"}, "body": "token=DEMO_FAKE_TOKEN_1234567890"},
        "sentinel_dependencies": [{"name": "demo", "version": "1.0.0", "ecosystem": "npm"}],
    }

    asyncio.run(main_module._process_event({"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d1"}, payload))

    assert any(table == "audit_events" for table, _, _ in store.rows)
    assert dispatched
    assert dispatched[0][0].vector_type == "credential_in_pr_body"
