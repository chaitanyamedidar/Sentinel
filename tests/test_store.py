import asyncio
from pathlib import Path
from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore


def test_store_writes_duckdb_and_jsonl(tmp_path: Path):
    settings = Settings.from_env().__class__(**{**Settings.from_env().__dict__, "home": tmp_path, "duckdb_path": tmp_path / "sentinel.duckdb", "coral_data_dir": tmp_path / "coral-data"})
    store = SentinelStore(settings)
    asyncio.run(store.init())
    asyncio.run(store.insert("audit_events", {"event_id":"d1","actor_login":"alice","action":"push","repository":"org/repo","head_sha":"abc","ip_address":"","created_at":"2026-05-30T00:00:00Z","raw_payload":"{}"}))
    assert (settings.coral_data_dir / "audit_events.jsonl").read_text(encoding="utf-8").strip()


def test_audit_events_include_delta_vector_columns(tmp_path: Path):
    settings = Settings.from_env().__class__(**{**Settings.from_env().__dict__, "home": tmp_path, "duckdb_path": tmp_path / "sentinel.duckdb", "coral_data_dir": tmp_path / "coral-data"})
    store = SentinelStore(settings)
    asyncio.run(store.init())
    columns = {row[1] for row in store.conn.execute("PRAGMA table_info('audit_events')").fetchall()}
    assert {
        "ci_exfiltration_detected",
        "self_hosted_first_actor",
        "force_push_after_approval",
        "unsigned_maintainer_commit",
        "action_typosquat_detected",
        "orphan_pkg_owner_change",
    } <= columns
