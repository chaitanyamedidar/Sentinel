from __future__ import annotations
import asyncio, json
from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
import duckdb
from sentinel.config import Settings

TABLE_COLUMNS = {
    "audit_events": ["event_id","actor_login","action","repository","head_sha","ip_address","created_at","raw_payload","ci_exfiltration_detected","self_hosted_first_actor","force_push_after_approval","unsigned_maintainer_commit","action_typosquat_detected","orphan_pkg_owner_change"],
    "supply_chain_findings": ["commit_sha","package_name","version","ecosystem","issue_type","severity","risk_score","provider","written_at"],
    "osv_findings": ["commit_sha","package_name","vuln_id","severity","ecosystem","written_at"],
    "enriched_packages": ["commit_sha","package_name","package_age_hours","maintainer_age_days","has_postinstall","name_edit_distance","source_repo_present","written_at"],
    "mcp_scan_findings": ["actor","skill_name","finding_type","severity","file_path","scanned_at"],
    "alert_events": ["commit_sha","actor_login","vector_type","score","severity","detection_provider","summary","created_at"],
    "brief_deliveries": ["actor","tier","sent_at","channel","status"],
    "dedup_cache": ["dedup_key","commit_sha","actor_login","vector_type","expires_at","created_at"],
    "enrichment_cache": ["cache_key","commit_sha","provider","dependency_hash","expires_at","created_at"],
}

CREATE_SQL = [
"""CREATE TABLE IF NOT EXISTS audit_events (event_id TEXT PRIMARY KEY, actor_login TEXT, action TEXT, repository TEXT, head_sha TEXT, ip_address TEXT, created_at TIMESTAMP, raw_payload TEXT, ci_exfiltration_detected BOOLEAN DEFAULT false, self_hosted_first_actor BOOLEAN DEFAULT false, force_push_after_approval BOOLEAN DEFAULT false, unsigned_maintainer_commit BOOLEAN DEFAULT false, action_typosquat_detected BOOLEAN DEFAULT false, orphan_pkg_owner_change BOOLEAN DEFAULT false)""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ci_exfiltration_detected BOOLEAN DEFAULT false""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS self_hosted_first_actor BOOLEAN DEFAULT false""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS force_push_after_approval BOOLEAN DEFAULT false""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS unsigned_maintainer_commit BOOLEAN DEFAULT false""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS action_typosquat_detected BOOLEAN DEFAULT false""",
"""ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS orphan_pkg_owner_change BOOLEAN DEFAULT false""",
"""CREATE TABLE IF NOT EXISTS supply_chain_findings (commit_sha TEXT, package_name TEXT, version TEXT, ecosystem TEXT, issue_type TEXT, severity TEXT, risk_score DOUBLE, provider TEXT, written_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS osv_findings (commit_sha TEXT, package_name TEXT, vuln_id TEXT, severity TEXT, ecosystem TEXT, written_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS enriched_packages (commit_sha TEXT, package_name TEXT, package_age_hours DOUBLE, maintainer_age_days INTEGER, has_postinstall BOOLEAN, name_edit_distance INTEGER, source_repo_present BOOLEAN, written_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS mcp_scan_findings (actor TEXT, skill_name TEXT, finding_type TEXT, severity TEXT, file_path TEXT, scanned_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS alert_events (commit_sha TEXT, actor_login TEXT, vector_type TEXT, score INTEGER, severity TEXT, detection_provider TEXT, summary TEXT, created_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS brief_deliveries (actor TEXT, tier TEXT, sent_at TIMESTAMP, channel TEXT, status TEXT)""",
"""CREATE TABLE IF NOT EXISTS dedup_cache (dedup_key TEXT PRIMARY KEY, commit_sha TEXT, actor_login TEXT, vector_type TEXT, expires_at TIMESTAMP, created_at TIMESTAMP DEFAULT now())""",
"""CREATE TABLE IF NOT EXISTS enrichment_cache (cache_key TEXT PRIMARY KEY, commit_sha TEXT, provider TEXT, dependency_hash TEXT, expires_at TIMESTAMP, created_at TIMESTAMP DEFAULT now())""",
]

class SentinelStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._connection: duckdb.DuckDBPyConnection | None = None
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @property
    def conn(self):
        if self._connection is None:
            raise RuntimeError("SentinelStore.init() must be called before use")
        return self._connection

    async def init(self) -> None:
        self.settings.duckdb_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings.coral_data_dir.mkdir(parents=True, exist_ok=True)
        self._connection = duckdb.connect(str(self.settings.duckdb_path))
        for statement in CREATE_SQL:
            self.conn.execute(statement)
        for table in TABLE_COLUMNS:
            (self.settings.coral_data_dir / f"{table}.jsonl").touch(exist_ok=True)

    async def insert(self, table: str, row: Mapping[str, Any], lock_key: str | None = None) -> None:
        if table not in TABLE_COLUMNS:
            raise ValueError(f"unknown table: {table}")
        key = lock_key or str(row.get("commit_sha") or row.get("event_id") or table)
        async with self._locks[key]:
            await asyncio.to_thread(self._insert_sync, table, dict(row))

    def _insert_sync(self, table: str, row: dict[str, Any]) -> None:
        columns = TABLE_COLUMNS[table]
        normalized = {column: _json_value(row.get(column)) for column in columns}
        placeholders = ", ".join(["?"] * len(columns))
        conflict = " OR REPLACE" if table in {"audit_events", "dedup_cache", "enrichment_cache"} else ""
        self.conn.execute(f"INSERT{conflict} INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", [normalized[c] for c in columns])
        with (self.settings.coral_data_dir / f"{table}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(normalized, default=str, separators=(",", ":")) + "\n")

    async def fetch_supply_chain(self, commit_sha: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(lambda: _rows(self.conn.execute("SELECT * FROM supply_chain_findings WHERE commit_sha = ?", [commit_sha])))

    async def fetch_enriched_packages(self, commit_sha: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(lambda: _rows(self.conn.execute("SELECT * FROM enriched_packages WHERE commit_sha = ?", [commit_sha])))

    async def fetch_mcp_findings(self, actor: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(lambda: _rows(self.conn.execute("SELECT * FROM mcp_scan_findings WHERE actor = ?", [actor])))

    async def fetch_recent(self, table: str, order_by: str, limit: int = 100) -> list[dict[str, Any]]:
        if table not in TABLE_COLUMNS:
            raise ValueError(f"unknown table: {table}")
        if order_by not in TABLE_COLUMNS[table]:
            raise ValueError(f"unknown column: {order_by}")
        safe_limit = max(1, min(int(limit), 500))
        return await asyncio.to_thread(lambda: _rows(self.conn.execute(f"SELECT * FROM {table} ORDER BY {order_by} DESC LIMIT ?", [safe_limit])))

    async def fetch_scalar(self, sql: str, params: list[Any] | None = None) -> Any:
        return await asyncio.to_thread(lambda: self.conn.execute(sql, params or []).fetchone()[0])

    async def fetch_rows(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        return await asyncio.to_thread(lambda: _rows(self.conn.execute(sql, params or [])))

    async def execute(self, sql: str, params: list[Any] | None = None) -> None:
        await asyncio.to_thread(lambda: self.conn.execute(sql, params or []))

    async def rebuild_jsonl(self) -> None:
        await asyncio.to_thread(self._rebuild_jsonl_sync)

    def _rebuild_jsonl_sync(self) -> None:
        for table in TABLE_COLUMNS:
            rows = _rows(self.conn.execute(f"SELECT * FROM {table}"))
            with (self.settings.coral_data_dir / f"{table}.jsonl").open("w", encoding="utf-8") as handle:
                for row in rows:
                    normalized = {column: _json_value(row.get(column)) for column in TABLE_COLUMNS[table]}
                    handle.write(json.dumps(normalized, default=str, separators=(",", ":")) + "\n")

    async def enrichment_cache_fresh(self, commit_sha: str, provider: str, dependency_hash: str) -> bool:
        row = await asyncio.to_thread(lambda: self.conn.execute("SELECT expires_at FROM enrichment_cache WHERE cache_key = ? AND dependency_hash = ?", [f"{commit_sha}:{provider}", dependency_hash]).fetchone())
        return bool(row and _dt(row[0]) > datetime.now(UTC))

    async def remember_enrichment(self, commit_sha: str, provider: str, dependency_hash: str) -> None:
        now = datetime.now(UTC)
        await self.insert("enrichment_cache", {"cache_key": f"{commit_sha}:{provider}", "commit_sha": commit_sha, "provider": provider, "dependency_hash": dependency_hash, "expires_at": (now + timedelta(hours=24)).isoformat(), "created_at": now.isoformat()}, lock_key=commit_sha)

    async def dedup_seen(self, commit_sha: str, actor_login: str, vector_type: str) -> bool:
        row = await asyncio.to_thread(lambda: self.conn.execute("SELECT expires_at FROM dedup_cache WHERE dedup_key = ?", [f"{commit_sha}:{actor_login}:{vector_type}"]).fetchone())
        return bool(row and _dt(row[0]) > datetime.now(UTC))

    async def remember_dedup(self, commit_sha: str, actor_login: str, vector_type: str) -> None:
        now = datetime.now(UTC)
        await self.insert("dedup_cache", {"dedup_key": f"{commit_sha}:{actor_login}:{vector_type}", "commit_sha": commit_sha, "actor_login": actor_login, "vector_type": vector_type, "expires_at": (now + timedelta(hours=24)).isoformat(), "created_at": now.isoformat()}, lock_key=commit_sha)

def _rows(result) -> list[dict[str, Any]]:
    columns = [c[0] for c in result.description or []]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]

def _json_value(value: Any) -> Any:
    return json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else value

def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
