from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from fastapi.responses import FileResponse

from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore


def dashboard_router(settings: Settings, store: SentinelStore) -> APIRouter:
    router = APIRouter()
    static_dir = Path(__file__).resolve().parent / "dashboard_static"

    @router.get("/")
    async def dashboard_home() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @router.get("/api/dashboard/summary")
    async def summary() -> dict[str, Any]:
        total_alerts = await store.fetch_scalar("SELECT COUNT(*) FROM alert_events")
        critical = await store.fetch_scalar("SELECT COUNT(*) FROM alert_events WHERE severity = 'CRITICAL'")
        high = await store.fetch_scalar("SELECT COUNT(*) FROM alert_events WHERE severity = 'HIGH'")
        vulnerabilities = await store.fetch_scalar("SELECT COUNT(*) FROM osv_findings")
        actors = await store.fetch_scalar("SELECT COUNT(DISTINCT actor_login) FROM audit_events")
        commits = await store.fetch_scalar("SELECT COUNT(DISTINCT head_sha) FROM audit_events WHERE head_sha IS NOT NULL AND head_sha != ''")
        pull_requests = await store.fetch_scalar("SELECT COUNT(*) FROM audit_events WHERE action LIKE 'pr_%'")
        sources = _source_health(settings)
        admin = await _admin_overview(store)
        return {
            "total_alerts": total_alerts,
            "critical": critical,
            "high": high,
            "vulnerabilities": vulnerabilities,
            "actors": actors,
            "commits": commits,
            "pull_requests": pull_requests,
            "milestones": len(admin["milestones"]),
            "provider": settings.supply_chain_provider,
            "source_health": sources,
            "connected_sources": sum(1 for item in sources if item["status"] == "connected"),
            "total_sources": len(sources),
        }

    @router.get("/api/dashboard/findings")
    async def findings() -> dict[str, Any]:
        alerts = await store.fetch_recent("alert_events", "created_at", 100)
        supply_chain = await store.fetch_recent("supply_chain_findings", "written_at", 50)
        vulnerabilities = await store.fetch_recent("osv_findings", "written_at", 50)
        mcp = await store.fetch_recent("mcp_scan_findings", "scanned_at", 50)
        return {"alerts": alerts, "supply_chain": supply_chain, "vulnerabilities": vulnerabilities, "mcp": mcp}

    @router.get("/api/dashboard/activity")
    async def activity() -> dict[str, Any]:
        audit_events = await store.fetch_recent("audit_events", "created_at", 50)
        briefs = await store.fetch_recent("brief_deliveries", "sent_at", 25)
        vector_counts = Counter(row["vector_type"] for row in await store.fetch_recent("alert_events", "created_at", 100) if row.get("vector_type"))
        return {"audit_events": audit_events, "briefs": briefs, "vector_counts": dict(vector_counts)}

    @router.get("/api/dashboard/admin")
    async def admin() -> dict[str, Any]:
        return await _admin_overview(store)

    @router.get("/api/dashboard/macros")
    async def macros() -> dict[str, Any]:
        macro_dir = settings.home / "sentinel" / "coral" / "macros"
        return {"macros": sorted(path.name for path in macro_dir.glob("*.sql"))}

    return router


async def _admin_overview(store: SentinelStore) -> dict[str, Any]:
    audit_events = await store.fetch_rows(
        "SELECT event_id, actor_login, action, repository, head_sha, created_at, raw_payload "
        "FROM audit_events WHERE action LIKE 'pr_%' ORDER BY created_at DESC LIMIT 100"
    )
    alerts = await store.fetch_recent("alert_events", "created_at", 200)
    vulnerabilities = await store.fetch_recent("osv_findings", "written_at", 100)
    alerts_by_commit = _group_by(alerts, "commit_sha")
    vulnerabilities_by_commit = _group_by(vulnerabilities, "commit_sha")
    pull_requests = _pull_request_rows(audit_events, alerts_by_commit, vulnerabilities_by_commit)
    return {
        "pull_requests": pull_requests,
        "milestones": _milestone_rows(pull_requests),
    }


def _pull_request_rows(
    audit_events: list[dict[str, Any]],
    alerts_by_commit: dict[str, list[dict[str, Any]]],
    vulnerabilities_by_commit: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    rows: list[dict[str, Any]] = []
    for event in audit_events:
        payload = _payload(event.get("raw_payload"))
        pr = payload.get("pull_request") if isinstance(payload.get("pull_request"), dict) else {}
        repo = str(event.get("repository") or "")
        number = str(pr.get("number") or payload.get("number") or "")
        commit = str(event.get("head_sha") or "")
        key = (repo, number, commit)
        if key in seen:
            continue
        seen.add(key)
        milestone = pr.get("milestone") if isinstance(pr.get("milestone"), dict) else {}
        commit_alerts = alerts_by_commit.get(commit, [])
        commit_vulnerabilities = vulnerabilities_by_commit.get(commit, [])
        rows.append(
            {
                "repository": repo,
                "number": number or "n/a",
                "title": str(pr.get("title") or f"Pull request {number or commit[:7] or 'n/a'}"),
                "actor_login": str(event.get("actor_login") or "unknown"),
                "action": str(event.get("action") or ""),
                "head_sha": commit,
                "created_at": str(event.get("created_at") or ""),
                "url": str(pr.get("html_url") or ""),
                "milestone": str(milestone.get("title") or "Unassigned"),
                "milestone_due_on": str(milestone.get("due_on") or ""),
                "milestone_state": str(milestone.get("state") or "open"),
                "open_alerts": len(commit_alerts),
                "vulnerabilities": len(commit_vulnerabilities),
                "risk_level": _risk_level(commit_alerts, commit_vulnerabilities),
                "status": _pr_status(commit_alerts, commit_vulnerabilities),
            }
        )
    return rows[:25]


def _milestone_rows(pull_requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for pr in pull_requests:
        key = (str(pr["repository"]), str(pr["milestone"]))
        row = grouped.setdefault(
            key,
            {
                "repository": pr["repository"],
                "name": pr["milestone"],
                "due_on": pr["milestone_due_on"],
                "state": pr["milestone_state"],
                "pull_requests": 0,
                "open_alerts": 0,
                "vulnerabilities": 0,
                "status": "on_track",
            },
        )
        row["pull_requests"] += 1
        row["open_alerts"] += int(pr["open_alerts"])
        row["vulnerabilities"] += int(pr["vulnerabilities"])
        if pr["risk_level"] == "critical":
            row["status"] = "blocked"
        elif pr["risk_level"] == "high" and row["status"] != "blocked":
            row["status"] = "review_required"
    return sorted(grouped.values(), key=lambda row: (row["status"] != "blocked", row["repository"], row["name"]))[:20]


def _group_by(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get(key) or ""), []).append(row)
    return grouped


def _payload(raw_payload: Any) -> dict[str, Any]:
    if isinstance(raw_payload, dict):
        return raw_payload
    try:
        decoded = json.loads(str(raw_payload or "{}"))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _risk_level(alerts: list[dict[str, Any]], vulnerabilities: list[dict[str, Any]]) -> str:
    if any(str(alert.get("severity") or "").upper() == "CRITICAL" for alert in alerts):
        return "critical"
    if vulnerabilities or alerts:
        return "high"
    return "normal"


def _pr_status(alerts: list[dict[str, Any]], vulnerabilities: list[dict[str, Any]]) -> str:
    if any(str(alert.get("severity") or "").upper() == "CRITICAL" for alert in alerts):
        return "blocked"
    if vulnerabilities or alerts:
        return "review_required"
    return "monitoring"


def _source_health(settings: Settings) -> list[dict[str, str]]:
    return [
        {"name": "GitHub", "status": "connected" if settings.github_token else "missing", "detail": settings.github_access_tier},
        {"name": "Coral", "status": "connected", "detail": "JSONL source"},
        {"name": "DuckDB", "status": "connected", "detail": str(settings.duckdb_path.name)},
        {"name": "Socket", "status": "connected" if settings.socket_api_key and settings.socket_org_slug else "missing", "detail": settings.socket_org_slug or "org slug required"},
        {"name": "Phylum", "status": "connected" if settings.phylum_api_key else "optional", "detail": "enterprise tier"},
        {"name": "Discord", "status": "connected" if settings.discord_webhook_url else "missing", "detail": "webhook dispatch"},
        {"name": "Slack", "status": "connected" if settings.slack_bot_token and settings.slack_channel_id else "optional", "detail": "approvals and bot"},
        {"name": "Jira", "status": "connected" if settings.jira_base_url and settings.jira_email and settings.jira_api_token else "optional", "detail": settings.jira_project_key or "change tickets"},
        {"name": "LLM", "status": _llm_status(settings), "detail": settings.llm_provider},
        {"name": "OpenTelemetry", "status": "connected" if settings.otlp_endpoint else "optional", "detail": "Grafana/OTLP"},
    ]


def _llm_status(settings: Settings) -> str:
    if settings.llm_provider == "gemini":
        return "connected" if settings.gemini_api_key else "missing"
    if settings.llm_provider == "anthropic":
        return "connected" if settings.anthropic_api_key else "missing"
    if settings.llm_provider == "ollama":
        return "local"
    return "missing"
