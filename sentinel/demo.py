from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso


@dataclass(frozen=True)
class DemoScenario:
    key: str
    label: str
    vector_type: str
    actor: str
    commit: str
    severity: str
    score: int
    provider: str
    summary: str


SCENARIOS = {
    item.key: item
    for item in [
        DemoScenario("supply_chain", "Young postinstall package", "supply_chain_malicious_package", "new-contrib", "demo001", "CRITICAL", 95, "socket", "Young npm package with postinstall behavior detected."),
        DemoScenario("credential", "Credential in PR description", "credential_in_pr_body", "feature-dev", "demo002", "CRITICAL", 90, "n/a", "Credential-like token detected in pull request metadata."),
        DemoScenario("mcp_skill", "Agent skill poisoning", "mcp_tool_poisoning_detected", "ai-helper", "demo003", "CRITICAL", 92, "n/a", "mcp-scan reported suspicious agent tool configuration."),
        DemoScenario("workflow", "Workflow permission escalation", "workflow_permission_escalation", "release-maintainer", "demo004", "HIGH", 75, "n/a", "Workflow changed to broad write permissions without approval trail."),
        DemoScenario("onboarding", "First-time contributor", "first_time_contributor", "first-timer", "demo005", "HIGH", 60, "n/a", "New contributor received security hygiene brief."),
        DemoScenario("member_added", "New maintainer added", "oauth_grant_no_approval", "new-maintainer", "demo006", "HIGH", 70, "n/a", "Maintainer onboarding event lacks approval trail."),
        DemoScenario("ci_exfiltration", "CI exfiltration script", "ci_exfiltration_script_detected", "suspicious-ci", "demo007", "CRITICAL", 70, "n/a", "Workflow or install script sends secrets to an explicit external destination."),
        DemoScenario("self_hosted_runner", "First-time actor self-hosted runner", "first_time_actor_self_hosted", "first-timer", "demo008", "HIGH", 60, "n/a", "First-time contributor routed CI onto a self-hosted runner."),
        DemoScenario("force_push_after_approval", "Force-push after approval", "force_push_after_approval", "feature-dev", "demo009", "HIGH", 60, "n/a", "Pull request was synchronized after an approved review."),
        DemoScenario("unsigned_maintainer", "Unsigned core maintainer commit", "unsigned_commit_core_maintainer", "core-maintainer", "demo010", "CRITICAL", 60, "n/a", "Core maintainer pushed an unsigned commit."),
        DemoScenario("action_typosquat", "GitHub Action typosquat", "action_typosquat_distance_lte_2", "release-maintainer", "demo011", "HIGH", 60, "n/a", "Workflow references an action name close to a known trusted action."),
        DemoScenario("orphan_owner_change", "Orphan package owner change", "orphan_pkg_recent_owner_change", "new-contrib", "demo012", "HIGH", 65, "socket", "Supply-chain provider reported a package ownership or maintainer change risk."),
    ]
}

DEMO_REPOSITORY = "chaitanyamedidar/sentinel-demo-repo"


async def seed_demo_scenario(store: SentinelStore, key: str) -> dict[str, Any]:
    if key == "batch":
        rows = []
        for scenario_key in ("credential", "supply_chain", "mcp_skill"):
            rows.append(await seed_demo_scenario(store, scenario_key))
        return {"scenario": "batch", "inserted": rows}
    scenario = SCENARIOS[key]
    now = utc_now_iso()
    await store.insert(
        "audit_events",
        {
            "event_id": f"demo-{scenario.key}-{now}",
            "actor_login": scenario.actor,
            "action": "pr_opened" if scenario.key != "member_added" else "member_added",
            "repository": DEMO_REPOSITORY,
            "head_sha": scenario.commit,
            "ip_address": "127.0.0.1",
            "created_at": now,
            "raw_payload": "{}",
            "ci_exfiltration_detected": scenario.key == "ci_exfiltration",
            "self_hosted_first_actor": scenario.key == "self_hosted_runner",
            "force_push_after_approval": scenario.key == "force_push_after_approval",
            "unsigned_maintainer_commit": scenario.key == "unsigned_maintainer",
            "action_typosquat_detected": scenario.key == "action_typosquat",
            "orphan_pkg_owner_change": scenario.key == "orphan_owner_change",
        },
        lock_key=scenario.commit,
    )
    if scenario.key in {"supply_chain", "orphan_owner_change"}:
        await store.insert(
            "supply_chain_findings",
            {
                "commit_sha": scenario.commit,
                "package_name": "postinstall-demo" if scenario.key == "supply_chain" else "orphan-demo",
                "version": "0.0.3",
                "ecosystem": "npm",
                "issue_type": "malicious_install_script" if scenario.key == "supply_chain" else "maintainerChange",
                "severity": "CRITICAL" if scenario.key == "supply_chain" else "HIGH",
                "risk_score": 98.0 if scenario.key == "supply_chain" else 82.0,
                "provider": scenario.provider,
                "written_at": now,
            },
            lock_key=scenario.commit,
        )
    if scenario.key == "mcp_skill":
        await store.insert(
            "mcp_scan_findings",
            {
                "actor": scenario.actor,
                "skill_name": "demo-skill",
                "finding_type": "mcp_tool_poisoning_detected",
                "severity": "CRITICAL",
                "file_path": "SKILL.md",
                "scanned_at": now,
            },
            lock_key=scenario.commit,
        )
    if scenario.key == "onboarding":
        await store.insert(
            "brief_deliveries",
            {"actor": scenario.actor, "tier": "contributor", "sent_at": now, "channel": "pr_comment", "status": "sent"},
            lock_key=scenario.commit,
        )
    await store.insert(
        "alert_events",
        {
            "commit_sha": scenario.commit,
            "actor_login": scenario.actor,
            "vector_type": scenario.vector_type,
            "score": scenario.score,
            "severity": scenario.severity,
            "detection_provider": scenario.provider,
            "summary": scenario.summary,
            "created_at": now,
        },
        lock_key=scenario.commit,
    )
    return {"scenario": scenario.key, "label": scenario.label, "commit": scenario.commit, "vector_type": scenario.vector_type}


async def reset_demo_data(store: SentinelStore) -> dict[str, int]:
    statements = [
        ("alert_events", "DELETE FROM alert_events WHERE commit_sha LIKE 'demo%' OR commit_sha IN ('cred123', 'abc123')"),
        ("supply_chain_findings", "DELETE FROM supply_chain_findings WHERE commit_sha LIKE 'demo%' OR commit_sha IN ('cred123', 'abc123')"),
        ("osv_findings", "DELETE FROM osv_findings WHERE commit_sha LIKE 'demo%' OR commit_sha IN ('cred123', 'abc123')"),
        ("enriched_packages", "DELETE FROM enriched_packages WHERE commit_sha LIKE 'demo%' OR commit_sha IN ('cred123', 'abc123')"),
        ("mcp_scan_findings", "DELETE FROM mcp_scan_findings WHERE actor IN ('ai-helper', 'daily-cron') OR file_path = 'SKILL.md'"),
        ("brief_deliveries", "DELETE FROM brief_deliveries WHERE actor IN ('first-timer', 'new-maintainer', 'demo-user')"),
        ("audit_events", "DELETE FROM audit_events WHERE event_id LIKE 'demo-%' OR event_id LIKE 'local-%'"),
    ]
    counts: dict[str, int] = {}
    for table, statement in statements:
        before = await store.fetch_scalar(f"SELECT COUNT(*) FROM {table}")
        await store.execute(statement)
        after = await store.fetch_scalar(f"SELECT COUNT(*) FROM {table}")
        counts[table] = int(before) - int(after)
    await store.rebuild_jsonl()
    return counts


def scenario_catalog() -> list[dict[str, str]]:
    catalog = [{"key": item.key, "label": item.label, "vector_type": item.vector_type} for item in SCENARIOS.values()]
    catalog.append({"key": "batch", "label": "Batch multiple critical findings", "vector_type": "aggregate"})
    return catalog
