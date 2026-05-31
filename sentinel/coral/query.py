from __future__ import annotations
import asyncio, json, time
from pathlib import Path
from typing import Any
from sentinel.telemetry.otel import record_query_duration

MASTER_QUERY = """
SELECT
  a.actor_login,
  a.action,
  a.repository,
  a.created_at,
  im.slack_id,
  im.workspace_email,
  s.text                 AS slack_approval,
  j.issue_key            AS jira_ticket,
  sc.package_name        AS flagged_package,
  sc.issue_type          AS supply_chain_finding,
  sc.provider            AS detection_provider

FROM sentinel.audit_events a

LEFT JOIN coral_files.identity_map im
  ON im.github_login = a.actor_login

LEFT JOIN slack.messages s
  ON s.channel = '#security-approvals'
  AND s.text LIKE 'Approved: ' || im.slack_id
  AND s.created BETWEEN a.created_at - INTERVAL '24 hours'
               AND a.created_at + INTERVAL '10 minutes'

LEFT JOIN jira.issues j
  ON j.summary LIKE '%' || a.repository || '%'
  AND j.created BETWEEN a.created_at - INTERVAL '7 days'
               AND a.created_at + INTERVAL '10 minutes'

LEFT JOIN sentinel.supply_chain_findings sc
  ON sc.commit_sha = a.head_sha

WHERE
  (s.text IS NULL AND j.issue_key IS NULL)
  OR sc.package_name IS NOT NULL

ORDER BY a.created_at DESC;
"""

MACRO_INTENTS = {
    "safe to release": "vw_release_blockers.sql", "release": "vw_release_blockers.sql",
    "oauth": "vw_oauth_ungoverned.sql", "supply": "vw_supply_chain_risks.sql", "package": "vw_supply_chain_risks.sql",
    "workflow": "vw_workflow_mutations.sql", "actor": "vw_actor_anomalies.sql",
    "credential": "vw_credential_exposure.sql", "secret": "vw_credential_exposure.sql", "onboarding": "vw_onboarding_pending.sql",
}

def macro_for_intent(query: str) -> str:
    lowered = query.lower()
    for phrase, filename in MACRO_INTENTS.items():
        if phrase in lowered: return filename
    return "vw_release_blockers.sql"

async def run_macro(query: str, macro_dir: Path) -> list[dict[str, Any]]:
    filename = macro_for_intent(query)
    sql = (macro_dir / filename).read_text(encoding="utf-8")
    started = time.perf_counter()
    process = await asyncio.create_subprocess_exec("coral", "sql", "--format", "json", sql, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    record_query_duration(time.perf_counter() - started, filename)
    if process.returncode != 0: raise RuntimeError(stderr.decode("utf-8", "ignore"))
    return json.loads(stdout.decode("utf-8") or "[]")
