from __future__ import annotations
import asyncio, logging
from contextlib import asynccontextmanager
import re
from dataclasses import replace
from typing import Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sentinel.audit_polling import github_audit_poll_loop
from sentinel.config import Settings
from sentinel.coral.query import macro_for_intent, run_macro
from sentinel.dashboard import dashboard_router
from sentinel.db.duckdb import SentinelStore
from sentinel.demo import reset_demo_data, scenario_catalog, seed_demo_scenario
from sentinel.dispatch.escalation import AlertRateEscalator
from sentinel.dispatch.queue import DebounceDispatcher
from sentinel.discord_interactions import APPLICATION_COMMAND, extract_query, interaction_message, is_security_team_member, ping_response, verify_discord_signature
from sentinel.enrichment.dependencies import parse_dependency_files
from sentinel.enrichment.mcpscan import run_mcp_scan
from sentinel.enrichment.osv import scan_osv
from sentinel.enrichment.registry import enrich_packages
from sentinel.enrichment.supply_chain import scan_packages
from sentinel.github_client import GitHubClient, PullRequestFiles, pull_request_number, pull_request_ref
from sentinel.ingestor import apply_attack_flags, check_self_hosted_runner, detect_action_typosquat, detect_force_push_after_approval, detect_malicious_skill_content, detect_unsigned_maintainer_commit, extract_changed_paths, extract_dependency_refs, extract_owner_change, new_actor_detected, normalize_github_event, payload_from_bytes, pr_secret_vectors, scan_for_exfiltration, touches_agent_config, workflow_vectors
from sentinel.integrations.jira import JiraClient
from sentinel.llm.narrator import narrate
from sentinel.onboarding.brief import record_brief
from sentinel.scheduler import daily_mcp_scan
from sentinel.scoring.scorer import Alert, score_findings
from sentinel.security import verify_github_signature
from sentinel.telemetry.otel import init_telemetry, record_alert, record_score
LOGGER = logging.getLogger("sentinel")

class AppState:
    def __init__(self) -> None:
        self.settings = Settings.from_env(); self.store = SentinelStore(self.settings)
        self.github = GitHubClient(self.settings)
        self.jira = JiraClient(self.settings)
        self.queue: asyncio.Queue[tuple[dict[str, str], dict[str, Any]]] = asyncio.Queue()
        self.dispatcher = DebounceDispatcher(self.settings, self.store); self.worker: asyncio.Task | None = None
        self.escalator = AlertRateEscalator()
        self.scheduler: asyncio.Task | None = None
        self.audit_poller: asyncio.Task | None = None
        self.dispatch_tasks: set[asyncio.Task] = set()
state = AppState()

@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO); init_telemetry(); await state.store.init()
    state.worker = asyncio.create_task(_worker())
    state.scheduler = asyncio.create_task(daily_mcp_scan(state.settings, state.store))
    state.audit_poller = asyncio.create_task(github_audit_poll_loop(state.settings, state.store))
    try: yield
    finally:
        if state.worker: state.worker.cancel()
        if state.scheduler: state.scheduler.cancel()
        if state.audit_poller: state.audit_poller.cancel()
        for task in state.dispatch_tasks: task.cancel()

app = FastAPI(title="SENTINEL v4", lifespan=lifespan)
app.include_router(dashboard_router(state.settings, state.store))
app.mount("/assets", StaticFiles(directory=state.settings.home / "sentinel" / "dashboard_static"), name="dashboard-assets")

@app.get("/health")
async def health() -> dict[str, str]: return {"status":"ok"}

@app.get("/api/demo/scenarios")
async def demo_scenarios() -> dict[str, Any]:
    return {"scenarios": scenario_catalog()}

@app.post("/api/demo/scenarios/{scenario_key}")
async def run_demo_scenario(scenario_key: str) -> JSONResponse:
    try:
        result = await seed_demo_scenario(state.store, scenario_key)
    except KeyError:
        return JSONResponse({"error": "unknown scenario"}, status_code=404)
    return JSONResponse({"accepted": True, "result": result})

@app.post("/api/demo/reset")
async def reset_demo() -> JSONResponse:
    return JSONResponse({"accepted": True, "deleted": await reset_demo_data(state.store)})

@app.get("/api/integrations/jira/search")
async def jira_search(repository: str) -> JSONResponse:
    issues = await state.jira.search_approval_issues(repository)
    return JSONResponse({"configured": state.jira.configured, "issues": [issue.__dict__ for issue in issues]})

@app.get("/api/integrations/jira/health")
async def jira_health() -> JSONResponse:
    try:
        ok = await state.jira.ping()
    except Exception as exc:
        return JSONResponse({"configured": state.jira.configured, "ok": False, "error": str(exc)}, status_code=502)
    return JSONResponse({"configured": state.jira.configured, "ok": ok})

@app.post("/webhooks/github")
async def github_webhook(request: Request) -> JSONResponse:
    body = await request.body(); signature = request.headers.get("X-Hub-Signature-256")
    if not verify_github_signature(state.settings.github_webhook_secret, body, signature):
        LOGGER.warning("dropped unsigned GitHub webhook delivery=%s", request.headers.get("X-GitHub-Delivery", "unknown"))
        return JSONResponse({"accepted": False})
    await state.queue.put((dict(request.headers), payload_from_bytes(body)))
    return JSONResponse({"accepted": True})

@app.post("/commands/sentinel")
async def sentinel_command(request: Request) -> JSONResponse:
    payload = await request.json()
    roles = set(payload.get("roles") or payload.get("user_roles") or [])
    if "Security-Team" not in roles:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    query = str(payload.get("query") or payload.get("text") or "").strip()
    if not query:
        return JSONResponse({"error": "query is required"}, status_code=400)
    macro = macro_for_intent(query)
    rows = await run_macro(query, state.settings.home / "sentinel" / "coral" / "macros")
    try:
        narrative = await narrate(state.settings, rows)
    except Exception:
        LOGGER.exception("LLM narrative generation failed")
        narrative = "Narrative unavailable. Fixed macro rows are returned for review."
    return JSONResponse({"macro": macro, "rows": rows, "summary": _plain_summary(query, rows), "narrative": narrative})

@app.post("/interactions/discord")
async def discord_interaction(request: Request) -> JSONResponse:
    body = await request.body()
    if not verify_discord_signature(state.settings.discord_public_key, body, request.headers.get("X-Signature-Timestamp"), request.headers.get("X-Signature-Ed25519")):
        return JSONResponse({"error": "bad signature"}, status_code=401)
    payload = payload_from_bytes(body)
    if payload.get("type") == 1:
        return JSONResponse(ping_response())
    if payload.get("type") != APPLICATION_COMMAND:
        return JSONResponse(interaction_message("Unsupported Discord interaction."))
    if not is_security_team_member(payload, state.settings):
        return JSONResponse(interaction_message("SENTINEL is restricted to the configured Security-Team role."))
    query = extract_query(payload)
    if not query:
        return JSONResponse(interaction_message("Usage: /sentinel query:<security question>"))
    rows = await run_macro(query, state.settings.home / "sentinel" / "coral" / "macros")
    macro = macro_for_intent(query)
    return JSONResponse(interaction_message(_discord_brief(query, macro, rows, str(request.base_url).rstrip("/"))))

async def _worker() -> None:
    while True:
        headers, payload = await state.queue.get()
        try: await _process_event(headers, payload)
        except Exception: LOGGER.exception("failed to process webhook")
        finally: state.queue.task_done()

async def _process_event(headers: dict[str, str], payload: dict[str, Any]) -> None:
    event = normalize_github_event(headers, payload)
    paths = extract_changed_paths(payload); packages = extract_dependency_refs(payload); direct_vectors = pr_secret_vectors(payload)
    github_files = await _fetch_github_files(payload, event.repository, event.head_sha)
    paths = sorted(set(paths) | set(github_files.paths))
    direct_vectors.extend(workflow_vectors(github_files.contents))
    packages = _merge_packages(packages, parse_dependency_files(github_files.contents))
    first_time = new_actor_detected(payload, event.action)
    reviews = await _fetch_github_reviews(payload, event.repository)
    attack_patches = {**github_files.contents, **github_files.patches}
    if detect_malicious_skill_content(attack_patches):
        direct_vectors.append("malicious_skill_md_detected")
    flags = {
        "ci_exfiltration_detected": scan_for_exfiltration(attack_patches),
        "self_hosted_first_actor": check_self_hosted_runner(attack_patches, first_time),
        "force_push_after_approval": detect_force_push_after_approval(payload, reviews),
        "unsigned_maintainer_commit": detect_unsigned_maintainer_commit(payload.get("commits") or [], event.actor_login, state.settings.core_maintainers or set()),
        "action_typosquat_detected": detect_action_typosquat(attack_patches),
        "orphan_pkg_owner_change": False,
    }
    event = apply_attack_flags(event, flags)
    await state.store.insert("audit_events", event.as_row(), lock_key=event.head_sha or event.event_id)
    if first_time: await record_brief(state.store, event.actor_login, "maintainer" if event.action == "member_added" else "contributor")
    if touches_agent_config(paths):
        try:
            await run_mcp_scan(event.actor_login, paths, state.store, state.settings.home)
        except Exception:
            LOGGER.exception("mcp-scan enrichment failed actor=%s", event.actor_login)
    if packages and event.head_sha:
        supply_findings: list[dict[str, Any]] = []
        try:
            supply_findings = await scan_packages(event.head_sha, packages, state.store, state.settings)
        except Exception:
            LOGGER.exception("supply-chain enrichment failed commit=%s", event.head_sha)
        else:
            if any(extract_owner_change(finding) for finding in supply_findings):
                flags["orphan_pkg_owner_change"] = True
                event = apply_attack_flags(event, flags)
                await state.store.insert("audit_events", event.as_row(), lock_key=event.head_sha or event.event_id)
        try:
            for finding in await scan_osv(event.head_sha, packages, state.store):
                severity = str(finding.get("severity") or "").upper()
                if severity == "CRITICAL":
                    direct_vectors.append("osv_critical")
                elif severity == "HIGH":
                    direct_vectors.append("osv_high")
        except Exception:
            LOGGER.exception("OSV enrichment failed commit=%s", event.head_sha)
        try:
            await enrich_packages(event.head_sha, packages, state.store)
        except Exception:
            LOGGER.exception("registry enrichment failed commit=%s", event.head_sha)
    alerts = score_findings(event.head_sha, event.actor_login, await state.store.fetch_supply_chain(event.head_sha), await state.store.fetch_enriched_packages(event.head_sha), await state.store.fetch_mcp_findings(event.actor_login), direct_vectors=direct_vectors, event_flags=flags, first_time_contributor=first_time, threshold=state.settings.alert_threshold)
    for alert in alerts:
        alert = _with_evidence(alert, event.repository, payload)
        record_score(alert.score, alert.vector_type)
        task = asyncio.create_task(_dispatch_alert(alert, event.repository))
        state.dispatch_tasks.add(task)
        task.add_done_callback(state.dispatch_tasks.discard)

async def _fetch_github_files(payload: dict[str, Any], repository: str, head_sha: str) -> PullRequestFiles:
    number = pull_request_number(payload)
    if not repository or number is None:
        return PullRequestFiles(paths=[], contents={}, patches={})
    try:
        return await state.github.fetch_pull_request_files(repository, number, pull_request_ref(payload, head_sha))
    except Exception:
        LOGGER.exception("GitHub PR file fetch failed repository=%s number=%s", repository, number)
        return PullRequestFiles(paths=[], contents={}, patches={})

async def _fetch_github_reviews(payload: dict[str, Any], repository: str) -> list[dict[str, Any]]:
    number = pull_request_number(payload)
    if not repository or number is None:
        return []
    try:
        return await state.github.fetch_pull_request_reviews(repository, number)
    except Exception:
        LOGGER.exception("GitHub PR review fetch failed repository=%s number=%s", repository, number)
        return []

async def _dispatch_alert(alert, repository: str) -> None:
    if not alert.bypass_buffer:
        await asyncio.sleep(state.settings.triage_buffer_seconds)
    record_alert(alert.vector_type, alert.detection_provider, repository)
    await state.dispatcher.enqueue(alert)
    if state.escalator.record(repository):
        escalation = Alert(alert.commit_sha, alert.actor_login, "alert_storm", 100, "CRITICAL", alert.detection_provider, f"40 or more alerts fired for {repository} within 10 minutes")
        record_alert(escalation.vector_type, escalation.detection_provider, repository)
        await state.dispatcher.enqueue(escalation)

def _merge_packages(left: list[dict[str, str]], right: list[dict[str, str]]) -> list[dict[str, str]]:
    merged: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in [*left, *right]:
        name, version, ecosystem = str(item.get("name") or "").strip(), str(item.get("version") or "").strip(), str(item.get("ecosystem") or "npm").strip().lower()
        if name and version:
            merged[(ecosystem, name, version)] = {"name": name, "version": version, "ecosystem": ecosystem}
    return sorted(merged.values(), key=lambda item: (item["ecosystem"], item["name"], item["version"]))

def _plain_summary(query: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f"No rows matched fixed SENTINEL macro for: {query}"
    return f"{len(rows)} row(s) matched fixed SENTINEL macro for: {query}"

def _discord_brief(query: str, macro: str, rows: list[dict[str, Any]], base_url: str) -> str:
    title = _brief_title(macro, rows)
    if not rows:
        return f"**{title}**\nNo active findings matched `{query}`.\nEvidence: {base_url}/"
    lines = [f"**{title}**", f"{len(rows)} finding(s) matched `{query}`."]
    for index, row in enumerate(rows[:3], 1):
        vector = _vector_label(str(row.get("vector_type") or row.get("issue_type") or row.get("action") or "security_signal"))
        severity = str(row.get("severity") or "UNKNOWN").upper()
        score = row.get("score") or row.get("risk_score") or "n/a"
        actor = row.get("actor_login") or row.get("actor") or "unknown actor"
        issue = row.get("summary") or _row_issue(row)
        evidence = _evidence_link(row, base_url)
        lines.extend([
            "",
            f"**{index}. {severity} - {vector}**",
            f"Issue: {issue}",
            f"Actor: `{actor}` | Score: `{score}`",
            f"Evidence: {evidence}",
        ])
    if len(rows) > 3:
        lines.append(f"\nShowing top 3. Open dashboard for {len(rows) - 3} more.")
    return "\n".join(lines)[:1900]

def _brief_title(macro: str, rows: list[dict[str, Any]]) -> str:
    if macro == "vw_release_blockers.sql":
        return "SENTINEL Release Risk"
    if macro == "vw_supply_chain_risks.sql":
        return "SENTINEL Supply Chain Risk"
    if macro == "vw_workflow_mutations.sql":
        return "SENTINEL Workflow Risk"
    if macro == "vw_credential_exposure.sql":
        return "SENTINEL Credential Exposure"
    return "SENTINEL Security Brief"

def _row_issue(row: dict[str, Any]) -> str:
    package = row.get("package_name")
    version = row.get("version")
    if package:
        return f"{package}@{version or 'unknown'} flagged as {row.get('issue_type') or 'supply-chain risk'}."
    if row.get("event_count"):
        return f"{row.get('actor_login')} has {row.get('event_count')} correlated events."
    return "Correlated SENTINEL evidence requires security review."

def _evidence_link(row: dict[str, Any], base_url: str) -> str:
    repository = str(row.get("repository") or "").strip()
    commit_sha = str(row.get("commit_sha") or row.get("head_sha") or "").strip()
    if repository and _looks_like_sha(commit_sha):
        return f"https://github.com/{repository}/commit/{commit_sha}"
    if repository:
        return f"https://github.com/{repository}"
    return f"{base_url}/"

def _looks_like_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{12,40}", value))

def _vector_label(vector: str) -> str:
    return vector.replace("_", " ").replace(" lte ", " <= ").title()

def _with_evidence(alert: Alert, repository: str, payload: dict[str, Any]) -> Alert:
    provider = alert.detection_provider or ("osv" if alert.vector_type.startswith("osv_") else "sentinel" if alert.vector_type.startswith(("credential_", "workflow_", "mcp_", "malicious_", "ci_", "first_time_", "force_push_", "unsigned_", "action_")) else "")
    evidence_url = _payload_evidence_url(alert, repository, payload) or alert.evidence_url
    return replace(alert, repository=repository, evidence_url=evidence_url, detection_provider=provider)

def _payload_evidence_url(alert: Alert, repository: str, payload: dict[str, Any]) -> str:
    pr = payload.get("pull_request") or {}
    if alert.vector_type in {"credential_in_pr_body", "malicious_skill_md_detected", "mcp_tool_poisoning_detected"} and pr.get("html_url"):
        return str(pr["html_url"])
    if alert.vector_type == "credential_in_pr_comment":
        for comment in payload.get("sentinel_pr_comments") or []:
            if isinstance(comment, dict) and comment.get("html_url"):
                return str(comment["html_url"])
    if repository and _looks_like_sha(alert.commit_sha):
        return f"https://github.com/{repository}/commit/{alert.commit_sha}"
    return f"https://github.com/{repository}" if repository else ""
