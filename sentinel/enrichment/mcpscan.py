from __future__ import annotations
import asyncio, json
from pathlib import Path
from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso

async def run_mcp_scan(actor: str, changed_paths: list[str], store: SentinelStore, cwd: Path) -> list[dict]:
    if not changed_paths: return []
    try:
        process = await asyncio.create_subprocess_exec("uvx", "mcp-scan@latest", "--skills", "--json", *changed_paths, cwd=str(cwd), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45)
        findings = _parse_findings(stdout) if process.returncode in {0, 1} else [{"skill_name":"mcp-scan","finding_type":"scan_failed","severity":"LOW","file_path":stderr.decode('utf-8','ignore')[:200]}]
    except (TimeoutError, FileNotFoundError):
        findings = [{"skill_name":"mcp-scan","finding_type":"scan_failed","severity":"LOW","file_path":""}]
    for finding in findings:
        await store.insert("mcp_scan_findings", {"actor": actor, "skill_name": finding.get("skill_name", "unknown"), "finding_type": finding.get("finding_type", "unknown"), "severity": finding.get("severity", "UNKNOWN"), "file_path": finding.get("file_path", ""), "scanned_at": utc_now_iso()})
    return findings

def _parse_findings(stdout: bytes) -> list[dict]:
    if not stdout.strip(): return []
    payload = json.loads(stdout.decode())
    items = payload.get("findings") if isinstance(payload, dict) else payload
    return [{"skill_name": i.get("skill_name") or i.get("name") or i.get("tool") or "unknown", "finding_type": i.get("finding_type") or i.get("type") or i.get("rule") or "mcp_scan_finding", "severity": str(i.get("severity") or "MEDIUM").upper(), "file_path": i.get("file_path") or i.get("path") or ""} for i in (items or []) if isinstance(i, dict)]
