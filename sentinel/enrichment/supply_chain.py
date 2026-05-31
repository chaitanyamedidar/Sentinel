from __future__ import annotations
import hashlib, json
from collections.abc import Mapping
from sentinel.config import Settings
from sentinel.db.duckdb import SentinelStore
from sentinel.models import utc_now_iso

def dependency_hash(packages: list[Mapping[str, str]]) -> str:
    canonical = json.dumps(sorted(packages, key=lambda p: (p.get("ecosystem", ""), p.get("name", ""), p.get("version", ""))), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()

async def scan_packages(commit_sha: str, packages: list[Mapping[str, str]], store: SentinelStore, settings: Settings) -> list[dict]:
    provider = settings.supply_chain_provider if settings.supply_chain_provider in {"socket", "phylum"} else "socket"
    dep_hash = dependency_hash(packages)
    if await store.enrichment_cache_fresh(commit_sha, provider, dep_hash):
        return await store.fetch_supply_chain(commit_sha)
    if provider == "phylum":
        from sentinel.enrichment.providers.phylum import scan
    else:
        from sentinel.enrichment.providers.socket import scan
    findings = await scan(packages, settings)
    for finding in findings:
        await store.insert("supply_chain_findings", {"commit_sha": commit_sha, "package_name": finding.get("package_name") or finding.get("name"), "version": finding.get("version"), "ecosystem": finding.get("ecosystem"), "issue_type": finding.get("issue_type", "unknown"), "severity": finding.get("severity", "UNKNOWN"), "risk_score": float(finding.get("risk_score") or 0), "provider": provider, "written_at": utc_now_iso()}, lock_key=commit_sha)
    await store.remember_enrichment(commit_sha, provider, dep_hash)
    return findings
