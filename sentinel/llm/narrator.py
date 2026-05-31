from __future__ import annotations
from collections.abc import Mapping
import httpx
from sentinel.config import Settings
from sentinel.security import redact_text

SYSTEM_PROMPT = """You are SENTINEL's security narrative formatter.
Use only the provided structured rows.
Do not invent actors, threats, repositories, credentials, approvals, or actions.
If rows are empty, say there are no active findings.
Return only this format:
THREAT: <one line>
ACTOR: <actor>
AFFECTED: <repo or commit>
CONFIDENCE: <low|medium|high>
IMMEDIATE ACTIONS: <numbered short actions>
"""
SAFE_FIELDS = {"actor_login","repository","commit_sha","vector_type","score","severity","detection_provider","package_name","issue_type"}

async def narrate(settings: Settings, rows: list[Mapping]) -> str:
    if not rows:
        return _fallback(rows)
    safe_rows = [{k: redact_text(str(v)) for k, v in row.items() if k in SAFE_FIELDS} for row in rows]
    if settings.llm_provider == "anthropic": return await _anthropic(settings, safe_rows)
    if settings.llm_provider == "ollama": return await _ollama(settings, safe_rows)
    return await _gemini(settings, safe_rows)

async def _gemini(settings: Settings, rows: list[Mapping]) -> str:
    if not settings.gemini_api_key: return _fallback(rows)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={settings.gemini_api_key}"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(url, json={"contents":[{"parts":[{"text": SYSTEM_PROMPT + "\nRows: " + repr(rows)}]}]})
        response.raise_for_status(); return response.json()["candidates"][0]["content"]["parts"][0]["text"]

async def _anthropic(settings: Settings, rows: list[Mapping]) -> str:
    if not settings.anthropic_api_key: return _fallback(rows)
    headers = {"x-api-key": settings.anthropic_api_key, "anthropic-version": "2023-06-01"}
    payload = {"model":"claude-sonnet-4-20250514","max_tokens":300,"system":SYSTEM_PROMPT,"messages":[{"role":"user","content":repr(rows)}]}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        response = await client.post("https://api.anthropic.com/v1/messages", json=payload)
        response.raise_for_status(); return response.json()["content"][0]["text"]

async def _ollama(settings: Settings, rows: list[Mapping]) -> str:
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(f"{settings.ollama_base_url.rstrip('/')}/api/generate", json={"model":"llama3","prompt":SYSTEM_PROMPT+"\nRows: "+repr(rows),"stream":False})
        response.raise_for_status(); return response.json().get("response", _fallback(rows))

def _fallback(rows: list[Mapping]) -> str:
    first = rows[0] if rows else {}
    if not first:
        return "\n".join(["THREAT: No active findings", "ACTOR: n/a", "AFFECTED: n/a", "CONFIDENCE: high", "IMMEDIATE ACTIONS: 1. Continue monitoring. 2. Re-run SENTINEL after new repository activity."])
    return "\n".join([f"THREAT: {first.get('vector_type','security finding')}", f"ACTOR: {first.get('actor_login','unknown')}", f"AFFECTED: {first.get('repository', first.get('commit_sha','unknown'))}", "CONFIDENCE: medium", "IMMEDIATE ACTIONS: 1. Review the finding. 2. Pause release if severity is high. 3. Rotate exposed credentials if any."])
