from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from sentinel.config import Settings


@dataclass(frozen=True)
class PullRequestFiles:
    paths: list[str]
    contents: dict[str, str]
    patches: dict[str, str]


class GitHubClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def fetch_pull_request_files(self, repository: str, number: int, ref: str) -> PullRequestFiles:
        if not self.settings.github_token:
            return PullRequestFiles(paths=[], contents={}, patches={})
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.settings.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=20) as client:
            files = await self._fetch_pr_file_list(client, repository, number)
            contents: dict[str, str] = {}
            for item in files:
                path = str(item.get("filename") or "")
                if path and _should_fetch_content(path):
                    text = await self._fetch_file_content(client, repository, path, ref, item)
                    if text is not None:
                        contents[path] = text
            return PullRequestFiles(
                paths=[str(item.get("filename")) for item in files if item.get("filename")],
                contents=contents,
                patches={str(item.get("filename")): str(item.get("patch") or "") for item in files if item.get("filename") and item.get("patch")},
            )

    async def fetch_pull_request_reviews(self, repository: str, number: int) -> list[dict[str, Any]]:
        if not self.settings.github_token:
            return []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.settings.github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=20) as client:
            response = await client.get(f"/repos/{repository}/pulls/{number}/reviews", params={"per_page": 100})
            response.raise_for_status()
            payload = response.json()
            return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []

    async def _fetch_pr_file_list(self, client: httpx.AsyncClient, repository: str, number: int) -> list[dict[str, Any]]:
        page = 1
        files: list[dict[str, Any]] = []
        while page <= 10:
            response = await client.get(f"/repos/{repository}/pulls/{number}/files", params={"per_page": 100, "page": page})
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list) or not batch:
                break
            files.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < 100:
                break
            page += 1
        return files

    async def _fetch_file_content(self, client: httpx.AsyncClient, repository: str, path: str, ref: str, item: dict[str, Any]) -> str | None:
        raw_url = item.get("raw_url")
        if raw_url:
            raw = await client.get(str(raw_url), follow_redirects=True)
            if raw.status_code == 200 and len(raw.content) <= 500_000:
                return raw.text
        response = await client.get(f"/repos/{repository}/contents/{path}", params={"ref": ref})
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
        content = payload.get("content") if isinstance(payload, dict) else None
        encoding = payload.get("encoding") if isinstance(payload, dict) else None
        if isinstance(content, str) and encoding == "base64":
            return base64.b64decode(content).decode("utf-8", "replace")
        return None


def pull_request_number(payload: dict[str, Any]) -> int | None:
    pr = payload.get("pull_request") or {}
    value = pr.get("number") or payload.get("number")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def pull_request_ref(payload: dict[str, Any], fallback_sha: str) -> str:
    head = (payload.get("pull_request") or {}).get("head") or {}
    return str(head.get("sha") or head.get("ref") or fallback_sha)


def _should_fetch_content(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "pyproject.toml"}:
        return True
    if normalized.startswith(".github/workflows/") and normalized.endswith((".yml", ".yaml")):
        return True
    return normalized in {"SKILL.md", "mcp.json", ".vscode/mcp.json"} or normalized.startswith((".cursor/rules", ".claude/", "skills/"))
