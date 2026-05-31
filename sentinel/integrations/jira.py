from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from sentinel.config import Settings


@dataclass(frozen=True)
class JiraIssue:
    issue_key: str
    summary: str
    status: str
    created: str
    url: str


class JiraClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        return bool(self.settings.jira_base_url and self.settings.jira_email and self.settings.jira_api_token)

    async def search_approval_issues(self, repository: str, limit: int = 10) -> list[JiraIssue]:
        if not self.configured or not repository:
            return []
        jql = self._approval_jql(repository)
        payload = await self._search(jql, max_results=limit)
        return [self._issue_from_payload(item) for item in payload.get("issues", []) if isinstance(item, dict)]

    async def ping(self) -> bool:
        if not self.configured:
            return False
        headers = self._headers()
        async with httpx.AsyncClient(base_url=self.settings.jira_base_url, headers=headers, timeout=20) as client:
            response = await client.get("/rest/api/3/myself")
            response.raise_for_status()
            payload = response.json()
            return bool(payload.get("accountId"))

    async def _search(self, jql: str, max_results: int) -> dict[str, Any]:
        headers = self._headers()
        params = {"jql": jql, "maxResults": max(1, min(max_results, 50)), "fields": "summary,status,created"}
        async with httpx.AsyncClient(base_url=self.settings.jira_base_url, headers=headers, timeout=20) as client:
            response = await client.get("/rest/api/3/search/jql", params=params)
            if response.status_code == 404:
                response = await client.get("/rest/api/3/search", params=params)
            response.raise_for_status()
            return response.json()

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self.settings.jira_email}:{self.settings.jira_api_token}".encode("utf-8")).decode("ascii")
        return {"Accept": "application/json", "Authorization": f"Basic {token}"}

    def _approval_jql(self, repository: str) -> str:
        escaped = repository.replace("\\", "\\\\").replace('"', '\\"')
        prefix = f"project = {self.settings.jira_project_key} AND " if self.settings.jira_project_key else ""
        return f'{prefix}summary ~ "{escaped}" ORDER BY created DESC'

    def _issue_from_payload(self, item: dict[str, Any]) -> JiraIssue:
        fields = item.get("fields") or {}
        status = fields.get("status") if isinstance(fields.get("status"), dict) else {}
        key = str(item.get("key") or "")
        return JiraIssue(
            issue_key=key,
            summary=str(fields.get("summary") or ""),
            status=str(status.get("name") or ""),
            created=str(fields.get("created") or ""),
            url=f"{self.settings.jira_base_url}/browse/{key}" if key else self.settings.jira_base_url,
        )
