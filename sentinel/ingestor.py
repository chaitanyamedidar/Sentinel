from __future__ import annotations
import json
import re
from collections.abc import Mapping
from typing import Any
from dataclasses import replace
from sentinel.models import AuditEvent, utc_now_iso
from sentinel.security import contains_secret, redacted_json

AGENT_CONFIG_PATHS = (".cursor/rules", "SKILL.md", "mcp.json", ".vscode/mcp.json", ".claude/", "skills/")
CI_EXFILTRATION_PATHS = (".github/workflows/", "package.json", "package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "pyproject.toml", "Makefile", "Dockerfile", "scripts/")
KNOWN_ACTIONS = {
    "actions/checkout", "actions/setup-node", "actions/setup-python", "actions/cache",
    "actions/upload-artifact", "actions/download-artifact", "docker/login-action",
    "docker/build-push-action", "github/codeql-action", "softprops/action-gh-release",
}
NETWORK_TOOL_RE = re.compile(r"\b(curl|wget|nc|ncat|Invoke-WebRequest|iwr)\b", re.IGNORECASE)
EXPLICIT_DEST_RE = re.compile(r"\bhttps?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/:][^\s'\"`]*)?", re.IGNORECASE)
SECRET_ACCESS_RE = re.compile(r"(\.env|\.npmrc|credentials?|api keys?|tokens?|secrets?)", re.IGNORECASE)
SELF_HOSTED_RE = re.compile(r"runs-on\s*:\s*(?:\[.*self-hosted.*\]|['\"]?self-hosted['\"]?)", re.IGNORECASE | re.DOTALL)
USES_ACTION_RE = re.compile(r"uses\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:@|\s|$)")
USES_REF_RE = re.compile(r"uses\s*:\s*([^\s#]+)")
PINNED_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")


def normalize_github_event(headers: Mapping[str, str], payload: Mapping[str, Any]) -> AuditEvent:
    event_name = _header(headers, "x-github-event") or "unknown"
    delivery_id = _header(headers, "x-github-delivery") or payload.get("delivery_id") or "unknown"
    action = _action(event_name, payload.get("action"))
    return AuditEvent(
        event_id=str(delivery_id),
        actor_login=_actor(payload),
        action=action,
        repository=_repository(payload),
        head_sha=_head_sha(payload),
        ip_address=(_header(headers, "x-forwarded-for") or "").split(",")[0].strip(),
        created_at=str(payload.get("sentinel_created_at") or utc_now_iso()),
        raw_payload=redacted_json(payload),
    )


def extract_changed_paths(payload: Mapping[str, Any]) -> list[str]:
    paths = set(payload.get("sentinel_changed_files") or [])
    for commit in payload.get("commits") or []:
        for key in ("added", "modified", "removed"):
            paths.update(str(path) for path in commit.get(key) or [])
    for file_obj in (payload.get("pull_request") or {}).get("sentinel_files") or []:
        paths.add(file_obj if isinstance(file_obj, str) else str(file_obj.get("filename", "")))
    return sorted(path for path in paths if path)


def touches_agent_config(paths: list[str]) -> bool:
    return any(_is_agent_config(path) for path in paths)


def new_actor_detected(payload: Mapping[str, Any], action: str) -> bool:
    if action == "member_added" or payload.get("actor_contribution_count") == 0:
        return True
    return (payload.get("pull_request") or {}).get("author_association") in {"FIRST_TIME_CONTRIBUTOR", "NONE"}


def extract_dependency_refs(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    refs = []
    for item in payload.get("sentinel_dependencies") or []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("package_name") or "").strip()
        version = str(item.get("version") or "").strip()
        ecosystem = str(item.get("ecosystem") or "npm").strip().lower()
        if name and version:
            refs.append({"name": name, "version": version, "ecosystem": ecosystem})
    return refs


def pr_secret_vectors(payload: Mapping[str, Any]) -> list[str]:
    vectors = []
    if contains_secret((payload.get("pull_request") or {}).get("body")):
        vectors.append("credential_in_pr_body")
    for comment in payload.get("sentinel_pr_comments") or []:
        if isinstance(comment, Mapping) and contains_secret(comment.get("body")):
            vectors.append("credential_in_pr_comment")
    return vectors


def workflow_vectors(files: Mapping[str, str]) -> list[str]:
    vectors: list[str] = []
    for path, content in files.items():
        normalized = path.replace("\\", "/")
        if not normalized.startswith(".github/workflows/"):
            continue
        if "write-all" in content or re.search(r"permissions\s*:\s*write", content):
            vectors.append("workflow_permission_escalation")
        for action_ref in USES_REF_RE.findall(content):
            if not PINNED_ACTION_RE.fullmatch(action_ref.strip("'\"")):
                vectors.append("unpinned_external_action")
    return vectors


def scan_for_exfiltration(diff_patches: Mapping[str, str]) -> bool:
    for path, patch in diff_patches.items():
        if not _is_ci_exfiltration_scope(path):
            continue
        for line in _added_lines(patch):
            if NETWORK_TOOL_RE.search(line) and EXPLICIT_DEST_RE.search(line):
                return True
    return False


def check_self_hosted_runner(workflow_patches: Mapping[str, str], is_first_time_actor: bool) -> bool:
    if not is_first_time_actor:
        return False
    return any(_is_workflow(path) and SELF_HOSTED_RE.search("\n".join(_added_lines(patch))) for path, patch in workflow_patches.items())


def detect_force_push_after_approval(payload: Mapping[str, Any], reviews: list[Mapping[str, Any]]) -> bool:
    if _action(str(_header(payload.get("sentinel_headers") or {}, "x-github-event") or "pull_request"), payload.get("action")) != "pr_synchronize":
        if payload.get("action") != "synchronize":
            return False
    return any(str(review.get("state") or "").upper() == "APPROVED" for review in reviews)


def detect_unsigned_maintainer_commit(commits: list[Mapping[str, Any]], actor_login: str, core_maintainers: set[str]) -> bool:
    if actor_login not in core_maintainers:
        return False
    for commit in commits:
        verification = commit.get("verification") or {}
        if isinstance(verification, Mapping) and verification.get("verified") is False:
            return True
    return False


def detect_action_typosquat(workflow_patches: Mapping[str, str]) -> bool:
    for path, patch in workflow_patches.items():
        if not _is_workflow(path):
            continue
        for line in _added_lines(patch):
            match = USES_ACTION_RE.search(line)
            if not match:
                continue
            action = match.group(1)
            if action in KNOWN_ACTIONS:
                continue
            if min((_levenshtein(action, known) for known in KNOWN_ACTIONS), default=99) <= 2:
                return True
    return False


def detect_malicious_skill_content(agent_files: Mapping[str, str]) -> bool:
    for path, content in agent_files.items():
        if not _is_agent_config(path):
            continue
        if SECRET_ACCESS_RE.search(content) and EXPLICIT_DEST_RE.search(content):
            return True
    return False


def extract_owner_change(socket_finding: Mapping[str, Any]) -> bool:
    text = " ".join(str(socket_finding.get(key) or "") for key in ("issue_type", "type", "key", "title", "description")).lower()
    return any(marker.lower() in text for marker in ("newMaintainer", "maintainerChange", "abandonedPackage", "orphan", "owner change"))


def apply_attack_flags(event: AuditEvent, flags: Mapping[str, bool]) -> AuditEvent:
    return replace(event, **{key: bool(value) for key, value in flags.items() if hasattr(event, key)})


def payload_from_bytes(body: bytes) -> dict[str, Any]:
    return json.loads(body.decode("utf-8"))


def _header(headers: Mapping[str, str], key: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == key.lower()), None)


def _action(event_name: str, action: object) -> str:
    suffix = str(action or "").strip()
    if event_name == "pull_request" and suffix:
        return f"pr_{suffix}"
    if event_name == "member" and suffix == "added":
        return "member_added"
    return f"{event_name}_{suffix}" if suffix else event_name


def _actor(payload: Mapping[str, Any]) -> str:
    for key in ("sender", "member", "pusher"):
        value = payload.get(key) or {}
        if isinstance(value, Mapping) and (value.get("login") or value.get("name")):
            return str(value.get("login") or value.get("name"))
    return "unknown"


def _repository(payload: Mapping[str, Any]) -> str:
    repo = payload.get("repository") or {}
    return str(repo.get("full_name") or repo.get("name") or "") if isinstance(repo, Mapping) else ""


def _head_sha(payload: Mapping[str, Any]) -> str:
    head = (payload.get("pull_request") or {}).get("head") or {}
    if isinstance(head, Mapping) and head.get("sha"):
        return str(head["sha"])
    return str(payload.get("after") or payload.get("head_sha") or "")


def _is_agent_config(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized == p.rstrip("/") or normalized.startswith(p) for p in AGENT_CONFIG_PATHS)


def _added_lines(patch: str) -> list[str]:
    if "\n+" not in f"\n{patch}":
        return [line.strip() for line in patch.splitlines() if line.strip()]
    return [line[1:].strip() for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")]


def _is_workflow(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.startswith(".github/workflows/") and normalized.endswith((".yml", ".yaml"))


def _is_ci_exfiltration_scope(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    return _is_workflow(normalized) or normalized.startswith("scripts/") or normalized in CI_EXFILTRATION_PATHS or name.endswith((".sh", ".ps1", ".bash"))


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (left_char != right_char)))
        previous = current
    return previous[-1]
