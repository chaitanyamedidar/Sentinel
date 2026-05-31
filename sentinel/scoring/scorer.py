from __future__ import annotations
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

SCORING_RULES = {
    "oauth_grant_no_approval": 40, "workspace_oauth_broad_scope": 35, "maintainer_anomalous_ip": 30,
    "supply_chain_malicious_package": 35, "osv_critical": 60, "osv_high": 60,
    "package_age_under_48h": 35, "maintainer_account_under_30d": 25, "has_postinstall_script": 30,
    "typosquat_distance_lte_2": 40, "no_source_repo": 20, "workflow_permission_escalation": 60,
    "unpinned_external_action": 60, "credential_in_pr_body": 35, "credential_in_pr_comment": 30,
    "merge_without_review": 60, "mcp_tool_poisoning_detected": 40, "malicious_skill_md_detected": 40,
    "unsigned_commit_core_maintainer": 60, "ci_exfiltration_script_detected": 50,
    "orphan_pkg_recent_owner_change": 60, "first_time_actor_self_hosted": 60,
    "force_push_after_approval": 60, "action_typosquat_distance_lte_2": 60,
}
TRUST_MODIFIERS = {"core_maintainer_over_1yr": -20, "first_time_contributor": 20}
BOT_ALLOWLIST = {"dependabot[bot]", "renovate[bot]", "github-actions[bot]"}
BYPASS_BUFFER = {"credential_in_pr_body", "credential_in_pr_comment", "supply_chain_malicious_package", "osv_critical", "osv_high", "package_age_under_48h", "mcp_tool_poisoning_detected", "malicious_skill_md_detected", "ci_exfiltration_script_detected", "unsigned_commit_core_maintainer"}
DEDUP_BYPASS = {"credential_in_pr_body", "credential_in_pr_comment", "mcp_tool_poisoning_detected", "malicious_skill_md_detected"}
BOOLEAN_FLAG_TO_RULE = {
    "ci_exfiltration_detected": "ci_exfiltration_script_detected",
    "self_hosted_first_actor": "first_time_actor_self_hosted",
    "force_push_after_approval": "force_push_after_approval",
    "unsigned_maintainer_commit": "unsigned_commit_core_maintainer",
    "action_typosquat_detected": "action_typosquat_distance_lte_2",
    "orphan_pkg_owner_change": "orphan_pkg_recent_owner_change",
}

@dataclass(frozen=True)
class Alert:
    commit_sha: str
    actor_login: str
    vector_type: str
    score: int
    severity: str
    detection_provider: str
    summary: str
    repository: str = ""
    evidence_url: str = ""
    @property
    def bypass_buffer(self) -> bool: return self.vector_type in BYPASS_BUFFER
    @property
    def bypass_dedup(self) -> bool: return self.vector_type in DEDUP_BYPASS

def score_findings(commit_sha: str, actor_login: str, supply_chain: list[Mapping], enriched_packages: list[Mapping], mcp_findings: list[Mapping], direct_vectors: list[str] | None = None, event_flags: Mapping[str, bool] | None = None, first_time_contributor: bool = False, threshold: int = 60) -> list[Alert]:
    if actor_login in BOT_ALLOWLIST:
        return []
    vectors = Counter(direct_vectors or [])
    for flag, rule in BOOLEAN_FLAG_TO_RULE.items():
        if (event_flags or {}).get(flag):
            vectors[rule] += 1
    provider = ""
    for finding in supply_chain:
        provider = str(finding.get("provider") or provider)
        if str(finding.get("severity") or "").upper() in {"HIGH", "CRITICAL"} or "malicious" in str(finding.get("issue_type") or "").lower():
            vectors["supply_chain_malicious_package"] += 1
    for package in enriched_packages:
        if float(package.get("package_age_hours") or 999999) < 48: vectors["package_age_under_48h"] += 1
        if int(package.get("maintainer_age_days") or 9999) < 30: vectors["maintainer_account_under_30d"] += 1
        if bool(package.get("has_postinstall")): vectors["has_postinstall_script"] += 1
        if int(package.get("name_edit_distance") or 9999) <= 2: vectors["typosquat_distance_lte_2"] += 1
        if package.get("source_repo_present") is False: vectors["no_source_repo"] += 1
    for finding in mcp_findings:
        kind = str(finding.get("finding_type") or "").lower()
        if "poison" in kind: vectors["mcp_tool_poisoning_detected"] += 1
        if "skill" in kind and "malicious" in kind: vectors["malicious_skill_md_detected"] += 1
    modifier = TRUST_MODIFIERS["first_time_contributor"] if first_time_contributor else 0
    alerts = []
    for vector, count in vectors.items():
        score = SCORING_RULES.get(vector, 0) + modifier + (min(20, (count - 1) * 5) if count > 1 else 0)
        alert_score = max(score, threshold) if vector in BYPASS_BUFFER else score
        if alert_score >= threshold:
            alerts.append(Alert(commit_sha, actor_login, vector, alert_score, "CRITICAL" if vector in BYPASS_BUFFER or alert_score >= 80 else "HIGH", provider, f"{vector} detected for {actor_login} on {commit_sha[:7]}"))
    return alerts
