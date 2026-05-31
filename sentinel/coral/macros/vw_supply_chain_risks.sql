SELECT sc.commit_sha, audit.repository, sc.package_name, sc.version, sc.ecosystem, sc.issue_type, sc.severity, sc.risk_score, sc.provider AS detection_provider, ep.package_age_hours, ep.maintainer_age_days, ep.has_postinstall, ep.name_edit_distance, ep.source_repo_present
FROM sentinel.supply_chain_findings sc
LEFT JOIN sentinel.enriched_packages ep ON ep.commit_sha = sc.commit_sha AND ep.package_name = sc.package_name
LEFT JOIN sentinel.audit_events audit ON audit.head_sha = sc.commit_sha
WHERE sc.package_name IS NOT NULL OR ep.package_age_hours < 48 OR ep.has_postinstall = true OR ep.name_edit_distance <= 2
ORDER BY sc.written_at DESC
LIMIT 100
