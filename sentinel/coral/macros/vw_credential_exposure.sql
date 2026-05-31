SELECT
  alerts.commit_sha,
  alerts.actor_login,
  alerts.vector_type,
  alerts.score,
  alerts.severity,
  alerts.summary,
  alerts.created_at,
  audit.repository
FROM sentinel.alert_events alerts
LEFT JOIN sentinel.audit_events audit
  ON audit.head_sha = alerts.commit_sha
WHERE alerts.vector_type IN ('credential_in_pr_body', 'credential_in_pr_comment')
ORDER BY alerts.created_at DESC
LIMIT 100
