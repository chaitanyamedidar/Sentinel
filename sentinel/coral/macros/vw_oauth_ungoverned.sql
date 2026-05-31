SELECT event_id, actor_login, action, repository, head_sha, created_at
FROM sentinel.audit_events
WHERE action LIKE '%oauth%'
ORDER BY created_at DESC
LIMIT 100
