SELECT actor_login, COUNT(*) AS event_count, MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
FROM sentinel.audit_events
GROUP BY actor_login
HAVING COUNT(*) > 1
ORDER BY event_count DESC
LIMIT 100
