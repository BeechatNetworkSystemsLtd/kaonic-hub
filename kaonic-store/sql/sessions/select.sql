SELECT csrf_token, role, created_ts, last_used_ts
FROM sessions
WHERE token_hash = ?1;
