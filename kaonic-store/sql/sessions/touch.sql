UPDATE sessions
SET last_used_ts = ?2
WHERE token_hash = ?1;
