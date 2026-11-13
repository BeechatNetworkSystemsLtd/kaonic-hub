DELETE FROM sessions
WHERE ?1 - last_used_ts > ?2
   OR ?1 - created_ts > ?3;
