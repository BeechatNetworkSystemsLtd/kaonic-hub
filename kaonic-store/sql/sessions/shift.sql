UPDATE sessions
SET created_ts = created_ts + ?1, last_used_ts = last_used_ts + ?1;
