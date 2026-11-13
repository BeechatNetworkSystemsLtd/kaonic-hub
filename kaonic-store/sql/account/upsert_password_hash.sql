INSERT INTO account (id, password_hash, changed_ts)
VALUES (1, ?1, ?2)
ON CONFLICT (id) DO UPDATE SET
    password_hash = excluded.password_hash,
    changed_ts = excluded.changed_ts;
