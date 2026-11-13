SELECT ts, actor, action, detail
FROM audit
ORDER BY id DESC
LIMIT ?1;
