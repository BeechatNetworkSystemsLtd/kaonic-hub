SELECT count(*), coalesce(sum(length(key) + length(value)), 0) FROM plugin_store
WHERE plugin = ?1 AND key != ?2;
