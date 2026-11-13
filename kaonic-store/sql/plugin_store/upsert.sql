INSERT INTO plugin_store (plugin, key, value) VALUES (?1, ?2, ?3)
ON CONFLICT (plugin, key) DO UPDATE SET value = excluded.value;
