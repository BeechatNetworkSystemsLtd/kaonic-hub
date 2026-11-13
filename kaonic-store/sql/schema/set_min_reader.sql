INSERT INTO schema_info (id, min_reader) VALUES (1, ?1)
ON CONFLICT (id) DO UPDATE SET min_reader = excluded.min_reader;
