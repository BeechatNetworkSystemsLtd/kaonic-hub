CREATE TABLE schema_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    min_reader INTEGER NOT NULL CHECK (min_reader >= 1)
) STRICT;
