CREATE TABLE plugin_store (
    plugin TEXT NOT NULL,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (plugin, key)
) STRICT;
