CREATE TABLE account (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    changed_ts INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    created_ts INTEGER NOT NULL,
    last_used_ts INTEGER NOT NULL
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE wifi_networks (
    ssid TEXT PRIMARY KEY,
    position INTEGER NOT NULL,
    secured INTEGER NOT NULL,
    hidden INTEGER NOT NULL,
    auto_connect INTEGER NOT NULL,
    last_connected_ts INTEGER
);

CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
