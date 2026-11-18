CREATE TABLE events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     TEXT NOT NULL,
    kind     TEXT NOT NULL,
    owner_id INTEGER,
    vhost_n  INTEGER,
    message  TEXT NOT NULL
);
CREATE INDEX events_kind_vhost ON events (kind, vhost_n, time);

-- Hysteresis for quota notifications and enforcement, one row per owner.
CREATE TABLE quota_state (
    owner_id   INTEGER PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    warned     INTEGER NOT NULL DEFAULT 0 CHECK (warned IN (0, 1)),
    enforced   INTEGER NOT NULL DEFAULT 0 CHECK (enforced IN (0, 1)),
    updated_at TEXT NOT NULL
);
