CREATE TABLE owners (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE limits (
    owner_id             INTEGER PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    max_vhosts           INTEGER NOT NULL CHECK (max_vhosts >= 0),
    disk_mb              INTEGER NOT NULL CHECK (disk_mb >= 0),
    max_databases        INTEGER NOT NULL CHECK (max_databases >= 0),
    max_db_users         INTEGER NOT NULL CHECK (max_db_users >= 0),
    max_access_accounts  INTEGER NOT NULL CHECK (max_access_accounts >= 0),
    shell_allowed        INTEGER NOT NULL CHECK (shell_allowed IN (0, 1)),
    -- Comma-separated versions; empty means every installed version.
    php_versions         TEXT NOT NULL,
    memory_max_mb        INTEGER NOT NULL CHECK (memory_max_mb > 0),
    cpu_quota_pct        INTEGER NOT NULL CHECK (cpu_quota_pct > 0),
    tasks_max            INTEGER NOT NULL CHECK (tasks_max > 0),
    pm_max_children      INTEGER NOT NULL CHECK (pm_max_children > 0),
    max_user_connections INTEGER NOT NULL CHECK (max_user_connections > 0)
);

CREATE TABLE php_versions (
    version      TEXT PRIMARY KEY,
    installed_at TEXT NOT NULL
);

-- AUTOINCREMENT keeps vhost numbers from ever being reused.
CREATE TABLE vhosts (
    n           INTEGER PRIMARY KEY AUTOINCREMENT CHECK (n BETWEEN 1 AND 65535),
    id          TEXT NOT NULL UNIQUE,
    owner_id    INTEGER NOT NULL REFERENCES owners (id),
    uid         INTEGER NOT NULL UNIQUE,
    php_version TEXT NOT NULL REFERENCES php_versions (version),
    status      TEXT NOT NULL CHECK (status IN ('creating', 'active', 'suspended', 'deleting', 'failed')),
    created_at  TEXT NOT NULL
);
CREATE INDEX vhosts_owner ON vhosts (owner_id);

CREATE TABLE domains (
    name       TEXT PRIMARY KEY,
    vhost_n    INTEGER NOT NULL REFERENCES vhosts (n) ON DELETE CASCADE,
    is_primary INTEGER NOT NULL CHECK (is_primary IN (0, 1))
);
CREATE INDEX domains_vhost ON domains (vhost_n);
CREATE UNIQUE INDEX domains_one_primary ON domains (vhost_n) WHERE is_primary = 1;

CREATE TABLE databases (
    name       TEXT PRIMARY KEY,
    vhost_n    INTEGER NOT NULL REFERENCES vhosts (n) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE INDEX databases_vhost ON databases (vhost_n);

CREATE TABLE db_users (
    name       TEXT PRIMARY KEY,
    vhost_n    INTEGER NOT NULL REFERENCES vhosts (n) ON DELETE CASCADE,
    grants     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX db_users_vhost ON db_users (vhost_n);

CREATE TABLE access_accounts (
    name       TEXT PRIMARY KEY,
    vhost_n    INTEGER NOT NULL REFERENCES vhosts (n) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('sftp', 'shell')),
    created_at TEXT NOT NULL
);
CREATE INDEX access_accounts_vhost ON access_accounts (vhost_n);

CREATE TABLE ssh_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     TEXT NOT NULL REFERENCES access_accounts (name) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (account, fingerprint)
);

CREATE TABLE certs (
    vhost_n     INTEGER PRIMARY KEY REFERENCES vhosts (n) ON DELETE CASCADE,
    source      TEXT NOT NULL CHECK (source IN ('acme', 'upload')),
    not_after   TEXT,
    fingerprint TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE admins (
    user_id        INTEGER PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    totp_secret    BLOB NOT NULL,
    last_used_step INTEGER NOT NULL DEFAULT 0,
    window_until   TEXT
);

CREATE TABLE jobs (
    id            TEXT PRIMARY KEY,
    op            TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    actor_user_id INTEGER,
    owner_id      INTEGER,
    result        TEXT,
    error_code    TEXT,
    error_message TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    time   TEXT NOT NULL,
    actor  TEXT NOT NULL,
    op     TEXT NOT NULL,
    args   TEXT NOT NULL,
    result TEXT NOT NULL
);
