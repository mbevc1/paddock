CREATE TABLE users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    role           TEXT NOT NULL CHECK (role IN ('owner', 'admin')),
    owner_id       INTEGER,
    password_hash  TEXT NOT NULL,
    -- Owners only: admins' TOTP secrets live in the agent's state.db.
    totp_secret    BLOB,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    totp_required  INTEGER NOT NULL DEFAULT 0 CHECK (totp_required IN (0, 1)),
    disabled       INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at     TEXT NOT NULL,
    CHECK (role = 'admin' OR owner_id IS NOT NULL),
    CHECK (role = 'owner' OR totp_secret IS NULL)
);

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE identities (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer  TEXT NOT NULL,
    subject TEXT NOT NULL,
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    ip            TEXT NOT NULL,
    user_agent    TEXT NOT NULL,
    -- Set once the second factor passed, or at login when none is needed.
    mfa_at        TEXT,
    -- Last password or TOTP check, for step-up.
    auth_at       TEXT NOT NULL,
    csrf_token    TEXT NOT NULL,
    impersonating INTEGER
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE invitations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    owner_id   INTEGER,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin')),
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    read_at    TEXT
);
CREATE INDEX notifications_user ON notifications (user_id, id);

CREATE TABLE login_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER,
    username TEXT NOT NULL,
    ip       TEXT NOT NULL,
    success  INTEGER NOT NULL CHECK (success IN (0, 1)),
    time     TEXT NOT NULL
);
CREATE INDEX login_events_user ON login_events (user_id, ip);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
