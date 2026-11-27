-- Values the agent keeps about itself, such as the version it last reconciled for.
CREATE TABLE agent_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
