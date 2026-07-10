-- reap loot store schema. Normalized; the spine everything reads/writes.
-- Persists across pivots within an engagement. IF NOT EXISTS keeps re-opening
-- an existing engagement DB idempotent.

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    os TEXT,
    notes TEXT,
    first_seen TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id),
    port INTEGER,
    proto TEXT,            -- ssh, mysql, mongodb, http, winrm, ...
    product TEXT,
    notes TEXT,
    remote_host TEXT       -- for conn-string services: the DB host from the URL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,    -- 'password' | 'hash' | 'ssh_key' | 'token' | 'capability'
    username TEXT,         -- nullable (a lone secret may have no user yet)
    secret TEXT,           -- the password/key/hash/secret material
    source TEXT,           -- where it was found: file path, env, module name
    host_id INTEGER REFERENCES hosts(id),
    metadata TEXT,         -- JSON: e.g. {"capability":"jwt_sign","alg":"HS256"}
    verified_against TEXT  -- JSON list of service ids it successfully authed to
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,    -- 'credential' | 'capability' | 'misconfig' | 'info'
    severity TEXT,         -- 'high' | 'medium' | 'low' — drives ranking
    title TEXT,
    detail TEXT,
    source_module TEXT,
    host_id INTEGER REFERENCES hosts(id),
    created TEXT,
    note TEXT              -- operator annotation (set via the console 'note' command)
);
