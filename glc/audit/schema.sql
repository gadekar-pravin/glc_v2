-- glc_v1 audit log schema v2. SQLite triggers enforce append-only DML,
-- and each immutable row is linked to the SHA-256 hash of its predecessor.

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT    NOT NULL
                            CHECK(length(prev_hash) = 64
                                  AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    entry_hash      TEXT    NOT NULL
                            CHECK(length(entry_hash) = 64
                                  AND entry_hash NOT GLOB '*[^0-9a-f]*')
);

CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX idx_audit_channel ON audit_log(channel, ts DESC);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TABLE audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT INTO audit_schema (version, applied_at) VALUES (2, strftime('%s','now'));
