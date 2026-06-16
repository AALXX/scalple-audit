-- audit_schema.sql — the append-only, per-user audit log and the roles that
-- enforce its immutability.
--
-- Two roles, two jobs:
--   audit_writer  — INSERT only. No UPDATE, DELETE, or TRUNCATE. The middleware
--                   holds these credentials. A rogue process (or DBA) using this
--                   role cannot alter or erase history.
--   audit_reader  — SELECT only. The role a DPA investigator / auditor uses.

CREATE SCHEMA IF NOT EXISTS scalple;

-- ---------------------------------------------------------------------------
-- The audit log. Partitioned by time so old partitions can be DETACHED (which
-- preserves the data outside the reach of audit_writer) rather than deleted.
-- ---------------------------------------------------------------------------
CREATE TABLE scalple.audit_log (
    id           BIGSERIAL,
    logged_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    real_user    TEXT        NOT NULL,   -- the person (e.g. alice@hospital.nl)
    db_role      TEXT        NOT NULL,   -- what PostgreSQL actually sees (app_user)
    action       TEXT        NOT NULL,   -- SELECT / INSERT / UPDATE / DELETE
    table_name   TEXT,
    row_id       TEXT,                   -- best-effort, null if not extractable
    query_hash   TEXT        NOT NULL,   -- SHA-256 of the query text
    query_text   TEXT,                   -- full query if GDPR-safe, else redacted
    client_addr  INET,
    session_id   TEXT        NOT NULL,
    PRIMARY KEY (id, logged_at)          -- partition key must be in the PK
) PARTITION BY RANGE (logged_at);

-- One partition covering the current year. Add a new partition per year/month;
-- archive old ones by DETACH (tamper-evidence) instead of DELETE.
CREATE TABLE scalple.audit_log_2026
    PARTITION OF scalple.audit_log
    FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

-- Helpful indexes for forensic queries ("who touched this row, when?").
CREATE INDEX audit_real_user_idx ON scalple.audit_log (real_user);
CREATE INDEX audit_logged_at_idx ON scalple.audit_log (logged_at);
CREATE INDEX audit_table_idx     ON scalple.audit_log (table_name);

-- ---------------------------------------------------------------------------
-- audit_writer — INSERT only.
-- ---------------------------------------------------------------------------
SET password_encryption = 'md5';
CREATE ROLE audit_writer WITH LOGIN PASSWORD 'audit_password';
RESET password_encryption;

GRANT USAGE ON SCHEMA scalple TO audit_writer;
-- INSERT on the parent table is necessary but not sufficient for partitioned
-- tables. PostgreSQL also checks the INSERT permission on the target partition
-- for each row routed. Both grants below are required; the parent grant alone
-- is not enough. IMPORTANT: when you add a new partition (e.g. audit_log_2027)
-- you must run:
--   GRANT INSERT ON scalple.audit_log_2027 TO audit_writer;
-- There is no ALTER DEFAULT PRIVILEGES mechanism for partitions.
GRANT INSERT ON scalple.audit_log TO audit_writer;
GRANT INSERT ON scalple.audit_log_2026 TO audit_writer;
-- BIGSERIAL needs sequence access to allocate ids.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA scalple TO audit_writer;

-- Explicitly strip everything that would let history be rewritten. These are
-- belt-and-suspenders: a freshly created role has no such grants anyway, but
-- stating them makes the guarantee auditable.
REVOKE UPDATE, DELETE, TRUNCATE ON scalple.audit_log      FROM audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON scalple.audit_log_2026 FROM audit_writer;

-- ---------------------------------------------------------------------------
-- audit_reader — SELECT only (for DPA auditors).
-- ---------------------------------------------------------------------------
SET password_encryption = 'md5';
CREATE ROLE audit_reader WITH LOGIN PASSWORD 'audit_password';
RESET password_encryption;
GRANT USAGE ON SCHEMA scalple TO audit_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA scalple TO audit_reader;
-- ALTER DEFAULT PRIVILEGES covers regular tables created after this script
-- runs, but NOT partitions. When you add a new partition (e.g. audit_log_2027)
-- you must also run:
--   GRANT SELECT ON scalple.audit_log_2027 TO audit_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA scalple GRANT SELECT ON TABLES TO audit_reader;
