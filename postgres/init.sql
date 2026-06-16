-- init.sql — application schema + the shared application role.
--
-- This is the "normal" half of the setup: the tables the app reads/writes and
-- the single database role (app_user) that every pooled connection authenticates
-- as. This shared role is exactly what creates the attribution gap that the
-- scalple audit log solves.

-- ---------------------------------------------------------------------------
-- The application role.
--
-- Every connection through PgBouncer (transaction mode) authenticates as this
-- ONE role. PostgreSQL — and therefore pgaudit / the server log — only ever
-- sees "app_user", never the human behind the query.
--
-- Password is stored as md5 so PgBouncer's md5 auth (userlist.txt) works
-- end-to-end against PostgreSQL 16 (whose default is scram-sha-256).
-- ---------------------------------------------------------------------------
SET password_encryption = 'md5';
CREATE ROLE app_user WITH LOGIN PASSWORD 'app_password';
RESET password_encryption;

-- ---------------------------------------------------------------------------
-- Application tables. Fake data only — no real PII. See seed_data.sql.
-- ---------------------------------------------------------------------------
CREATE TABLE clinicians (
    id          TEXT PRIMARY KEY,   -- application user id (NOT a database role)
    name        TEXT NOT NULL,
    department  TEXT NOT NULL
);

CREATE TABLE patients (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    dob         DATE NOT NULL,
    diagnosis   TEXT NOT NULL,      -- GDPR Art. 9 special-category data
    risk_level  TEXT NOT NULL
);

CREATE TABLE appointments (
    id                TEXT PRIMARY KEY,
    patient_id        TEXT NOT NULL REFERENCES patients(id),
    clinician_id      TEXT NOT NULL REFERENCES clinicians(id),
    appointment_date  DATE NOT NULL,
    notes             TEXT
);

-- app_user can read and write application data — but has NO access to the
-- scalple schema (granted separately in audit_schema.sql, only to audit roles).
-- The application literally cannot touch the audit log.
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
