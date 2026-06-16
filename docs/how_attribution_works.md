# How attribution works

## The problem

PgBouncer in **transaction pooling mode** multiplexes many client connections
onto a small pool of backend connections. Every one of those backend
connections authenticates to PostgreSQL as a single shared role — `app_user`.

So when PostgreSQL logs a query (via `log_statement`, `pgaudit`, or
`pg_stat_activity`), the user it records is always `app_user`. The human who
actually ran the query is invisible to the database.

```
  alice ─┐
  bob   ─┼──▶ [ PgBouncer ]──▶ all connections = app_user ──▶ [ PostgreSQL ]
  carol ─┘    transaction mode                                  log: "app_user"
```

Under GDPR Art. 32 (and Art. 30 records of processing), "a query happened as
`app_user`" is not an adequate audit trail for special-category data.

## The fix

Carry the real user identity *in band* and record it before the query runs.

```
  alice ─┐                                          ┌─▶ patients (the query)
  bob   ─┼─▶ SET LOCAL scalple.user_id = 'bob-002' ─┤
  carol ─┘   (one extra line per transaction)       └─▶ scalple.audit_log
                                                         real_user = 'bob-002'
                                                         db_role   = 'app_user'
                                                         (append-only)
```

### Step 1 — the app declares who it is

```sql
SET LOCAL scalple.user_id = 'bob-002';
SELECT * FROM patients WHERE id = 'p-001';
```

`SET LOCAL` is **transaction-scoped**. It resets on `COMMIT`/`ROLLBACK`, so it
is safe under transaction pooling — a pooled backend connection handed to the
next client carries no leftover identity. This is the key property that makes
the pattern correct behind PgBouncer.

If the variable is never set (legacy code path), the middleware records
`real_user = 'UNATTRIBUTED'` rather than failing silently.

### Step 2 — the middleware records it

Before the query executes, `ScalpleAuditor` reads the variable with
`current_setting('scalple.user_id', true)`, derives the action and table, and
writes one row to `scalple.audit_log` using a dedicated `audit_writer`
connection.

`audit_writer` holds **INSERT only** — no `UPDATE`, `DELETE`, or `TRUNCATE`.
Even the process doing the logging cannot rewrite history.

## Why partitioning matters

`scalple.audit_log` is `PARTITION BY RANGE (logged_at)`. Old partitions are
archived by **`DETACH`** — which preserves the rows as an independent table
outside the reach of `audit_writer` — rather than by `DELETE`. Combined with a
WORM cold store (object-lock / immutability policy), this is the tamper-evidence
story for protecting against a privileged DBA, a threat the live `audit_writer`
grant alone does not cover.
