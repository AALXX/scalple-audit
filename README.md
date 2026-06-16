<div align="center">
  <a href="https://scalple.com">
    <img src="assets/Scalple_Logo.png" alt="Scalple" width="260">
  </a>
</div>

# scalple-audit

> Append-only per-user audit log for PostgreSQL behind PgBouncer. Survives a hostile DBA. MIT.

An open-source illustration of the PostgreSQL attribution gap that [**scalple.com**](https://scalple.com) is built to close —
the GDPR-first production database ops platform for engineering teams handling special-category data.

---

**PostgreSQL logs `app_user`. Not the human.** This repo shows what that costs
you under GDPR Art. 32 and how to fix it in one afternoon.

## The 30-second context

When you put PostgreSQL behind **PgBouncer in transaction mode**, the pooler
multiplexes every client onto a small set of backend connections that all
authenticate as one shared role `app_user`. So `pgaudit`, `log_statement`,
and `pg_stat_activity` only ever record `app_user`. The individual is invisible.

A DPA investigator asks: *"Who accessed patient record 7 on March 15th at
14:23?"* The honest answer your database can give is **`app_user`**. That is
not a compliant audit trail for special-category data.

This repo fixes it with a tiny attribution pattern: the app sets
`SET LOCAL scalple.user_id = 'alice'` in each transaction (one line of code),
and a ~100-line middleware writes that to an **append-only** audit table before
the query runs. The `audit_writer` role has `INSERT` only no `UPDATE`,
`DELETE`, or `TRUNCATE`. A rogue process cannot cover its tracks. It runs in one
Docker command on fake hospital data.

## Quick start

```bash
git clone https://github.com/AALXX/scalple-audit
cd scalple-audit
docker compose up -d
python demo/run_demo.py        # needs: pip install psycopg2-binary
```

No local Python? Run the demo in a container instead:

```bash
docker compose up -d
docker compose run --rm demo
```

Total runtime: under 60 seconds.

## What the demo shows

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCALPLE DEMO Hospital patient records
PostgreSQL + PgBouncer + GDPR Art. 32
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1/4] Running 20 queries through PgBouncer as three clinicians...
  alice: 5 queries
  bob:   12 queries  ← suspicious
  carol: 3 queries

[2/4] What does the database log see?
  The audit log's own db_role column what PostgreSQL authenticated
  every connection as shows one role for all 20 queries:

  db_role  | count
  ---------+------
  app_user | 20

  (live check: SELECT current_user through PgBouncer → "app_user")

  DPA question: "Who accessed patient Jan de Vries on June 15th?"
  Database answer: app_user. Cannot tell you more.

[3/4] What does the Scalple audit log see?

  real_user | count | first_access        | last_access
  ----------+-------+---------------------+--------------------
  bob-002   | 12    | 2026-06-15 14:23:07 | 2026-06-15 14:46:19
  alice-001 | 1     | 2026-06-15 14:31:52 | 2026-06-15 14:31:52

  DPA answer: bob-002 accessed this patient 12 times between 14:23:07 and 14:46:19.

[4/4] Testing append-only guarantee can the app erase bob's tracks?

  DELETE FROM scalple.audit_log WHERE real_user = 'bob-002';

  ERROR: permission denied for table audit_log
  ✓ Audit log is tamper-proof. The audit_writer role cannot
    UPDATE, DELETE, or TRUNCATE only INSERT.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Demo complete. This is what GDPR Art. 32 evidence looks like.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The timestamps (14:23–14:46) are hardcoded in the scenario so the forensic query
tells a realistic story without waiting 23 real minutes. The DELETE rejection in
step 4 is live PostgreSQL enforces it at the role level.

`demo/without_scalple.py` and `demo/with_scalple.py` show the gap and the fix in
isolation.

## How attribution works

```
SET LOCAL scalple.user_id = 'bob-002';   -- one extra line per transaction
SELECT * FROM patients WHERE id = 'p-001';
```

`SET LOCAL` is transaction-scoped, so it is safe under transaction pooling it
resets on `COMMIT`/`ROLLBACK` and never leaks between pooled sessions. The
middleware reads it with `current_setting('scalple.user_id', true)` and records
the real user alongside the `app_user` role the database actually saw. If it is
never set, the row is logged as `UNATTRIBUTED` never silently dropped.

Full diagram in [`docs/how_attribution_works.md`](docs/how_attribution_works.md).

## The append-only guarantee

```sql
GRANT INSERT ON scalple.audit_log TO audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON scalple.audit_log FROM audit_writer;
```

The middleware writes through `audit_writer`, which can only `INSERT`. Step 4 of
the demo proves it: a `DELETE` is rejected by PostgreSQL itself. The table is
`PARTITION BY RANGE (logged_at)`, so old data is archived by **`DETACH`** (which
moves it beyond `audit_writer`'s reach) rather than `DELETE` the tamper-evidence
story for protecting against a privileged DBA, when paired with a WORM cold store.

## What this is not

This is the open-source core the attribution pattern and the append-only
table, nothing more. Query parsing is a regex; there is no UI, no DPA report
formatter, no multi-DB support. The full platform with those features is at
[**scalple.com**](https://scalple.com).

## License

MIT see [`LICENSE`](LICENSE).
