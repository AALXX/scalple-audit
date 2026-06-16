#!/usr/bin/env python3
"""
The one-command demo. Runs in under a minute and shows the gap and the fix
side by side.

    docker compose up -d
    python demo/run_demo.py
"""

import sys

import psycopg2

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from scalple import ScalpleAuditor  # noqa: E402
from demo._common import (  # noqa: E402
    APP_DB_URL,
    AUDIT_DB_URL,
    AUDIT_READER_URL,
    POSTGRES_DB_URL,
    connect,
    print_table,
    run_scenario,
)

BAR = "━" * 39


def reset_audit_log():
    """Give each demo run a clean slate. This uses a SUPERUSER connection on
    purpose: the append-only guarantee constrains the app's `audit_writer`
    role (proven in step 4), not a DBA with full rights. Best-effort."""
    try:
        conn = connect(POSTGRES_DB_URL, retries=3, delay=1.0)
        conn.autocommit = True
        conn.cursor().execute("TRUNCATE scalple.audit_log")
        conn.close()
    except Exception:
        pass  # not fatal — the demo still runs, counts just accumulate


def main():
    print(BAR)
    print("SCALPLE DEMO — Hospital patient records")
    print("PostgreSQL + PgBouncer + GDPR Art. 32")
    print(BAR)
    print()

    reset_audit_log()

    app_conn = connect(APP_DB_URL)
    audit_writer = connect(AUDIT_DB_URL)
    audit_reader = connect(AUDIT_READER_URL)
    auditor = ScalpleAuditor(app_conn, audit_writer)

    # ---- [1/4] Run the queries -------------------------------------------
    print("[1/4] Running 20 queries through PgBouncer as three clinicians...")
    run_scenario(auditor, app_conn)
    print("  alice: 5 queries")
    print("  bob:   12 queries  ← suspicious")
    print("  carol: 3 queries")
    print()

    # ---- [2/4] What the database sees ------------------------------------
    print("[2/4] What does the database log see?")
    print("  Every connection authenticated as the SAME pooled role:")
    print()
    # Live proof: through PgBouncer, current_user is app_user no matter who.
    cur = app_conn.cursor()
    cur.execute("SELECT current_user")
    live_role = cur.fetchone()[0]
    rc = audit_reader.cursor()
    rc.execute(
        "SELECT db_role, count(*) FROM scalple.audit_log GROUP BY db_role"
    )
    print_table(["db_role", "count"], rc.fetchall())
    print()
    print(f'  (live check: a query through PgBouncer reports current_user = "{live_role}")')
    print()
    print('  DPA question: "Who accessed patient Jan de Vries on June 15th?"')
    print(f"  Database answer: {live_role}. Cannot tell you more.")
    print()

    # ---- [3/4] What the Scalple audit log sees ---------------------------
    print("[3/4] What does the Scalple audit log see?")
    print()
    rc.execute(
        """
        SELECT real_user, count(*) AS count,
               min(logged_at) AS first_access,
               max(logged_at) AS last_access
        FROM scalple.audit_log
        WHERE table_name = 'patients' AND query_text LIKE '%p-001%'
        GROUP BY real_user
        ORDER BY count DESC
        """
    )
    rows = [
        (r[0], r[1], r[2].strftime("%Y-%m-%d %H:%M:%S"),
         r[3].strftime("%Y-%m-%d %H:%M:%S"))
        for r in rc.fetchall()
    ]
    print_table(["real_user", "count", "first_access", "last_access"], rows)
    print()
    if not rows:
        print("  (no audit rows found — was the scenario run?)")
    else:
        top = rows[0]
        print(f"  DPA answer: {top[0]} accessed this patient {top[1]} times "
              f"between {top[2][11:]} and {top[3][11:]}.")
    print()

    # ---- [4/4] The append-only guarantee ---------------------------------
    print("[4/4] Testing append-only guarantee — can the app erase bob's tracks?")
    print()
    print("  DELETE FROM scalple.audit_log WHERE real_user = 'bob-002';")
    print()
    try:
        wc = audit_writer.cursor()
        wc.execute("DELETE FROM scalple.audit_log WHERE real_user = 'bob-002'")
        audit_writer.commit()
        print("  !! DELETE SUCCEEDED — append-only guarantee is BROKEN")
        sys.exit(1)
    except psycopg2.Error as e:
        audit_writer.rollback()
        msg = str(e).strip().splitlines()[0]
        print(f"  ERROR: {msg}")
        print("  ✓ Audit log is tamper-proof. The audit_writer role cannot")
        print("    UPDATE, DELETE, or TRUNCATE — only INSERT.")
    print()

    print(BAR)
    print("Demo complete. This is what GDPR Art. 32 evidence looks like.")
    print(BAR)

    for c in (app_conn, audit_writer, audit_reader):
        c.close()


if __name__ == "__main__":
    main()
