#!/usr/bin/env python3
"""
The fix, in isolation.

Run the same scenario through the ScalpleAuditor middleware, then read the
append-only audit log back per user.

    python demo/with_scalple.py
"""

import sys

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


def main():
    print("=== WITH scalple ===\n")

    # Clean slate (superuser) so counts are deterministic on rerun.
    try:
        su = connect(POSTGRES_DB_URL, retries=3)
        su.autocommit = True
        cur = su.cursor()
        cur.execute("TRUNCATE scalple.audit_log")
        cur.close()
        su.close()
    except Exception:
        pass

    app_conn = connect(APP_DB_URL)
    audit_writer = connect(AUDIT_DB_URL)
    audit_reader = connect(AUDIT_READER_URL)

    auditor = ScalpleAuditor(app_conn, audit_writer)
    run_scenario(auditor, app_conn)

    print("20 queries ran. The append-only audit log attributes every one:\n")
    rc = audit_reader.cursor()
    rc.execute(
        """
        SELECT real_user, count(*) AS n
        FROM scalple.audit_log
        GROUP BY real_user
        ORDER BY n DESC
        """
    )
    print_table(["real_user", "queries"], rc.fetchall())
    print()
    print("Forensic query — who accessed patient p-001?\n")
    rc.execute(
        """
        SELECT real_user, count(*) AS n,
               min(logged_at) AS first, max(logged_at) AS last
        FROM scalple.audit_log
        WHERE table_name = 'patients' AND query_text LIKE '%p-001%'
        GROUP BY real_user
        ORDER BY n DESC
        """
    )
    rows = [
        (r[0], r[1], r[2].strftime("%H:%M:%S"), r[3].strftime("%H:%M:%S"))
        for r in rc.fetchall()
    ]
    print_table(["real_user", "count", "first", "last"], rows)

    for c in (app_conn, audit_writer, audit_reader):
        c.close()


if __name__ == "__main__":
    main()
