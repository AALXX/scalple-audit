#!/usr/bin/env python3
"""
The gap, in isolation.

Run the scenario through PgBouncer WITHOUT the audit middleware and ask the
database who did what. The only answer it can give is `app_user`.

    python demo/without_scalple.py
"""

import sys

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from demo._common import APP_DB_URL, connect, print_table, scenario  # noqa: E402


def main():
    print("=== WITHOUT scalple ===\n")
    app_conn = connect(APP_DB_URL)

    seen_roles = set()
    for real_user, query, _ts in scenario():
        cur = app_conn.cursor()
        # The app "knows" who it is — but it never tells the database in a way
        # the database records. PgBouncer collapses everyone to one role.
        cur.execute("SELECT set_config('scalple.user_id', %s, true)", (real_user,))
        cur.execute(query)
        cur.fetchall()
        cur.execute("SELECT current_user")
        seen_roles.add(cur.fetchone()[0])
        app_conn.commit()

    print("20 queries ran as 3 different clinicians.")
    print("The role PostgreSQL authenticated every one of them as:\n")
    print_table(["db_role PostgreSQL saw"], [[r] for r in sorted(seen_roles)])
    print()
    print('DPA question: "Who accessed patient p-001 on June 15th?"')
    print(f"Database answer: {', '.join(sorted(seen_roles))}. Nothing more.")
    print("\nThere is no per-user record anywhere. The attribution is lost.")
    app_conn.close()


if __name__ == "__main__":
    main()
