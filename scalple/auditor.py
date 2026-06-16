"""
scalple.auditor — per-user attribution middleware for PostgreSQL behind PgBouncer.

This is the whole idea, in one small class. It is NOT a proxy and NOT production
code: it is a proof that the attribution pattern works.

The pattern:
  1. The app sets a transaction-scoped variable before each query:
         SET LOCAL scalple.user_id = 'alice@hospital.nl';
     `SET LOCAL` is scoped to the transaction, so it is safe under PgBouncer
     transaction-mode pooling — it resets on COMMIT/ROLLBACK and never leaks
     between pooled sessions.
  2. This middleware reads that variable, figures out the action + table, and
     writes one row to the append-only `scalple.audit_log` BEFORE running the
     query — using a dedicated `audit_writer` connection that can only INSERT.

The result: PostgreSQL still only sees `app_user`, but the audit log knows the
human.
"""

import hashlib
import re

from psycopg2.extras import RealDictCursor

# Naive table extraction — regex is fine for a demo (see "what is NOT in scope").
_TABLE_RE = re.compile(
    r"\b(?:FROM|INTO|UPDATE)\s+([a-zA-Z_][\w\.]*)", re.IGNORECASE
)
_DML = ("SELECT", "INSERT", "UPDATE", "DELETE")


def _extract_table(query: str):
    m = _TABLE_RE.search(query)
    return m.group(1) if m else None


class ScalpleAuditor:
    """
    Wraps a psycopg2 connection. Call .execute() instead of cursor.execute().

    app_conn:   the connection the app uses (goes through PgBouncer, role = app_user)
    audit_conn: a dedicated connection to the audit schema (role = audit_writer)
    """

    def __init__(self, app_conn, audit_conn):
        self.app_conn = app_conn
        self.audit_conn = audit_conn

    def execute(self, query, params=None, logged_at=None):
        """
        Audit, then run the query. Returns the app cursor (already executed).

        `logged_at` is an escape hatch used ONLY by the demo to reconstruct a
        realistic forensic timeline on seed data. In real use you leave it None
        and the database stamps now().
        """
        cur = self.app_conn.cursor(cursor_factory=RealDictCursor)

        # Fetch all app-connection metadata in one round-trip.
        # pg_backend_pid() here returns the APP connection's PID — essential for
        # correlating audit rows with pg_stat_activity / server logs. If we called
        # pg_backend_pid() inside the audit_conn INSERT it would return the
        # audit_writer's PID, which is useless for forensic correlation.
        cur.execute(
            """
            SELECT current_setting('scalple.user_id', true) AS uid,
                   current_user                              AS role,
                   pg_backend_pid()                         AS pid
            """
        )
        meta = cur.fetchone()
        uid     = meta["uid"] or "UNATTRIBUTED"
        db_role = meta["role"]
        app_pid = str(meta["pid"])

        # Best-effort parse — good enough for the demo, not for production.
        first_word = query.strip().split()[0].upper() if query.strip() else ""
        action = first_word if first_word in _DML else "OTHER"
        table_name = _extract_table(query)
        query_hash = hashlib.sha256(query.encode()).hexdigest()

        # Write the audit row BEFORE executing the query, via audit_writer.
        audit_cur = self.audit_conn.cursor()
        if logged_at is None:
            audit_cur.execute(
                """
                INSERT INTO scalple.audit_log
                    (real_user, db_role, action, table_name, query_hash,
                     query_text, session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (uid, db_role, action, table_name, query_hash, query[:500],
                 app_pid),
            )
        else:
            audit_cur.execute(
                """
                INSERT INTO scalple.audit_log
                    (logged_at, real_user, db_role, action, table_name,
                     query_hash, query_text, session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (logged_at, uid, db_role, action, table_name, query_hash,
                 query[:500], app_pid),
            )
        self.audit_conn.commit()

        # Now run the real query.
        cur.execute(query, params)
        return cur
