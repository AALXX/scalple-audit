"""Shared helpers for the demo scripts: connections, the query scenario, and
tiny table-printing utilities. Kept deliberately small."""

import os
import time
from datetime import datetime

import psycopg2

# Connection strings. Defaults target a `docker compose up -d` on the host
# (postgres on 5432, pgbouncer on 6432). The compose `demo` service overrides
# these with the internal hostnames.
APP_DB_URL = os.environ.get(
    "APP_DB_URL", "postgresql://app_user:app_password@localhost:6432/hospital_demo"
)
AUDIT_DB_URL = os.environ.get(
    "AUDIT_DB_URL",
    "postgresql://audit_writer:audit_password@localhost:5432/hospital_demo",
)
AUDIT_READER_URL = os.environ.get(
    "AUDIT_READER_URL",
    "postgresql://audit_reader:audit_password@localhost:5432/hospital_demo",
)
# Superuser — used ONLY to reset the audit log between demo runs (see note in
# run_demo.py). The append-only guarantee applies to the app's audit_writer
# role, not to a database superuser.
POSTGRES_DB_URL = os.environ.get(
    "POSTGRES_DB_URL",
    "postgresql://postgres:postgres@localhost:5432/hospital_demo",
)


def connect(url, retries=30, delay=1.0):
    """Connect with retries — the DB/pooler may still be starting up."""
    last = None
    for _ in range(retries):
        try:
            return psycopg2.connect(url)
        except psycopg2.OperationalError as e:
            last = e
            time.sleep(delay)
    raise last


# ---------------------------------------------------------------------------
# The scenario: 20 queries on June 15th, 2026.
#   alice-001 — 5 routine queries across different patients (one hits p-001)
#   bob-002   — 12 queries against p-001 over ~23 minutes  ← suspicious
#   carol-003 — 3 routine queries
# Timestamps are simulated so the forensic query tells a realistic story on
# seed data (see ScalpleAuditor.execute's `logged_at` argument).
# ---------------------------------------------------------------------------
def _ts(hh, mm, ss):
    return datetime(2026, 6, 15, hh, mm, ss)


def _q(pid):
    # Inline id (demo only) so query_text contains the patient id, which is
    # what a forensic LIKE '%p-001%' search keys off.
    return f"SELECT id, name, diagnosis, risk_level FROM patients WHERE id = '{pid}'"


def scenario():
    """Returns a list of (real_user, query, logged_at) in chronological order."""
    events = []

    # bob — 12 hits on p-001, 14:23:07 → 14:46:19
    bob_times = [
        (14, 23, 7), (14, 24, 51), (14, 26, 33), (14, 28, 12), (14, 31, 5),
        (14, 33, 40), (14, 36, 19), (14, 38, 2), (14, 40, 47), (14, 42, 30),
        (14, 44, 58), (14, 46, 19),
    ]
    for hh, mm, ss in bob_times:
        events.append(("bob-002", _q("p-001"), _ts(hh, mm, ss)))

    # alice — 5 routine queries; one touches p-001 at 14:31:52
    alice = [
        ("p-002", _ts(14, 10, 3)),
        ("p-014", _ts(14, 18, 22)),
        ("p-001", _ts(14, 31, 52)),
        ("p-027", _ts(14, 39, 11)),
        ("p-033", _ts(14, 51, 44)),
    ]
    for pid, ts in alice:
        events.append(("alice-001", _q(pid), ts))

    # carol — 3 routine queries
    carol = [
        ("p-005", _ts(14, 5, 30)),
        ("p-019", _ts(14, 27, 9)),
        ("p-040", _ts(14, 49, 2)),
    ]
    for pid, ts in carol:
        events.append(("carol-003", _q(pid), ts))

    events.sort(key=lambda e: e[2])
    return events


def run_scenario(auditor, app_conn):
    """Run every scenario query through the auditor, each in its own
    transaction so `SET LOCAL` resets — exactly as it would behind PgBouncer."""
    for real_user, query, ts in scenario():
        cur = app_conn.cursor()
        # The one extra line per transaction. set_config(..., true) is the
        # function form of `SET LOCAL scalple.user_id = ...`.
        cur.execute("SELECT set_config('scalple.user_id', %s, true)", (real_user,))
        auditor.execute(query, logged_at=ts)
        app_conn.commit()


# ---------------------------------------------------------------------------
# Tiny table printer.
# ---------------------------------------------------------------------------
def print_table(headers, rows):
    cols = [str(h) for h in headers]
    data = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [len(h) for h in cols]
    for r in data:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(cols))
    sep = "  " + "-+-".join("-" * widths[i] for i in range(len(cols)))
    print(line)
    print(sep)
    for r in data:
        print("  " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(r)))
