#!/usr/bin/env python3
"""
End-to-end test suite for scalple-audit.

Verifies every security and correctness claim made in the README and code:
  1. PgBouncer hides individual identities (only app_user visible to PostgreSQL)
  2. Audit log captures the real user correctly
  3. Audit log captures the right PostgreSQL role (app_user)
  4. session_id is the app connection's PID, not audit_writer's PID
  5. audit_writer CANNOT DELETE audit rows
  6. audit_writer CANNOT UPDATE audit rows
  7. audit_writer CANNOT TRUNCATE the audit table
  8. audit_reader CANNOT INSERT audit rows
  9. app_user CANNOT access the scalple schema at all
 10. SET LOCAL identity resets after COMMIT (safe under transaction pooling)
 11. Missing user_id is recorded as UNATTRIBUTED, not silently dropped
 12. Scenario counts match (bob=12, alice=5, carol=3)
 13. Forensic query returns bob-002 as the top accessor of p-001
 14. without_scalple.py exits 0 and shows only app_user
 15. with_scalple.py exits 0 and shows per-user attribution

Each test prints PASS or FAIL with a reason.
Exit code is 0 only if all tests pass.
"""

import os
import subprocess
import sys

import psycopg2

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

APP_DB_URL    = os.environ.get("APP_DB_URL",    "postgresql://app_user:app_password@localhost:6432/hospital_demo")
AUDIT_DB_URL  = os.environ.get("AUDIT_DB_URL",  "postgresql://audit_writer:audit_password@localhost:5432/hospital_demo")
READER_URL    = os.environ.get("AUDIT_READER_URL", "postgresql://audit_reader:audit_password@localhost:5432/hospital_demo")
SUPER_URL     = os.environ.get("POSTGRES_DB_URL",  "postgresql://postgres:postgres@localhost:5432/hospital_demo")

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from scalple import ScalpleAuditor
from demo._common import connect, run_scenario

# ---------------------------------------------------------------------------
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = []
_total_checks = 0

def check(name, ok, detail=""):
    global _total_checks
    _total_checks += 1
    if ok:
        print(f"  {PASS}  {name}")
    else:
        print(f"  {FAIL}  {name}" + (f"\n         {detail}" if detail else ""))
        failures.append(name)

def expect_denied(conn, sql, params=None):
    """Run SQL and return True if PostgreSQL raises a permission error."""
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        conn.commit()
        return False   # executed — not denied
    except psycopg2.Error as e:
        conn.rollback()
        return "permission denied" in str(e).lower() or "must be" in str(e).lower()

# ---------------------------------------------------------------------------
print("\n━━━  scalple-audit end-to-end test  ━━━\n")

# ---- connections -----------------------------------------------------------
print("[setup] connecting …")
app    = connect(APP_DB_URL)
writer = connect(AUDIT_DB_URL)
reader = connect(READER_URL)
sup    = connect(SUPER_URL)

sup.autocommit = True
sup.cursor().execute("TRUNCATE scalple.audit_log")

# ---- run the scenario ------------------------------------------------------
print("[setup] running scenario …")
auditor = ScalpleAuditor(app, writer)
run_scenario(auditor, app)

# ---- 1. PgBouncer hides individual identities ------------------------------
print("\n[1] PgBouncer identity hiding")
cur = app.cursor()
cur.execute("SELECT current_user")
role = cur.fetchone()[0]
app.commit()
check("current_user through PgBouncer is app_user", role == "app_user",
      f"got {role!r}")

# ---- 2. Real user captured correctly ---------------------------------------
print("\n[2] Attribution correctness")
rc = reader.cursor()
rc.execute("SELECT real_user, count(*) FROM scalple.audit_log GROUP BY real_user ORDER BY real_user")
rows = {r[0]: r[1] for r in rc.fetchall()}
check("alice-001 has 5 rows",  rows.get("alice-001") == 5,  str(rows))
check("bob-002 has 12 rows",   rows.get("bob-002") == 12,   str(rows))
check("carol-003 has 3 rows",  rows.get("carol-003") == 3,  str(rows))
check("total 20 rows",         sum(rows.values()) == 20,    str(rows))

# ---- 3. db_role is app_user in every row -----------------------------------
print("\n[3] db_role column accuracy")
rc.execute("SELECT count(*) FROM scalple.audit_log WHERE db_role != 'app_user'")
bad = rc.fetchone()[0]
check("all rows have db_role = app_user", bad == 0, f"{bad} rows differ")

# ---- 4. session_id is app connection PID, not audit_writer PID ------------
print("\n[4] session_id is app connection PID")
# Get the audit_writer backend pid
wc = writer.cursor()
wc.execute("SELECT pg_backend_pid()")
writer_pid = str(wc.fetchone()[0])
# Every session_id in the audit log should NOT be the writer's PID
rc.execute("SELECT count(*) FROM scalple.audit_log WHERE session_id = %s", (writer_pid,))
wrong_pid_count = rc.fetchone()[0]
check("no audit row has audit_writer PID as session_id",
      wrong_pid_count == 0,
      f"{wrong_pid_count} rows used writer PID {writer_pid}")
# And session_ids should be non-null numeric strings
rc.execute("SELECT count(*) FROM scalple.audit_log WHERE session_id IS NULL OR session_id = ''")
null_pids = rc.fetchone()[0]
check("all session_id values are non-null", null_pids == 0, f"{null_pids} null")

# ---- 5. audit_writer cannot DELETE ----------------------------------------
print("\n[5–7] append-only enforcement")
check("audit_writer cannot DELETE",
      expect_denied(writer, "DELETE FROM scalple.audit_log WHERE real_user = 'bob-002'"))

# ---- 6. audit_writer cannot UPDATE ----------------------------------------
check("audit_writer cannot UPDATE",
      expect_denied(writer, "UPDATE scalple.audit_log SET real_user = 'nobody' WHERE real_user = 'bob-002'"))

# ---- 7. audit_writer cannot TRUNCATE --------------------------------------
check("audit_writer cannot TRUNCATE",
      expect_denied(writer, "TRUNCATE scalple.audit_log"))

# ---- 8. audit_reader cannot INSERT ----------------------------------------
print("\n[8] audit_reader is SELECT-only")
check("audit_reader cannot INSERT",
      expect_denied(reader,
          "INSERT INTO scalple.audit_log (real_user,db_role,action,query_hash,query_text,session_id) "
          "VALUES ('hacker','app_user','SELECT','aabbcc','fake','99')"))

# ---- 9. app_user cannot access scalple schema -----------------------------
print("\n[9] app_user isolated from scalple schema")
check("app_user cannot SELECT audit_log",
      expect_denied(app, "SELECT * FROM scalple.audit_log LIMIT 1"))
check("app_user cannot INSERT into audit_log",
      expect_denied(app,
          "INSERT INTO scalple.audit_log (real_user,db_role,action,query_hash,query_text,session_id) "
          "VALUES ('x','y','SELECT','aabb','q','1')"))

# ---- 10. SET LOCAL resets after COMMIT ------------------------------------
print("\n[10] SET LOCAL resets after COMMIT (transaction pooling safety)")
cur = app.cursor()
cur.execute("SELECT set_config('scalple.user_id', 'test-user', true)")
cur.execute("SELECT current_setting('scalple.user_id', true) AS uid")
in_txn = cur.fetchone()[0]
app.commit()
# Start a new transaction — value must be gone
cur.execute("SELECT current_setting('scalple.user_id', true) AS uid")
after_commit = cur.fetchone()[0]
app.commit()
check("scalple.user_id is set within transaction", in_txn == "test-user",
      f"got {in_txn!r}")
check("scalple.user_id resets to empty after COMMIT",
      after_commit in (None, ""),
      f"got {after_commit!r}")

# ---- 11. Missing user_id → UNATTRIBUTED, not silent ----------------------
print("\n[11] missing scalple.user_id → UNATTRIBUTED")
# Run a query without setting the user_id
cur = app.cursor()
# explicitly clear it (no SET LOCAL — value already gone after commit above)
auditor.execute("SELECT 1")
app.commit()
rc.execute("SELECT count(*) FROM scalple.audit_log WHERE real_user = 'UNATTRIBUTED'")
unattr = rc.fetchone()[0]
check("query without user_id recorded as UNATTRIBUTED", unattr >= 1,
      f"found {unattr} UNATTRIBUTED rows")

# ---- 12–13. Forensic query ------------------------------------------------
print("\n[12–13] Forensic query correctness")
rc.execute("""
    SELECT real_user, count(*) AS n
    FROM scalple.audit_log
    WHERE table_name = 'patients' AND query_text LIKE '%p-001%'
    GROUP BY real_user ORDER BY n DESC
""")
forensic = rc.fetchall()
check("forensic query returns results", len(forensic) > 0)
if forensic:
    top = forensic[0]
    check("top accessor of p-001 is bob-002", top[0] == "bob-002",
          f"got {top[0]!r}")
    check("bob-002 accessed p-001 exactly 12 times", top[1] == 12,
          f"got {top[1]}")

# ---- 14–15. Isolated demo scripts exit 0 ----------------------------------
print("\n[14–15] Isolated demo scripts")
# Commit reader before the subprocess so it releases its AccessShareLock.
# with_scalple.py truncates audit_log (via superuser) — that TRUNCATE blocks
# if any other connection holds an AccessShareLock in an open transaction.
reader.commit()

r1 = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "demo/without_scalple.py")],
                    capture_output=True, text=True, cwd=REPO_ROOT)
check("without_scalple.py exits 0", r1.returncode == 0, r1.stderr[:200])
check("without_scalple.py output mentions app_user",
      "app_user" in r1.stdout, r1.stdout[:200])
check("without_scalple.py output says attribution is lost",
      "attribution is lost" in r1.stdout, r1.stdout[:200])

r2 = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "demo/with_scalple.py")],
                    capture_output=True, text=True, cwd=REPO_ROOT)
check("with_scalple.py exits 0", r2.returncode == 0, r2.stderr[:200])
check("with_scalple.py output shows bob-002",
      "bob-002" in r2.stdout, r2.stdout[:200])
check("with_scalple.py output shows alice-001",
      "alice-001" in r2.stdout, r2.stdout[:200])

# ---- summary ---------------------------------------------------------------
print()
passed = _total_checks - len(failures)
print(f"━━━  {passed}/{_total_checks} checks passed  ━━━")
if failures:
    print("\nFailed:")
    for f in failures:
        print(f"  ✗ {f}")
    sys.exit(1)
else:
    print("\nAll checks passed. ✓")
    sys.exit(0)
