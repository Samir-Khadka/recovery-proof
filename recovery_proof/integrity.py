"""Postgres database integrity checks for a restored backup.

Two checks, both honest about their limits:

1. Dump verification (before the restore): for pg_dump custom-format files,
   ``pg_restore --list`` must exit 0 — the dump is at least readable and its
   table of contents parses. Plain SQL has no equivalent cheap check, so it is
   recorded as skipped, not passed.
2. amcheck index verification (after the restore): if the ``amcheck``
   extension is available in the restored database, every btree index is
   verified with ``bt_index_check``. If amcheck is unavailable (no
   superuser, extension missing), the check is recorded as skipped — never
   as a pass, never as a failure.

A skipped check is neither a pass nor a failure: it is excluded from the
failed list and from the pass count, and its detail says why it was skipped.
"""
from __future__ import annotations

import subprocess


def verify_dump(path: str, fmt: str) -> dict:
    """Check the backup file itself is readable before restoring it."""
    if fmt != "custom":
        return {
            "name": "backup file readable (pg_restore --list)",
            "type": "integrity",
            "passed": True,
            "skipped": True,
            "detail": "plain SQL — no table-of-contents check available",
        }
    try:
        p = subprocess.run(
            ["pg_restore", "--list", path],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return {
            "name": "backup file readable (pg_restore --list)",
            "type": "integrity",
            "passed": True,
            "skipped": True,
            "detail": "pg_restore not found — dump check skipped",
        }
    except subprocess.TimeoutExpired:
        return {
            "name": "backup file readable (pg_restore --list)",
            "type": "integrity",
            "passed": False,
            "skipped": False,
            "detail": "pg_restore --list timed out after 120s",
        }
    if p.returncode != 0:
        return {
            "name": "backup file readable (pg_restore --list)",
            "type": "integrity",
            "passed": False,
            "skipped": False,
            "detail": f"pg_restore --list failed (exit {p.returncode}): "
                      f"{p.stderr.strip()[-300:]}",
        }
    entries = len([l for l in p.stdout.splitlines() if l.strip()])
    return {
        "name": "backup file readable (pg_restore --list)",
        "type": "integrity",
        "passed": True,
        "skipped": False,
        "detail": f"dump table of contents parses ({entries} entries)",
    }


def run_integrity_checks(conn) -> list[dict]:
    """Run amcheck btree verification against an open DBAPI connection.

    Returns [{name, type, passed, skipped, detail}]. One aggregate check for
    all btree indexes: a single corrupt index fails the check and is named.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS amcheck")
            cur.execute(
                "SELECT n.nspname, c.relname FROM pg_index i "
                "JOIN pg_class c ON c.oid = i.indexrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_am a ON a.oid = c.relam "
                "WHERE a.amname = 'btree'"
            )
            indexes = [(row[0], row[1]) for row in cur.fetchall()]
    except Exception as e:  # noqa: BLE001 - amcheck unavailable, record and move on
        try:
            conn.rollback()
        except Exception:
            pass
        return [{
            "name": "amcheck btree index verification",
            "type": "integrity",
            "passed": True,
            "skipped": True,
            "detail": f"amcheck unavailable — skipped ({e})",
        }]
    if not indexes:
        return [{
            "name": "amcheck btree index verification",
            "type": "integrity",
            "passed": True,
            "skipped": True,
            "detail": "no btree indexes found — nothing to verify",
        }]
    failed: list[str] = []
    for schema, name in indexes:
        qualified = f"{schema}.{name}"
        try:
            with conn.cursor() as cur:
                # Parameterised: the name is a regclass value, not a column
                # reference. (Quoting it as an identifier — bt_index_check
                # ("users_pkey") — makes Postgres look for a column of that
                # name and fails on every index.)
                cur.execute("SELECT bt_index_check(%s)", (qualified,))
                cur.fetchall()
        except Exception as e:  # noqa: BLE001 - one bad index fails the check
            failed.append(f"{qualified}: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
    if failed:
        return [{
            "name": "amcheck btree index verification",
            "type": "integrity",
            "passed": False,
            "skipped": False,
            "detail": f"{len(failed)}/{len(indexes)} indexes failed: "
                      + "; ".join(failed[:3]),
        }]
    return [{
        "name": "amcheck btree index verification",
        "type": "integrity",
        "passed": True,
        "skipped": False,
        "detail": f"{len(indexes)} btree indexes verified",
    }]
