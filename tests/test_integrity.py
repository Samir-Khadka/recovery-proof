"""Tests for the Postgres engine's integrity checks (dump verification + amcheck)."""
import subprocess

import pytest

from conftest import FakeConn
from recovery_proof.engines.postgres import PostgresEngine

ENGINE = PostgresEngine()


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_verify_dump_custom_ok(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted(
        0, stdout="1; 0 0 TABLE public users\n2; 0 0 TABLE public orders\n"))
    r = ENGINE.verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is True and r["skipped"] is False
    assert "2 entries" in r["detail"]


def test_verify_dump_custom_corrupt(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted(
        1, stderr="pg_restore: error: input file is not a valid archive"))
    r = ENGINE.verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is False and r["skipped"] is False
    assert "not a valid archive" in r["detail"]


def test_verify_dump_custom_pg_restore_missing(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("pg_restore")
    monkeypatch.setattr(subprocess, "run", boom)
    r = ENGINE.verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is True and r["skipped"] is True
    assert "pg_restore not found" in r["detail"]


def test_verify_dump_plain_is_skipped_not_passed():
    r = ENGINE.verify_dump("/backups/x.sql", "plain")
    assert r["skipped"] is True
    assert "plain SQL" in r["detail"]


def _amcheck_handler(indexes, corrupt=None):
    """indexes: [(schema, name)]. corrupt: set of qualified 'schema.name'."""
    corrupt = corrupt or set()

    def handler(sql, params=None):
        if "CREATE EXTENSION" in sql:
            return ("all", [])
        if "FROM pg_index" in sql:
            return ("all", [(schema, name) for schema, name in indexes])
        if "bt_index_check" in sql:
            # Regression guard for the v0.1 CI failure: the index must arrive
            # as a bound parameter (a regclass value), never interpolated
            # into the SQL as a quoted identifier — that makes Postgres look
            # for a column of that name and fails on every index.
            assert "%s" in sql, "bt_index_check must be parameterised"
            assert params and len(params) == 1, "bt_index_check needs one parameter"
            qualified = params[0]
            assert "." in qualified, "index name must be schema-qualified"
            if qualified in corrupt:
                raise RuntimeError("heap tuple (0,1) from table points to missing index tuple")
            return ("all", [(None,)])
        return ("all", [])

    return handler


def test_amcheck_all_indexes_verified():
    conn = FakeConn(_amcheck_handler([("public", "idx_users_email"), ("public", "idx_orders_user")]))
    results = ENGINE.run_integrity_checks(conn)
    assert len(results) == 1
    assert results[0]["passed"] is True and results[0]["skipped"] is False
    assert "2 btree indexes verified" in results[0]["detail"]
    # The index names travelled as parameters, not as SQL text.
    calls = [e for e in conn.cursor_obj.executed if "bt_index_check" in e[0]]
    assert [c[1] for c in calls] == [("public.idx_users_email",), ("public.idx_orders_user",)]


def test_amcheck_corrupt_index_fails_and_names_it():
    conn = FakeConn(_amcheck_handler(
        [("public", "idx_ok"), ("public", "idx_bad")],
        corrupt={"public.idx_bad"},
    ))
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["passed"] is False
    assert "public.idx_bad" in results[0]["detail"]
    assert "1/2 indexes failed" in results[0]["detail"]


def test_amcheck_unavailable_is_skipped():
    def handler(sql, params=None):
        raise RuntimeError('extension "amcheck" is not available')
    conn = FakeConn(handler)
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert results[0]["passed"] is True  # skipped, not failed
    assert "amcheck unavailable" in results[0]["detail"]


def test_amcheck_no_indexes_is_skipped():
    conn = FakeConn(_amcheck_handler([]))
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert "no btree indexes" in results[0]["detail"]
