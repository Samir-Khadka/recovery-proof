"""Tests for the integrity checks (dump verification + amcheck)."""
import subprocess

import pytest

from conftest import FakeConn
from recovery_proof.integrity import run_integrity_checks, verify_dump


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_verify_dump_custom_ok(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted(
        0, stdout="1; 0 0 TABLE public users\n2; 0 0 TABLE public orders\n"))
    r = verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is True and r["skipped"] is False
    assert "2 entries" in r["detail"]


def test_verify_dump_custom_corrupt(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted(
        1, stderr="pg_restore: error: input file is not a valid archive"))
    r = verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is False and r["skipped"] is False
    assert "not a valid archive" in r["detail"]


def test_verify_dump_custom_pg_restore_missing(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("pg_restore")
    monkeypatch.setattr(subprocess, "run", boom)
    r = verify_dump("/backups/x.dump", "custom")
    assert r["passed"] is True and r["skipped"] is True
    assert "pg_restore not found" in r["detail"]


def test_verify_dump_plain_is_skipped_not_passed():
    r = verify_dump("/backups/x.sql", "plain")
    assert r["skipped"] is True
    assert "plain SQL" in r["detail"]


def _amcheck_handler(indexes, corrupt=None):
    corrupt = corrupt or set()

    def handler(sql):
        if "CREATE EXTENSION" in sql:
            return ("all", [])
        if "FROM pg_index" in sql:
            return ("all", [(name,) for name in indexes])
        if "bt_index_check" in sql:
            name = sql.split('"')[1]
            if name in corrupt:
                raise RuntimeError("heap tuple (0,1) from table points to missing index tuple")
            return ("all", [(None,)])
        return ("all", [])

    return handler


def test_amcheck_all_indexes_verified():
    conn = FakeConn(_amcheck_handler(["idx_users_email", "idx_orders_user"]))
    results = run_integrity_checks(conn)
    assert len(results) == 1
    assert results[0]["passed"] is True and results[0]["skipped"] is False
    assert "2 btree indexes verified" in results[0]["detail"]


def test_amcheck_corrupt_index_fails_and_names_it():
    conn = FakeConn(_amcheck_handler(["idx_ok", "idx_bad"], corrupt={"idx_bad"}))
    results = run_integrity_checks(conn)
    assert results[0]["passed"] is False
    assert "idx_bad" in results[0]["detail"]
    assert "1/2 indexes failed" in results[0]["detail"]


def test_amcheck_unavailable_is_skipped():
    def handler(sql):
        raise RuntimeError('extension "amcheck" is not available')
    conn = FakeConn(handler)
    results = run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert results[0]["passed"] is True  # skipped, not failed
    assert "amcheck unavailable" in results[0]["detail"]


def test_amcheck_no_indexes_is_skipped():
    conn = FakeConn(_amcheck_handler([]))
    results = run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert "no btree indexes" in results[0]["detail"]
