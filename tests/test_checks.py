"""Tests for checks-file loading and the row-count / SQL checks."""
import json

import pytest

from conftest import FakeConn, table_handler
from recovery_proof.check import InfraError, load_checks, run_checks


def test_load_checks_yaml(tmp_path):
    p = tmp_path / "checks.yaml"
    p.write_text("tables:\n  users: 5\nqueries:\n  - name: q\n    sql: SELECT 1\nintegrity:\n  enabled: true\n")
    data = load_checks(p)
    assert data["tables"] == {"users": 5}
    assert data["queries"][0]["name"] == "q"
    assert data["integrity"] == {"enabled": True}


def test_load_checks_json(tmp_path):
    p = tmp_path / "checks.json"
    p.write_text(json.dumps({"tables": {"orders": 2}, "queries": []}))
    data = load_checks(p)
    assert data["tables"] == {"orders": 2}
    assert data["integrity"] == {}


def test_load_checks_empty_file(tmp_path):
    p = tmp_path / "checks.yaml"
    p.write_text("")
    data = load_checks(p)
    assert data == {"tables": {}, "queries": [], "integrity": {}}


def test_load_checks_not_a_mapping(tmp_path):
    p = tmp_path / "checks.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(InfraError, match="must be a mapping"):
        load_checks(p)


def test_load_checks_tables_must_be_mapping(tmp_path):
    p = tmp_path / "checks.yaml"
    p.write_text("tables: [1]\nqueries: []\n")
    with pytest.raises(InfraError, match="'tables' must be a mapping"):
        load_checks(p)


def test_load_checks_integrity_must_be_mapping(tmp_path):
    p = tmp_path / "checks.yaml"
    p.write_text("tables: {}\nqueries: []\nintegrity: yes\n")
    with pytest.raises(InfraError, match="'integrity' must be a mapping"):
        load_checks(p)


def test_load_checks_example_file():
    from pathlib import Path
    data = load_checks(Path(__file__).parent.parent / "checks.example.yaml")
    assert data["tables"]["users"] == 1
    assert data["integrity"]["enabled"] is True


def test_run_checks_table_pass():
    conn = FakeConn(table_handler({"users": 10, "orders": 3}))
    results = run_checks(conn, {"tables": {"users": 1, "orders": 1}, "queries": []})
    assert all(r["passed"] for r in results)
    assert results[0]["detail"] == "10 rows (minimum 1)"
    assert conn.closed is False  # run_checks does not close the connection


def test_run_checks_table_fail_below_minimum():
    conn = FakeConn(table_handler({"users": 0}))
    results = run_checks(conn, {"tables": {"users": 1}, "queries": []})
    assert results[0]["passed"] is False
    assert "0 rows" in results[0]["detail"]


def test_run_checks_table_error_recorded_not_raised():
    conn = FakeConn(table_handler({"users": RuntimeError("relation does not exist")}))
    results = run_checks(conn, {"tables": {"users": 1}, "queries": []})
    assert results[0]["passed"] is False
    assert "relation does not exist" in results[0]["detail"]


def test_run_checks_query_pass_and_fail():
    conn = FakeConn(table_handler({}, {"recent": [(1,)], "missing": []}))
    results = run_checks(conn, {"tables": {}, "queries": [
        {"name": "recent", "sql": "SELECT 1 -- recent"},
        {"name": "missing", "sql": "SELECT 1 -- missing"},
    ]})
    assert results[0]["passed"] is True
    assert results[0]["detail"] == "1 row(s) returned (need >= 1)"
    assert results[1]["passed"] is False


def test_run_checks_query_error_recorded():
    conn = FakeConn(table_handler({}, {"boom": RuntimeError("syntax error")}))
    results = run_checks(conn, {"tables": {}, "queries": [
        {"name": "boom", "sql": "SELECT boom"},
    ]})
    assert results[0]["passed"] is False
    assert "syntax error" in results[0]["detail"]


def test_run_checks_quotes_weird_table_names():
    conn = FakeConn(table_handler({"we\"ird": 2}))
    results = run_checks(conn, {"tables": {'we"ird': 1}, "queries": []})
    assert results[0]["passed"] is True
    assert '"we""ird"' in conn.cursor_obj.executed[0]
