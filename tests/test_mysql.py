"""Tests for the MySQL engine: URL parsing, checks, CHECK TABLE, and the
command lines it builds (password via env, never on the command line)."""
import subprocess

import pytest

from conftest import FakeConn, table_handler
from recovery_proof.check import InfraError
from recovery_proof.engines import get_engine
from recovery_proof.engines.base import Engine
from recovery_proof.engines.mysql import MySQLEngine, _parse_mysql_url

ENGINE = MySQLEngine()


def test_engine_registry():
    assert isinstance(get_engine("postgres"), Engine)
    assert isinstance(get_engine("mysql"), MySQLEngine)
    with pytest.raises(InfraError, match="unknown engine"):
        get_engine("oracle")


def test_mysql_detect_format_always_sql(tmp_path):
    p = tmp_path / "b.sql"
    p.write_bytes(b"CREATE TABLE t (id INT);\n")
    assert ENGINE.detect_format(p) == "sql"


def test_mysql_verify_dump_is_skipped():
    r = ENGINE.verify_dump("/backups/x.sql", "sql")
    assert r["skipped"] is True
    assert "no table-of-contents check" in r["detail"]


def test_parse_mysql_url_full():
    cfg = _parse_mysql_url("mysql://samir:s3cret@db.example.com:3307/app")
    assert cfg == {"user": "samir", "password": "s3cret",
                   "host": "db.example.com", "port": 3307, "database": "app"}


def test_parse_mysql_url_defaults():
    cfg = _parse_mysql_url("mysql://root@127.0.0.1/mydb")
    assert cfg["port"] == 3306 and cfg["password"] == "" and cfg["user"] == "root"


def test_parse_mysql_url_rejects_wrong_scheme():
    with pytest.raises(InfraError, match="must start with mysql://"):
        _parse_mysql_url("postgresql://u:p@h/db")


def test_parse_mysql_url_rejects_missing_database():
    with pytest.raises(InfraError, match="needs a host and a database"):
        _parse_mysql_url("mysql://root@127.0.0.1/")


def mysql_table_handler(counts, queries=None):
    """Like conftest.table_handler, but matching MySQL backtick quoting."""
    queries = queries or {}

    def handler(sql, params=None):
        if sql.startswith("SELECT COUNT(*)"):
            for key, val in counts.items():
                quoted = "`" + key.replace("`", "``") + "`"
                if quoted in sql:
                    if isinstance(val, Exception):
                        raise val
                    return ("one", val)
            return ("one", 0)
        for key, val in queries.items():
            if key in sql:
                if isinstance(val, Exception):
                    raise val
                return ("all", val)
        return ("all", [])

    return handler


def test_mysql_run_checks_backtick_quoting():
    conn = FakeConn(mysql_table_handler({"users": 4}))
    results = ENGINE.run_checks(conn, {"tables": {"users": 1}, "queries": []})
    assert results[0]["passed"] is True
    sql = conn.cursor_obj.executed[0][0]
    assert sql == "SELECT COUNT(*) FROM `users`"


def test_mysql_run_checks_weird_table_name():
    conn = FakeConn(mysql_table_handler({"we`ird": 2}))
    results = ENGINE.run_checks(conn, {"tables": {"we`ird": 1}, "queries": []})
    assert results[0]["passed"] is True
    assert "SELECT COUNT(*) FROM `we``ird`" in conn.cursor_obj.executed[0][0]


def test_mysql_run_checks_query_pass_and_fail():
    conn = FakeConn(table_handler({}, {"recent": [(1,)], "missing": []}))
    results = ENGINE.run_checks(conn, {"tables": {}, "queries": [
        {"name": "recent", "sql": "SELECT 1 -- recent"},
        {"name": "missing", "sql": "SELECT 1 -- missing"},
    ]})
    assert results[0]["passed"] is True
    assert results[1]["passed"] is False


def _check_table_handler(tables, bad=None):
    """tables: [name]; bad: {name: Msg_text} for tables that fail CHECK TABLE."""
    bad = bad or {}

    def handler(sql, params=None):
        if "FROM information_schema.TABLES" in sql:
            return ("all", [(t,) for t in tables])
        if sql.startswith("CHECK TABLE"):
            name = sql.split("`")[1]
            msg = bad.get(name, "OK")
            return ("all", [(name, "check", "status" if msg == "OK" else "error", msg)])
        return ("all", [])

    return handler


def test_mysql_check_table_all_ok():
    conn = FakeConn(_check_table_handler(["users", "orders"]))
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["passed"] is True and results[0]["skipped"] is False
    assert "2 tables verified" in results[0]["detail"]


def test_mysql_check_table_failure_names_table():
    conn = FakeConn(_check_table_handler(["users", "orders"], bad={"orders": "Corrupt"}))
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["passed"] is False
    assert "orders: Corrupt" in results[0]["detail"]
    assert "1/2 tables failed" in results[0]["detail"]


def test_mysql_check_table_no_tables_skipped():
    conn = FakeConn(_check_table_handler([]))
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert "no base tables" in results[0]["detail"]


def test_mysql_check_table_list_error_skipped():
    def handler(sql, params=None):
        raise RuntimeError("denied")
    conn = FakeConn(handler)
    results = ENGINE.run_integrity_checks(conn)
    assert results[0]["skipped"] is True
    assert "could not list tables" in results[0]["detail"]


class FakeCompleted:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_mysql_restore_uses_env_password_not_argv(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["env"] = kw.get("env", {})
        return FakeCompleted(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    backup = tmp_path / "b.sql"
    backup.write_bytes(b"SELECT 1;")
    ENGINE.restore_backup("sql", backup, "127.0.0.1", 33061, "pw123", "recovery_proof", 60)
    assert seen["cmd"][:2] == ["mysql", "--host"]
    assert "--database" in seen["cmd"] and "recovery_proof" in seen["cmd"]
    assert not any("pw123" in str(a) for a in seen["cmd"])
    assert seen["env"].get("MYSQL_PWD") == "pw123"


def test_mysql_restore_missing_client_is_infra(tmp_path, monkeypatch):
    def boom(cmd, **kw):
        raise FileNotFoundError("mysql")
    monkeypatch.setattr(subprocess, "run", boom)
    backup = tmp_path / "b.sql"
    backup.write_bytes(b"SELECT 1;")
    with pytest.raises(InfraError, match="mysql client not found"):
        ENGINE.restore_backup("sql", backup, "127.0.0.1", 33061, "pw", "db", 60)


def test_mysql_dump_source_builds_mysqldump_command(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        seen["env"] = kw.get("env", {})
        return FakeCompleted(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    dest = tmp_path / "out.sql"
    ENGINE.dump_source("mysql://samir:s3cret@db.example.com:3307/app", dest, 60)
    assert seen["cmd"][0] == "mysqldump"
    assert "--single-transaction" in seen["cmd"]
    assert "app" in seen["cmd"]
    assert not any("s3cret" in str(a) for a in seen["cmd"])
    assert seen["env"].get("MYSQL_PWD") == "s3cret"
    assert dest.exists()


def test_mysql_start_container_sets_database_env(monkeypatch):
    import recovery_proof.engines.mysql as m

    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "port"]:
            return FakeCompleted(0, stdout="127.0.0.1:33061\n")
        return FakeCompleted(0, stdout="")

    monkeypatch.setattr(m, "run", fake_run)
    host, port = ENGINE.start_container("mysql:8.0", "pw123", "c1", "mydb")
    assert (host, port) == ("127.0.0.1", 33061)
    run_cmd = calls[0]
    assert "MYSQL_ROOT_PASSWORD=pw123" in run_cmd
    assert "MYSQL_DATABASE=mydb" in run_cmd
    assert not any("pw123" in a and a.startswith("-p") for a in run_cmd)


def test_mysql_connect_without_driver_is_infra(monkeypatch):
    import recovery_proof.engines.mysql as m
    monkeypatch.setattr(m, "mysql", None)
    with pytest.raises(InfraError, match="mysql-connector-python is not installed"):
        ENGINE.connect("127.0.0.1", 3306, "pw", "db")
