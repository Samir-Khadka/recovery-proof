"""Tests for the CLI routing and the full run_check orchestration (mocked)."""
import pytest

from conftest import FakeConn, table_handler
from recovery_proof import __main__ as cli
from recovery_proof.check import (
    EXIT_FAIL,
    EXIT_INFRA,
    EXIT_PASS,
    InfraError,
    check_main,
    run_check,
)


def test_cli_report_markdown(tmp_path, capsys):
    p = tmp_path / "results.jsonl"
    p.write_text('{"label": "nightly", "passed": true, "duration_s": 30, "checks": []}\n')
    assert cli.main(["report", "--results", str(p), "--system", "nightly"]) == 0
    out = capsys.readouterr().out
    assert "Recovery report — nightly" in out
    assert "Measured recovery time (median):** 30.0s" in out


def test_cli_report_bad_format(tmp_path):
    # argparse rejects the bad choice with SystemExit(2), the standard CLI contract.
    with pytest.raises(SystemExit) as exc:
        cli.main(["report", "--results", str(tmp_path / "x"), "--format", "pdf"])
    assert exc.value.code == 2


def test_cli_check_requires_exactly_one_source(tmp_path):
    # The checker's own parser enforces the mutually-exclusive required group.
    with pytest.raises(SystemExit) as exc:
        cli.main(["check"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--backup-file", "a", "--source-url", "postgresql://x"])
    assert exc.value.code == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "recovery-proof" in capsys.readouterr().out


def _make_args(tmp_path, monkeypatch, *, engine="postgres", checks_pass=True,
               integrity=True):
    """Build a namespace for run_check with the engine's container I/O mocked."""
    import recovery_proof.check as chk
    import recovery_proof.engines.postgres as pg

    backup = tmp_path / "backup.sql"
    backup.write_bytes(b"SELECT 1;\n")
    checks_file = tmp_path / "checks.yaml"
    checks_file.write_text(
        "tables:\n  users: 1\nqueries: []\nintegrity:\n  enabled: "
        + ("true" if integrity else "false") + "\n"
    )
    results = tmp_path / "results.jsonl"

    monkeypatch.setattr(chk, "docker_available", lambda: True)
    monkeypatch.setattr(chk, "stop_container", lambda *a, **k: None)
    monkeypatch.setattr(chk, "post_event", lambda *a, **k: "skipped")
    monkeypatch.setattr(chk, "maybe_notify_telegram", lambda *a, **k: "skipped")
    monkeypatch.setattr(pg.PostgresEngine, "start_container",
                        lambda self, *a, **k: ("127.0.0.1", 54321))
    monkeypatch.setattr(pg.PostgresEngine, "wait_ready", lambda self, *a, **k: None)
    monkeypatch.setattr(pg.PostgresEngine, "restore_backup", lambda self, *a, **k: None)

    counts = {"users": 5} if checks_pass else {"users": 0}
    monkeypatch.setattr(
        pg.PostgresEngine, "connect",
        lambda self, *a, **k: FakeConn(table_handler(counts)),
    )
    args = chk.parse_check_args([
        "--engine", engine,
        "--backup-file", str(backup),
        "--checks", str(checks_file),
        "--results", str(results),
        "--label", "nightly",
        "--no-telegram",
    ])
    return args, results


def test_run_check_full_pass_records_history(tmp_path, monkeypatch):
    args, results_path = _make_args(tmp_path, monkeypatch)
    result = run_check(args)
    assert result["passed"] is True
    assert result["engine"] == "postgres"
    assert result["restore_ok"] is True
    assert result["history"] == "recorded"
    assert result["duration_s"] >= 0
    # dump check (plain SQL -> skipped) + 1 table check; amcheck skipped
    # because the fake conn has no amcheck tables (CREATE EXTENSION returns
    # empty, index query returns no rows).
    assert any(c["type"] == "table_rows" and c["passed"] for c in result["checks"])
    assert results_path.is_file()


def test_run_check_failing_table_check(tmp_path, monkeypatch):
    args, _ = _make_args(tmp_path, monkeypatch, checks_pass=False)
    result = run_check(args)
    assert result["passed"] is False
    assert "checks failed" in result["failed_reason"]


def test_run_check_no_history_flag(tmp_path, monkeypatch):
    args, results_path = _make_args(tmp_path, monkeypatch)
    args.no_history = True
    result = run_check(args)
    assert result["history"] == "skipped"
    assert not results_path.exists()


def test_run_check_no_integrity_when_disabled(tmp_path, monkeypatch):
    args, _ = _make_args(tmp_path, monkeypatch, integrity=False)
    result = run_check(args)
    assert result["passed"] is True
    # No database integrity check ran — but the dump check (type "dump")
    # always runs, because it verifies the backup file itself.
    assert not any(c["type"] == "integrity" for c in result["checks"])
    assert any(c["type"] == "dump" for c in result["checks"])


def test_run_check_docker_missing_is_infra(tmp_path, monkeypatch):
    import recovery_proof.check as chk
    monkeypatch.setattr(chk, "docker_available", lambda: False)
    backup = tmp_path / "b.sql"
    backup.write_bytes(b"SELECT 1;")
    args = chk.parse_check_args([
        "--backup-file", str(backup), "--no-telegram",
        "--results", str(tmp_path / "r.jsonl"),
    ])
    with pytest.raises(InfraError, match="no Docker daemon"):
        run_check(args)


def test_run_check_unknown_engine_is_infra(tmp_path, monkeypatch):
    import recovery_proof.check as chk
    backup = tmp_path / "b.sql"
    backup.write_bytes(b"SELECT 1;")
    args = chk.parse_check_args([
        "--backup-file", str(backup), "--no-telegram",
        "--results", str(tmp_path / "r.jsonl"),
    ])
    args.engine = "oracle"
    with pytest.raises(InfraError, match="unknown engine"):
        run_check(args)


def test_check_main_exit_codes(tmp_path, monkeypatch):
    args_ok, _ = _make_args(tmp_path, monkeypatch)
    # check_main parses argv itself; _make_args already mocked the engine.
    argv = [
        "--backup-file", str(tmp_path / "backup.sql"),
        "--checks", str(tmp_path / "checks.yaml"),
        "--results", str(tmp_path / "r2.jsonl"),
        "--label", "nightly", "--no-telegram",
    ]
    assert check_main(argv) == EXIT_PASS

    # Now make the table check fail.
    import recovery_proof.engines.postgres as pg
    monkeypatch.setattr(
        pg.PostgresEngine, "connect",
        lambda self, *a, **k: FakeConn(table_handler({"users": 0})),
    )
    assert check_main(argv) == EXIT_FAIL


def test_check_main_missing_backup_file_is_infra(tmp_path, monkeypatch):
    import recovery_proof.check as chk
    monkeypatch.setattr(chk, "docker_available", lambda: True)
    argv = [
        "--backup-file", str(tmp_path / "does-not-exist.dump"),
        "--no-telegram", "--results", str(tmp_path / "r.jsonl"),
    ]
    assert check_main(argv) == EXIT_INFRA
