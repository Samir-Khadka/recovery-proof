"""End-to-end restore tests against real Docker databases (CI only).

Runs only when invoked with ``pytest -m docker``. GitHub-hosted runners
have Docker and the database clients installed (see .github/workflows/ci.yml).
Skipped everywhere else — the sandbox has neither.
"""
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

ROOT = Path(__file__).parent.parent


def _run_checker(engine, backup, checks, results, label):
    cmd = [
        sys.executable, "-m", "recovery_proof", "check",
        "--engine", engine,
        "--backup-file", str(backup),
        "--checks", str(checks),
        "--results", str(results),
        "--label", label,
        "--no-telegram",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=ROOT)


def _assert_report(results, label):
    report = subprocess.run(
        [sys.executable, "-m", "recovery_proof", "report",
         "--system", label, "--results", str(results)],
        capture_output=True, text=True, timeout=60, cwd=ROOT,
    )
    assert report.returncode == 0
    assert "Measured recovery time (median)" in report.stdout
    assert "Runs:** 1 (1 passed" in report.stdout


def test_real_restore_of_demo_fixture(tmp_path):
    results = tmp_path / "results.jsonl"
    p = _run_checker("postgres", ROOT / "fixtures" / "demo.sql",
                     ROOT / "checks.example.yaml", results, "ci-demo")
    assert p.returncode == 0, f"stdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    assert "PASS" in p.stdout or "PASS" in p.stderr
    assert results.is_file()
    _assert_report(results, "ci-demo")


def test_real_mysql_restore_of_demo_fixture(tmp_path):
    results = tmp_path / "results-mysql.jsonl"
    p = _run_checker("mysql", ROOT / "fixtures" / "demo-mysql.sql",
                     ROOT / "checks.mysql.example.yaml", results, "ci-demo-mysql")
    assert p.returncode == 0, f"stdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    assert "PASS" in p.stdout or "PASS" in p.stderr
    assert results.is_file()
    _assert_report(results, "ci-demo-mysql")
