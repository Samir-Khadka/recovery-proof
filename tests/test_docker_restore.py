"""End-to-end restore test against a real Docker Postgres (CI only).

Runs only when invoked with ``pytest -m docker``. GitHub-hosted runners
have Docker and postgresql-client installed (see .github/workflows/ci.yml).
Skipped everywhere else — the sandbox has neither.
"""
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

ROOT = Path(__file__).parent.parent


def test_real_restore_of_demo_fixture(tmp_path):
    results = tmp_path / "results.jsonl"
    cmd = [
        sys.executable, "-m", "recovery_proof", "check",
        "--backup-file", str(ROOT / "fixtures" / "demo.sql"),
        "--checks", str(ROOT / "checks.example.yaml"),
        "--results", str(results),
        "--label", "ci-demo",
        "--no-telegram",
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=ROOT)
    assert p.returncode == 0, f"stdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    assert "PASS" in p.stdout or "PASS" in p.stderr
    assert results.is_file()

    # The measured RTO report reads the recorded run back.
    report = subprocess.run(
        [sys.executable, "-m", "recovery_proof", "report",
         "--system", "ci-demo", "--results", str(results)],
        capture_output=True, text=True, timeout=60, cwd=ROOT,
    )
    assert report.returncode == 0
    assert "Measured recovery time (median)" in report.stdout
    assert "Runs:** 1 (1 passed" in report.stdout
