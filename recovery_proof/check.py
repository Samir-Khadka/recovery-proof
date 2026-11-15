"""Restore checker (Recovery Proof v0.2) — engine-agnostic orchestrator.

The orchestrator acquires the backup, verifies the dump, starts an
ephemeral container, restores, runs the checks, and records the result.
Everything database-specific lives in an engine
(``recovery_proof.engines``): Postgres in v0.1, MySQL in v0.2.

Usage:
    python -m recovery_proof check --backup-file /backups/latest.dump --checks checks.yaml
    python -m recovery_proof check --engine mysql --backup-file /backups/latest.sql --checks checks.mysql.yaml
    python -m recovery_proof check --source-url postgresql://user:pw@host/db --checks checks.yaml
    python -m recovery_proof report --system nightly

Exit codes: 0 = all checks passed, 1 = restore or a check failed, 2 = infra/usage error.

Host prerequisites: docker, the engine's client tools (postgresql-client
for Postgres, mysql-client for MySQL), python 3.11+ + requirements.txt.
Never commit real credentials — pass them via env vars (.env is gitignored).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .engines import get_engine
from .engines.base import CheckError, InfraError, redact_url
from .events import (
    build_event_payload,
    maybe_notify_slack,
    maybe_notify_telegram,
    post_event,
)
from .history import append_result, default_results_path

log = logging.getLogger("recovery-proof")

READY_TIMEOUT_S = 120
RESTORE_TIMEOUT_S = 900
DUMP_TIMEOUT_S = 900

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2

__all__ = ["CheckError", "InfraError", "check_main", "load_checks",
           "parse_check_args", "redact_url", "run_check"]


def docker_available() -> bool:
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=15)
        return p.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ---------------------------------------------------------------- checks file
def load_checks(path: Path) -> dict:
    """Load the checks file (YAML preferred, JSON accepted). Same shape for
    every engine: tables, queries, integrity. The SQL inside is the engine's
    dialect — a Postgres checks file will not run against MySQL."""
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise InfraError(
                "checks file is YAML but pyyaml is not installed — "
                "pip install pyyaml or use a .json checks file"
            ) from None
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise InfraError(f"checks file {path} must be a mapping")
    tables = data.get("tables") or {}
    queries = data.get("queries") or []
    integrity = data.get("integrity") or {}
    if not isinstance(tables, dict) or not isinstance(queries, list):
        raise InfraError(f"checks file {path}: 'tables' must be a mapping, 'queries' a list")
    if not isinstance(integrity, dict):
        raise InfraError(f"checks file {path}: 'integrity' must be a mapping")
    return {"tables": tables, "queries": queries, "integrity": integrity}


# ---------------------------------------------------------------- orchestration
def parse_check_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Recovery Proof restore checker")
    ap.add_argument("--engine", choices=["postgres", "mysql"], default="postgres",
                    help="database engine (default: postgres)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--backup-file", type=Path, help="backup file (pg_dump .dump/.sql, or mysqldump .sql)")
    src.add_argument("--source-url", help="live database URL to dump first (password stays out of logs)")
    ap.add_argument("--checks", type=Path, default=Path(__file__).parent.parent / "checks.example.yaml",
                    help="checks file (YAML or JSON)")
    ap.add_argument("--api-url", default=os.environ.get("COPILOT_API_URL"),
                    help="optional Copilot API base URL for the timeline event (default: $COPILOT_API_URL; unset = skip)")
    ap.add_argument("--results", type=Path, default=default_results_path(),
                    help="append-only results history file (default: ~/.recovery-proof/results.jsonl)")
    ap.add_argument("--no-history", action="store_true", help="do not record the run in the results history")
    ap.add_argument("--label", default="nightly", help="run label used in titles and reports")
    ap.add_argument("--image", default=None,
                    help="container image for the temp database (default: the engine's pinned image)")
    ap.add_argument("--database", default=None,
                    help="database the checks connect to (default: the engine's default)")
    ap.add_argument("--ready-timeout", type=int, default=READY_TIMEOUT_S)
    ap.add_argument("--restore-timeout", type=int, default=RESTORE_TIMEOUT_S)
    ap.add_argument("--workdir", type=Path, help="working dir (default: fresh temp dir)")
    ap.add_argument("--keep-workdir", action="store_true", help="debug: don't delete the temp dir")
    ap.add_argument("--no-telegram", action="store_true", help="skip Telegram even if configured")
    ap.add_argument("--no-slack", action="store_true", help="skip Slack even if configured")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def stop_container(name: str) -> None:
    """Best-effort removal. Never raises — called from finally blocks."""
    try:
        subprocess.run(["docker", "rm", "-f", name],
                       capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa: BLE001 - cleanup must not mask the real error
        log.warning("container cleanup failed for %s: %s", name, e)


def run_check(args: argparse.Namespace) -> dict:
    """Execute one restore check. Always cleans up the container. Returns the result dict."""
    engine = get_engine(args.engine)
    image = args.image or engine.default_image
    database = args.database or engine.default_database
    started = time.monotonic()
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="recovery-proof-restore-"))
    workdir.mkdir(parents=True, exist_ok=True)
    container: str | None = None
    result: dict = {
        "engine": engine.name,
        "label": args.label,
        "passed": False,
        "duration_s": 0,
        "restore_ok": False,
        "restore_error": None,
        "failed_reason": None,
        "backup": {},
        "checks": [],
        "event": "skipped",
        "history": "skipped",
        "telegram": "skipped",
        "slack": "skipped",
    }
    try:
        if not docker_available():
            raise InfraError("no Docker daemon reachable (is dockerd running?)")

        # --- acquire backup
        if args.backup_file:
            bp = args.backup_file
            if not bp.is_file():
                raise InfraError(f"backup file not found: {bp}")
            st = bp.stat()
            result["backup"] = {
                "kind": "file", "path": str(bp),
                "size_bytes": st.st_size, "age_s": int(time.time() - st.st_mtime),
            }
            backup_path = bp
        else:
            backup_path = workdir / "source.dump"
            log.info("dumping live source %s ...", redact_url(args.source_url))
            engine.dump_source(args.source_url, backup_path, DUMP_TIMEOUT_S)
            result["backup"] = {
                "kind": "dump", "source": redact_url(args.source_url),
                "size_bytes": backup_path.stat().st_size, "age_s": 0,
            }
        result["backup"]["format"] = engine.detect_format(backup_path)

        # --- verify the dump itself before restoring it
        result["checks"].append(engine.verify_dump(str(backup_path), result["backup"]["format"]))
        dump_check = result["checks"][-1]
        if not dump_check["passed"] and not dump_check.get("skipped"):
            raise CheckError(f"backup file failed verification: {dump_check['detail']}")

        # --- temp database
        password = secrets.token_hex(16)
        cname = f"{engine.container_prefix}-{secrets.token_hex(4)}"
        container = cname
        host, port = engine.start_container(image, password, cname, database)
        log.info("temp %s at %s:%d", engine.name, host, port)
        engine.wait_ready(cname, password, args.ready_timeout)

        # --- restore
        log.info("restoring (%s format) ...", result["backup"]["format"])
        engine.restore_backup(result["backup"]["format"], backup_path, host, port,
                              password, database, args.restore_timeout)
        result["restore_ok"] = True

        # --- sanity + integrity checks
        checks = load_checks(args.checks)
        conn = engine.connect(host, port, password, database)
        try:
            result["checks"].extend(engine.run_checks(conn, checks))
            if (checks.get("integrity") or {}).get("enabled"):
                result["checks"].extend(engine.run_integrity_checks(conn))
        finally:
            conn.close()

        failed = [c for c in result["checks"] if not c["passed"] and not c.get("skipped")]
        if failed:
            result["failed_reason"] = f"{len(failed)}/{len(result['checks'])} checks failed: " + \
                ", ".join(c["name"] for c in failed[:3])
        else:
            result["passed"] = True
    except CheckError as e:
        result["failed_reason"] = str(e)
        log.error("check failed: %s", e)
    finally:
        result["duration_s"] = round(time.monotonic() - started, 1)
        if container:
            stop_container(container)
        if not args.keep_workdir and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    # --- record + report (never lets reporting break the result)
    if not args.no_history:
        ok = append_result(args.results, result)
        result["history"] = "recorded" if ok else "failed"
    result["event"] = post_event(args.api_url, build_event_payload(args.label, result))
    result["telegram"] = "skipped" if args.no_telegram else maybe_notify_telegram(args.label, result)
    result["slack"] = "skipped" if args.no_slack else maybe_notify_slack(args.label, result)
    return result


def check_main(argv=None) -> int:
    args = parse_check_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        result = run_check(args)
    except InfraError as e:
        log.error("infra error: %s", e)
        return EXIT_INFRA
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_INFRA
    passed_n = sum(1 for c in result["checks"] if c["passed"] and not c.get("skipped"))
    total_n = sum(1 for c in result["checks"] if not c.get("skipped"))
    if result["passed"]:
        log.info("PASS: %d/%d checks in %ss (history: %s, event: %s, telegram: %s, slack: %s)",
                 passed_n, total_n, result["duration_s"],
                 result["history"], result["event"], result["telegram"], result["slack"])
        return EXIT_PASS
    for c in result["checks"]:
        if not c["passed"] and not c.get("skipped"):
            log.error("  failed check: %s — %s", c["name"], c.get("detail", ""))
    log.error("FAIL: %s (history: %s, event: %s, telegram: %s, slack: %s)",
              result["failed_reason"], result["history"],
              result["event"], result["telegram"], result["slack"])
    return EXIT_FAIL


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(check_main())
