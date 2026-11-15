"""Postgres restore checker (Recovery Proof v0.1).

Restores a backup into an ephemeral Postgres container, runs integrity and
sanity checks, records the measured restore time to an append-only history,
and optionally reports to the Incident Copilot timeline and Telegram.

Adapted from the Incident Copilot restore checker
(https://github.com/Samir-Khadka/incident-copilot, restore/check.py).
What is new here: the integrity checks (dump verification + amcheck), the
local results history with a measured RTO, and a standalone CLI — no Copilot
API required.

Usage:
    python -m recovery_proof check --backup-file /backups/latest.dump --checks checks.yaml
    python -m recovery_proof check --source-url postgresql://user:pw@host/db --checks checks.yaml
    python -m recovery_proof report --system nightly

Exit codes: 0 = all checks passed, 1 = restore or a check failed, 2 = infra/usage error.

Host prerequisites: docker, postgresql-client (pg_dump/pg_restore/psql),
python 3.11+ + requirements.txt. Never commit real credentials — pass them via
env vars (.env is gitignored).
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
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from .events import (
    build_event_payload,
    maybe_notify_telegram,
    post_event,
)
from .history import append_result, default_results_path
from .integrity import run_integrity_checks, verify_dump

log = logging.getLogger("recovery-proof")

POSTGRES_IMAGE = "postgres:16.4"
READY_TIMEOUT_S = 120
RESTORE_TIMEOUT_S = 900
DUMP_TIMEOUT_S = 900
STATEMENT_TIMEOUT_MS = 30_000

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2


class CheckError(Exception):
    """A restore/check failure (exit 1)."""


class InfraError(Exception):
    """Missing tooling or bad usage (exit 2)."""


# ---------------------------------------------------------------- helpers
def redact_url(url: str) -> str:
    """Hide the password in a Postgres URL for logs.

    A URL with no password is returned unchanged; only a present password
    is replaced with ``***``. Unparseable input returns a marker.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.scheme:
            return "<redacted-url>"
        if "@" not in parts.netloc:
            return url
        userinfo, _, host = parts.netloc.partition("@")
        if ":" not in userinfo:
            return url
        user, _, _ = userinfo.partition(":")
        netloc = f"{user}:***@{host}"
        return urllib.parse.urlunsplit(
            (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
        )
    except Exception:
        pass
    return "<redacted-url>"


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Run a command, capturing output. Never logs secrets (callers redact)."""
    log.debug("exec: %s", " ".join(cmd[:2]) + " ...")
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_available() -> bool:
    try:
        p = run(["docker", "info"], timeout=15)
        return p.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def detect_format(path: Path) -> str:
    """'custom' for pg_dump custom format (PGDMP magic), else 'plain' SQL."""
    with open(path, "rb") as f:
        magic = f.read(5)
    return "custom" if magic == b"PGDMP" else "plain"


# ---------------------------------------------------------------- container
def start_container(image: str, password: str, name: str) -> tuple[str, int]:
    """Start an ephemeral Postgres; return (host, port)."""
    p = run(
        [
            "docker", "run", "-d", "--rm",
            "--name", name,
            "-e", f"POSTGRES_PASSWORD={password}",
            "-p", "127.0.0.1::5432",
            image,
        ],
        timeout=180,
    )
    if p.returncode != 0:
        raise InfraError(f"docker run failed: {p.stderr.strip()[-500:]}")
    p = run(["docker", "port", name, "5432"], timeout=15)
    if p.returncode != 0:
        raise InfraError(f"docker port failed: {p.stderr.strip()[-200:]}")
    # e.g. "127.0.0.1:49153" (or "0.0.0.0:49153")
    mapping = p.stdout.strip().splitlines()[-1]
    host, _, port = mapping.rpartition(":")
    return host or "127.0.0.1", int(port)


def wait_ready(name: str, timeout_s: int = READY_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        p = run(["docker", "exec", name, "pg_isready", "-U", "postgres"], timeout=10)
        if p.returncode == 0:
            return
        time.sleep(2)
    raise InfraError(f"postgres container {name} not ready after {timeout_s}s")


def stop_container(name: str) -> None:
    """Best-effort removal. Never raises — called from finally blocks."""
    try:
        run(["docker", "rm", "-f", name], timeout=30)
    except Exception as e:  # noqa: BLE001 - cleanup must not mask the real error
        log.warning("container cleanup failed for %s: %s", name, e)


def restore_backup(
    fmt: str,
    path: Path,
    host: str,
    port: int,
    password: str,
    timeout_s: int = RESTORE_TIMEOUT_S,
) -> None:
    """Restore into the temp container. Raises CheckError on failure."""
    env = {**os.environ, "PGPASSWORD": password}
    base = ["--host", host, "--port", str(port), "--username", "postgres",
            "--dbname", "postgres"]
    if fmt == "custom":
        cmd = ["pg_restore", *base, "--no-owner", "--clean", "--if-exists", str(path)]
    else:
        cmd = ["psql", *base, "-v", "ON_ERROR_STOP=1", "-f", str(path)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout_s)
    except FileNotFoundError:
        tool = "pg_restore" if fmt == "custom" else "psql"
        raise InfraError(f"{tool} not found — install postgresql-client") from None
    except subprocess.TimeoutExpired:
        raise CheckError(f"restore timed out after {timeout_s}s") from None
    if p.returncode != 0:
        raise CheckError(f"restore failed (exit {p.returncode}): {p.stderr.strip()[-800:]}")


def dump_source(url: str, dest: Path, timeout_s: int = DUMP_TIMEOUT_S) -> None:
    """pg_dump a live source to a custom-format file. URL is never logged."""
    try:
        p = subprocess.run(
            ["pg_dump", "--format=custom", "--file", str(dest), url],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except FileNotFoundError:
        raise InfraError("pg_dump not found — install postgresql-client") from None
    except subprocess.TimeoutExpired:
        raise CheckError(f"pg_dump timed out after {timeout_s}s") from None
    if p.returncode != 0:
        raise CheckError(f"pg_dump failed (exit {p.returncode}): {p.stderr.strip()[-800:]}")


# ---------------------------------------------------------------- checks
def load_checks(path: Path) -> dict:
    """Load the checks file (YAML preferred, JSON accepted)."""
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


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def run_checks(conn, checks: dict) -> list[dict]:
    """Run sanity checks against an open DBAPI connection.

    Returns [{name, type, passed, skipped, detail}]. A check that raises is
    recorded as failed (with the error in detail) — it never aborts the
    remaining checks. Skipped checks (integrity) are excluded from failures.
    """
    results: list[dict] = []
    for table, minimum in (checks.get("tables") or {}).items():
        try:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {_quote_ident(table)}")
                count = cur.fetchone()[0]
            passed = count >= int(minimum)
            detail = f"{count} rows (minimum {minimum})"
        except Exception as e:  # noqa: BLE001 - recorded, not raised
            passed, detail = False, f"error: {e}"
        results.append({"name": f"table {table} rows", "type": "table_rows",
                        "passed": passed, "skipped": False, "detail": detail})
    for q in checks.get("queries") or []:
        name, sql = q.get("name", "query"), q.get("sql", "")
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                n = len(cur.fetchall())
            passed = n >= 1
            detail = f"{n} row(s) returned (need >= 1)"
        except Exception as e:  # noqa: BLE001 - recorded, not raised
            passed, detail = False, f"error: {e}"
        results.append({"name": name, "type": "query",
                        "passed": passed, "skipped": False, "detail": detail})
    return results


# ---------------------------------------------------------------- orchestration
def parse_check_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Recovery Proof Postgres restore checker")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--backup-file", type=Path, help="pg_dump backup file (.dump custom or .sql plain)")
    src.add_argument("--source-url", help="live Postgres URL to pg_dump first (password stays out of logs)")
    ap.add_argument("--checks", type=Path, default=Path(__file__).parent.parent / "checks.example.yaml",
                    help="checks file (YAML or JSON)")
    ap.add_argument("--api-url", default=os.environ.get("COPILOT_API_URL"),
                    help="optional Copilot API base URL for the timeline event (default: $COPILOT_API_URL; unset = skip)")
    ap.add_argument("--results", type=Path, default=default_results_path(),
                    help="append-only results history file (default: ~/.recovery-proof/results.jsonl)")
    ap.add_argument("--no-history", action="store_true", help="do not record the run in the results history")
    ap.add_argument("--label", default="nightly", help="run label used in titles and reports")
    ap.add_argument("--postgres-image", default=POSTGRES_IMAGE, help="pinned postgres image for the temp container")
    ap.add_argument("--ready-timeout", type=int, default=READY_TIMEOUT_S)
    ap.add_argument("--restore-timeout", type=int, default=RESTORE_TIMEOUT_S)
    ap.add_argument("--workdir", type=Path, help="working dir (default: fresh temp dir)")
    ap.add_argument("--keep-workdir", action="store_true", help="debug: don't delete the temp dir")
    ap.add_argument("--no-telegram", action="store_true", help="skip Telegram even if configured")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def run_check(args: argparse.Namespace) -> dict:
    """Execute one restore check. Always cleans up the container. Returns the result dict."""
    started = time.monotonic()
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="recovery-proof-restore-"))
    workdir.mkdir(parents=True, exist_ok=True)
    container: str | None = None
    result: dict = {
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
            dump_source(args.source_url, backup_path)
            result["backup"] = {
                "kind": "dump", "source": redact_url(args.source_url),
                "size_bytes": backup_path.stat().st_size, "age_s": 0,
            }
        result["backup"]["format"] = detect_format(backup_path)

        # --- verify the dump itself before restoring it
        result["checks"].append(verify_dump(str(backup_path), result["backup"]["format"]))
        dump_check = result["checks"][-1]
        if not dump_check["passed"] and not dump_check.get("skipped"):
            raise CheckError(f"backup file failed verification: {dump_check['detail']}")

        # --- temp postgres
        password = secrets.token_hex(16)
        cname = f"recovery-proof-restore-{secrets.token_hex(4)}"
        container = cname
        host, port = start_container(args.postgres_image, password, cname)
        log.info("temp postgres at %s:%d", host, port)
        wait_ready(cname, args.ready_timeout)

        # --- restore
        log.info("restoring (%s format) ...", result["backup"]["format"])
        restore_backup(result["backup"]["format"], backup_path, host, port,
                       password, args.restore_timeout)
        result["restore_ok"] = True

        # --- sanity + integrity checks
        checks = load_checks(args.checks)
        conn = psycopg.connect(host=host, port=port, user="postgres",
                               password=password, dbname="postgres",
                               connect_timeout=10,
                               options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}")
        try:
            result["checks"].extend(run_checks(conn, checks))
            if (checks.get("integrity") or {}).get("enabled"):
                result["checks"].extend(run_integrity_checks(conn))
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
        log.info("PASS: %d/%d checks in %ss (history: %s, event: %s, telegram: %s)",
                 passed_n, total_n, result["duration_s"],
                 result["history"], result["event"], result["telegram"])
        return EXIT_PASS
    for c in result["checks"]:
        if not c["passed"] and not c.get("skipped"):
            log.error("  failed check: %s — %s", c["name"], c.get("detail", ""))
    log.error("FAIL: %s (history: %s, event: %s, telegram: %s)",
              result["failed_reason"], result["history"],
              result["event"], result["telegram"])
    return EXIT_FAIL


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(check_main())
