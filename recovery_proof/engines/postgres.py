"""Postgres engine — moved verbatim from the v0.1 checker, now behind the
Engine interface. The one behavioural change: ``run_checks`` records the
``skipped`` key on every check, matching the MySQL engine's shape.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import psycopg

from .base import CheckError, Engine, InfraError, run

POSTGRES_IMAGE = "postgres:16.4"
READY_TIMEOUT_S = 120
RESTORE_TIMEOUT_S = 900
DUMP_TIMEOUT_S = 900
STATEMENT_TIMEOUT_MS = 30_000


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class PostgresEngine(Engine):
    name = "postgres"
    default_image = POSTGRES_IMAGE
    default_database = "postgres"
    container_prefix = "recovery-proof-restore"
    container_port = 5432

    def detect_format(self, path: Path) -> str:
        """'custom' for pg_dump custom format (PGDMP magic), else 'plain' SQL."""
        with open(path, "rb") as f:
            magic = f.read(5)
        return "custom" if magic == b"PGDMP" else "plain"

    def verify_dump(self, path: str, fmt: str) -> dict:
        """pg_restore --list for custom format; plain SQL has no such check."""
        if fmt != "custom":
            return {
                "name": "backup file readable (pg_restore --list)",
                "type": "dump",
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
                "type": "dump",
                "passed": True,
                "skipped": True,
                "detail": "pg_restore not found — dump check skipped",
            }
        except subprocess.TimeoutExpired:
            return {
                "name": "backup file readable (pg_restore --list)",
                "type": "dump",
                "passed": False,
                "skipped": False,
                "detail": "pg_restore --list timed out after 120s",
            }
        if p.returncode != 0:
            return {
                "name": "backup file readable (pg_restore --list)",
                "type": "dump",
                "passed": False,
                "skipped": False,
                "detail": f"pg_restore --list failed (exit {p.returncode}): "
                          f"{p.stderr.strip()[-300:]}",
            }
        entries = len([l for l in p.stdout.splitlines() if l.strip()])
        return {
            "name": "backup file readable (pg_restore --list)",
            "type": "dump",
            "passed": True,
            "skipped": False,
            "detail": f"dump table of contents parses ({entries} entries)",
        }

    def start_container(self, image: str, password: str, name: str,
                        database: str) -> tuple[str, int]:
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
        mapping = p.stdout.strip().splitlines()[-1]
        host, _, port = mapping.rpartition(":")
        return host or "127.0.0.1", int(port)

    def wait_ready(self, name: str, password: str, timeout_s: int = READY_TIMEOUT_S) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            p = run(["docker", "exec", name, "pg_isready", "-U", "postgres"], timeout=10)
            if p.returncode == 0:
                return
            time.sleep(2)
        raise InfraError(f"postgres container {name} not ready after {timeout_s}s")

    def restore_backup(self, fmt: str, path: Path, host: str, port: int,
                       password: str, database: str,
                       timeout_s: int = RESTORE_TIMEOUT_S) -> None:
        env = {**os.environ, "PGPASSWORD": password}
        base = ["--host", host, "--port", str(port), "--username", "postgres",
                "--dbname", database]
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

    def dump_source(self, url: str, dest: Path, timeout_s: int = DUMP_TIMEOUT_S) -> None:
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

    def connect(self, host: str, port: int, password: str, database: str):
        return psycopg.connect(
            host=host, port=port, user="postgres",
            password=password, dbname=database,
            connect_timeout=10,
            options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
        )

    def run_checks(self, conn, checks: dict) -> list[dict]:
        """Per-table row counts + custom SQL. A raising check is recorded, not fatal."""
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

    def run_integrity_checks(self, conn) -> list[dict]:
        """amcheck btree verification. See recovery_proof/integrity.py in v0.1
        for the rationale; the index name travels as a bound regclass
        parameter, never as a quoted identifier in the SQL."""
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
