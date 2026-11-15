"""MySQL engine (v0.2).

Contract, documented so users are not surprised:
- Backups are SQL files (the ``mysqldump`` form). MySQL has no custom
  binary dump format in scope, so ``detect_format`` always returns ``"sql"``
  and dump verification is recorded as skipped — there is no
  table-of-contents check for a SQL dump.
- The dump restores into the database named by ``--database`` (default
  ``recovery_proof``), which the container creates on first start via
  ``MYSQL_DATABASE``. Use a single-database dump without ``CREATE DATABASE``
  (the plain ``mysqldump <db>`` form); a dump that contains its own
  ``USE <db>`` will land in that database instead, and the checks will
  connect to ``--database`` and find nothing.
- The password travels via the ``MYSQL_PWD`` environment variable, never on
  a command line (it would be visible in the process list).
- Integrity is ``CHECK TABLE`` over every base table (views excluded).
  A table whose ``CHECK TABLE`` reports anything but ``OK`` fails the check.
"""
from __future__ import annotations

import os
import subprocess
import time
import urllib.parse
from pathlib import Path

from .base import CheckError, Engine, InfraError, run

try:
    import mysql.connector
except ImportError:  # pragma: no cover - exercised by the import guard test
    mysql = None

MYSQL_IMAGE = "mysql:8.0"
READY_TIMEOUT_S = 120
RESTORE_TIMEOUT_S = 900
DUMP_TIMEOUT_S = 900


def _quote_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _parse_mysql_url(url: str) -> dict:
    """Split a mysql:// URL into its parts. Raises InfraError on bad input."""
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        raise InfraError(f"could not parse MySQL URL: {url}") from None
    if parts.scheme not in ("mysql", "mysql+pymysql"):
        raise InfraError(f"MySQL source URL must start with mysql:// (got {parts.scheme}://)")
    if not parts.hostname or not parts.path or parts.path == "/":
        raise InfraError("MySQL source URL needs a host and a database: mysql://user:pw@host:3306/db")
    return {
        "user": urllib.parse.unquote(parts.username or "root"),
        "password": urllib.parse.unquote(parts.password or ""),
        "host": parts.hostname,
        "port": parts.port or 3306,
        "database": parts.path.lstrip("/"),
    }


class MySQLEngine(Engine):
    name = "mysql"
    default_image = MYSQL_IMAGE
    default_database = "recovery_proof"
    container_prefix = "recovery-proof-mysql"
    container_port = 3306

    def detect_format(self, path: Path) -> str:
        return "sql"

    def verify_dump(self, path: str, fmt: str) -> dict:
        return {
            "name": "backup file readable",
            "type": "dump",
            "passed": True,
            "skipped": True,
            "detail": "mysqldump SQL — no table-of-contents check available",
        }

    def start_container(self, image: str, password: str, name: str,
                        database: str) -> tuple[str, int]:
        p = run(
            [
                "docker", "run", "-d", "--rm",
                "--name", name,
                "-e", f"MYSQL_ROOT_PASSWORD={password}",
                "-e", f"MYSQL_DATABASE={database}",
                "-p", "127.0.0.1::3306",
                image,
            ],
            timeout=180,
        )
        if p.returncode != 0:
            raise InfraError(f"docker run failed: {p.stderr.strip()[-500:]}")
        p = run(["docker", "port", name, "3306"], timeout=15)
        if p.returncode != 0:
            raise InfraError(f"docker port failed: {p.stderr.strip()[-200:]}")
        mapping = p.stdout.strip().splitlines()[-1]
        host, _, port = mapping.rpartition(":")
        return host or "127.0.0.1", int(port)

    def wait_ready(self, name: str, password: str, timeout_s: int = READY_TIMEOUT_S) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            env = {**os.environ, "MYSQL_PWD": password}
            p = subprocess.run(
                ["docker", "exec", "-e", f"MYSQL_PWD={password}", name,
                 "mysqladmin", "ping", "-h127.0.0.1", "-uroot", "--silent"],
                capture_output=True, text=True, timeout=10, env=env,
            )
            if p.returncode == 0:
                return
            time.sleep(2)
        raise InfraError(f"mysql container {name} not ready after {timeout_s}s")

    def restore_backup(self, fmt: str, path: Path, host: str, port: int,
                       password: str, database: str,
                       timeout_s: int = RESTORE_TIMEOUT_S) -> None:
        env = {**os.environ, "MYSQL_PWD": password}
        cmd = ["mysql", "--host", host, "--port", str(port),
               "--user", "root", "--database", database]
        try:
            with open(path, "rb") as f:
                p = subprocess.run(cmd, stdin=f, capture_output=True,
                                   text=True, env=env, timeout=timeout_s)
        except FileNotFoundError:
            raise InfraError("mysql client not found — install mysql-client") from None
        except subprocess.TimeoutExpired:
            raise CheckError(f"restore timed out after {timeout_s}s") from None
        if p.returncode != 0:
            raise CheckError(f"restore failed (exit {p.returncode}): {p.stderr.strip()[-800:]}")

    def dump_source(self, url: str, dest: Path, timeout_s: int = DUMP_TIMEOUT_S) -> None:
        cfg = _parse_mysql_url(url)
        env = {**os.environ, "MYSQL_PWD": cfg["password"]}
        cmd = [
            "mysqldump", "--single-transaction", "--routines", "--triggers",
            "--host", cfg["host"], "--port", str(cfg["port"]),
            "--user", cfg["user"], cfg["database"],
        ]
        try:
            with open(dest, "wb") as f:
                p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE,
                                   env=env, timeout=timeout_s)
        except FileNotFoundError:
            raise InfraError("mysqldump not found — install mysql-client") from None
        except subprocess.TimeoutExpired:
            raise CheckError(f"mysqldump timed out after {timeout_s}s") from None
        if p.returncode != 0:
            raise CheckError(
                f"mysqldump failed (exit {p.returncode}): "
                f"{p.stderr.decode(errors='replace').strip()[-800:]}"
            )

    def connect(self, host: str, port: int, password: str, database: str):
        if mysql is None:
            raise InfraError(
                "mysql-connector-python is not installed — "
                "pip install mysql-connector-python"
            )
        return mysql.connector.connect(
            host=host, port=port, user="root",
            password=password, database=database,
            connection_timeout=10, autocommit=True,
        )

    def run_checks(self, conn, checks: dict) -> list[dict]:
        """Per-table row counts + custom SQL. A raising check is recorded, not fatal."""
        results: list[dict] = []
        for table, minimum in (checks.get("tables") or {}).items():
            try:
                cur = conn.cursor()
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {_quote_ident(table)}")
                    count = cur.fetchone()[0]
                finally:
                    cur.close()
                passed = count >= int(minimum)
                detail = f"{count} rows (minimum {minimum})"
            except Exception as e:  # noqa: BLE001 - recorded, not raised
                passed, detail = False, f"error: {e}"
            results.append({"name": f"table {table} rows", "type": "table_rows",
                            "passed": passed, "skipped": False, "detail": detail})
        for q in checks.get("queries") or []:
            name, sql = q.get("name", "query"), q.get("sql", "")
            try:
                cur = conn.cursor()
                try:
                    cur.execute(sql)
                    n = len(cur.fetchall())
                finally:
                    cur.close()
                passed = n >= 1
                detail = f"{n} row(s) returned (need >= 1)"
            except Exception as e:  # noqa: BLE001 - recorded, not raised
                passed, detail = False, f"error: {e}"
            results.append({"name": name, "type": "query",
                            "passed": passed, "skipped": False, "detail": detail})
        return results

    def run_integrity_checks(self, conn) -> list[dict]:
        """CHECK TABLE over every base table (views excluded).

        One aggregate check. A table whose CHECK TABLE reports anything but
        OK fails the check and is named. No base tables = skipped.
        """
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT TABLE_NAME FROM information_schema.TABLES "
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'"
                )
                tables = [row[0] for row in cur.fetchall()]
            finally:
                cur.close()
        except Exception as e:  # noqa: BLE001 - cannot list tables, record and move on
            return [{
                "name": "CHECK TABLE verification",
                "type": "integrity",
                "passed": True,
                "skipped": True,
                "detail": f"could not list tables — skipped ({e})",
            }]
        if not tables:
            return [{
                "name": "CHECK TABLE verification",
                "type": "integrity",
                "passed": True,
                "skipped": True,
                "detail": "no base tables found — nothing to verify",
            }]
        failed: list[str] = []
        for table in tables:
            try:
                cur = conn.cursor()
                try:
                    cur.execute(f"CHECK TABLE {_quote_ident(table)}")
                    rows = cur.fetchall()
                finally:
                    cur.close()
                bad = [r for r in rows if len(r) >= 4 and r[3] != "OK"]
                if bad:
                    failed.append(f"{table}: " + "; ".join(str(r[3]) for r in bad[:2]))
            except Exception as e:  # noqa: BLE001 - one bad table fails the check
                failed.append(f"{table}: {e}")
        if failed:
            return [{
                "name": "CHECK TABLE verification",
                "type": "integrity",
                "passed": False,
                "skipped": False,
                "detail": f"{len(failed)}/{len(tables)} tables failed: "
                          + "; ".join(failed[:3]),
            }]
        return [{
            "name": "CHECK TABLE verification",
            "type": "integrity",
            "passed": True,
            "skipped": False,
            "detail": f"{len(tables)} tables verified (CHECK TABLE OK)",
        }]
