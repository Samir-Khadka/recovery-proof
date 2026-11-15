"""Engine interface: one database backend behind the restore checker.

An engine knows how to start an ephemeral container for its database, dump
a live source, restore a backup file into the container, connect to it, and
run the sanity + integrity checks. The orchestrator
(``recovery_proof.check``) is engine-agnostic: it acquires the backup,
verifies the dump, starts the container, restores, runs the checks, and
records the result. Adding a database means adding an engine, not touching
the orchestrator.
"""
from __future__ import annotations

import logging
import subprocess
import urllib.parse
from abc import ABC, abstractmethod
from pathlib import Path

log = logging.getLogger("recovery-proof.engine")


def redact_url(url: str) -> str:
    """Hide the password in a database URL for logs.

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


class CheckError(Exception):
    """A restore/check failure (exit 1)."""


class InfraError(Exception):
    """Missing tooling or bad usage (exit 2)."""


class Engine(ABC):
    """One database backend."""

    #: CLI name: --engine postgres | mysql
    name: str = ""
    #: Pinned container image for the ephemeral database.
    default_image: str = ""
    #: Database the checks connect to (and plain dumps restore into).
    default_database: str = ""
    #: Prefix for the ephemeral container name.
    container_prefix: str = ""
    #: TCP port inside the container.
    container_port: int = 0

    @abstractmethod
    def detect_format(self, path: Path) -> str:
        """'custom' or 'plain'/'sql' — what the backup file is."""

    @abstractmethod
    def verify_dump(self, path: str, fmt: str) -> dict:
        """Check the backup file itself before restoring it.

        Returns an integrity check dict {name, type, passed, skipped,
        detail}. A dump that cannot be verified is recorded as skipped,
        never as a pass.
        """

    @abstractmethod
    def start_container(self, image: str, password: str, name: str,
                        database: str) -> tuple[str, int]:
        """Start an ephemeral database; return (host, port)."""

    @abstractmethod
    def wait_ready(self, name: str, password: str, timeout_s: int) -> None:
        """Block until the container accepts connections (or raise InfraError)."""

    @abstractmethod
    def restore_backup(self, fmt: str, path: Path, host: str, port: int,
                       password: str, database: str, timeout_s: int) -> None:
        """Restore into the temp container. Raises CheckError on failure."""

    @abstractmethod
    def dump_source(self, url: str, dest: Path, timeout_s: int) -> None:
        """Dump a live source to a backup file. URL is never logged."""

    @abstractmethod
    def connect(self, host: str, port: int, password: str, database: str):
        """Open a DBAPI connection to the restored database."""

    @abstractmethod
    def run_checks(self, conn, checks: dict) -> list[dict]:
        """Run the sanity checks (tables + queries) from the checks file."""

    @abstractmethod
    def run_integrity_checks(self, conn) -> list[dict]:
        """Run the engine-native integrity checks on the restored database."""
