"""Engine registry: --engine postgres | mysql."""
from __future__ import annotations

from .base import CheckError, Engine, InfraError
from .mysql import MySQLEngine
from .postgres import PostgresEngine

ENGINES: dict[str, type[Engine]] = {
    PostgresEngine.name: PostgresEngine,
    MySQLEngine.name: MySQLEngine,
}


def get_engine(name: str) -> Engine:
    """Return an engine instance by CLI name. Raises InfraError on unknown names."""
    try:
        return ENGINES[name]()
    except KeyError:
        raise InfraError(
            f"unknown engine: {name!r} (want one of: {', '.join(sorted(ENGINES))})"
        ) from None


__all__ = ["CheckError", "Engine", "ENGINES", "InfraError", "MySQLEngine",
           "PostgresEngine", "get_engine"]
