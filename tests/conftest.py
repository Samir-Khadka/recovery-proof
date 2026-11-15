"""Shared fakes for Recovery Proof tests."""
from __future__ import annotations


class FakeCursor:
    """A DBAPI cursor driven by a handler: handler(sql, params) -> ("one", value) | ("all", rows)."""

    def __init__(self, handler):
        self.handler = handler
        self.executed: list[tuple[str, object]] = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        self._result = self.handler(sql, params)

    def close(self):
        self.closed = True

    def fetchone(self):
        kind, val = self._result
        if kind == "one":
            return (val,)
        return val[0] if val else None

    def fetchall(self):
        kind, val = self._result
        if kind == "one":
            return [(val,)]
        return val


class FakeConn:
    def __init__(self, handler):
        self.handler = handler
        self.cursor_obj = FakeCursor(handler)
        self.closed = False
        self.rolled_back = 0

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True

    def rollback(self):
        self.rolled_back += 1


def table_handler(counts: dict, queries=None):
    """Handler for run_checks tests.

    counts: {table: row count or Exception}. queries: {sql substring: rows or Exception}.
    """
    queries = queries or {}

    def handler(sql, params=None):
        if sql.startswith("SELECT COUNT(*)"):
            for key, val in counts.items():
                quoted = '"' + key.replace('"', '""') + '"'
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
