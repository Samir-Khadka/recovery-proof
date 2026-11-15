"""Row-level comparison of plain-SQL database dumps (pg_dump --format=plain).

A plain SQL dump carries its table data in ``COPY table (...) FROM stdin;``
blocks, one data line per row, terminated by ``\\.``. This module reads
only those blocks and hashes each row, giving a per-table multiset of row
hashes — enough to measure how much of the data changed between two dumps
without a database, a restore, or Docker.

Limits, stated plainly:
- Only ``COPY`` blocks are read. A mysqldump file (INSERT statements) has
  no COPY blocks, so its mass change is not measurable this way — the
  scorer says so instead of guessing.
- Row hashes are SHA-256 of the COPY data line as written, so a dump taken
  with different column order or formatting reads as changed. Compare dumps
  taken the same way.
- The hash sets live in memory (32 bytes per distinct row). Fine for the
  dumps this tool targets; not for multi-gigabyte dumps.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_COPY_RE = re.compile(r"^COPY\s+([^\s(]+)\s*\(")


def parse_sql_dump(path: Path) -> dict[str, dict[str, int]]:
    """{table: {row_sha256: count}} from the COPY blocks of a plain-SQL dump."""
    tables: dict[str, dict[str, int]] = {}
    current: str | None = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if current is None:
                m = _COPY_RE.match(line)
                if m:
                    raw = m.group(1)
                    current = raw.split(".")[-1].strip('"')
                    tables.setdefault(current, {})
                continue
            if line.rstrip("\n") == "\\.":
                current = None
                continue
            h = hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()
            bucket = tables[current]
            bucket[h] = bucket.get(h, 0) + 1
    return tables


def compare_dumps(current: dict[str, dict[str, int]],
                  previous: dict[str, dict[str, int]]) -> tuple[float, str]:
    """Fraction of rows that differ between two dumps, and the detail line.

    Changed rows per table = the larger row total minus the rows that match
    (sum over hashes of min(count_current, count_previous)). A row that was
    edited, added, or deleted counts once. The fraction divides by the
    larger row total, so added rows count as change.
    """
    changed = 0
    cur_total = 0
    prev_total = 0
    for table, rows in current.items():
        cur_total += sum(rows.values())
    for table, rows in previous.items():
        prev_total += sum(rows.values())
    for table in set(current) | set(previous):
        cur_rows = current.get(table, {})
        prev_rows = previous.get(table, {})
        matching = sum(min(cur_rows.get(h, 0), prev_rows.get(h, 0))
                       for h in set(cur_rows) | set(prev_rows))
        changed += max(sum(cur_rows.values()), sum(prev_rows.values())) - matching
    denom = max(cur_total, prev_total, 1)
    frac = changed / denom
    return frac, (f"{changed}/{denom} rows differ "
                  f"({frac * 100:.0f}%) across {len(set(current) | set(previous))} tables")


def db_mass_change(point: Path, previous: dict | None) -> tuple[float, str] | dict:
    """Convenience wrapper used by the clean-point scorer.

    With ``previous=None`` returns this dump's per-table row hashes (the
    state to carry to the next point). Otherwise returns (fraction, detail).
    """
    current = parse_sql_dump(point)
    if previous is None:
        return current
    return compare_dumps(current, previous)
