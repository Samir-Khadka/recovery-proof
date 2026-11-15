"""Append-only results history — the measured recovery time, with a past.

Every restore check appends one JSON line to a results file (default
``~/.recovery-proof/results.jsonl``). The file is append-only: runs are never
edited or deleted by the tool, so the measured RTO is a history, not a
single number someone typed into a spreadsheet.

``summarize`` turns the history into the numbers a report needs: run count,
pass rate, median and p95 restore duration (the measured RTO), and the most
recent run. A system with no history summarises to zero runs, not to a
guess.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("recovery-proof.history")


def default_results_path() -> Path:
    return Path.home() / ".recovery-proof" / "results.jsonl"


def default_audit_results_path() -> Path:
    return Path.home() / ".recovery-proof" / "audit.jsonl"


def default_drills_path() -> Path:
    return Path.home() / ".recovery-proof" / "drills.jsonl"


def append_result(path: Path, result: dict) -> bool:
    """Append one result as a JSON line. Returns False (never raises)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"recorded_at": datetime.now(timezone.utc).isoformat(), **result}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return True
    except Exception as e:  # noqa: BLE001 - recording must not fail the check
        log.warning("could not append result to %s: %s", path, e)
        return False


def load_history(path: Path) -> list[dict]:
    """Load all results, skipping malformed lines. Empty list if no file."""
    if not path.is_file():
        return []
    results: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                results.append(rec)
    return results


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolation percentile (the median people expect)."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = pct / 100 * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def summarize(results: list[dict], system: str | None = None) -> dict:
    """Summarise the history for one system (label) or all systems."""
    runs = [r for r in results if system is None or r.get("label") == system]
    durations = sorted(
        float(r["duration_s"]) for r in runs
        if isinstance(r.get("duration_s"), (int, float))
    )
    passes = sum(1 for r in runs if r.get("passed"))
    last = runs[-1] if runs else None
    return {
        "system": system or "all",
        "runs": len(runs),
        "passes": passes,
        "pass_rate": round(passes / len(runs), 3) if runs else 0.0,
        "median_duration_s": round(_percentile(durations, 50), 1) if durations else 0.0,
        "p95_duration_s": round(_percentile(durations, 95), 1) if durations else 0.0,
        "last_run_at": (last or {}).get("recorded_at"),
        "last_passed": (last or {}).get("passed"),
        "last_duration_s": (last or {}).get("duration_s"),
    }
