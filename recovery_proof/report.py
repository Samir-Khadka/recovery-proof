"""The measured-RTO report: turn the results history into proof.

``recovery-proof report`` reads the append-only history and prints, per
system, the measured recovery time (median and p95 restore duration), the
pass rate, and the recent runs. Markdown is the default (paste it into an
audit pack); JSON is for machines.

A system with no history reports zero runs — never a guessed RTO.
"""
from __future__ import annotations

import json
from pathlib import Path

from .history import load_history, summarize


def render_markdown(summary: dict, recent: list[dict]) -> str:
    lines = [
        f"# Recovery report — {summary['system']}",
        "",
        f"- **Runs:** {summary['runs']} ({summary['passes']} passed, "
        f"pass rate {summary['pass_rate'] * 100:.0f}%)",
        f"- **Measured recovery time (median):** {summary['median_duration_s']}s",
        f"- **Measured recovery time (p95):** {summary['p95_duration_s']}s",
    ]
    if summary["last_run_at"]:
        verdict = "PASS" if summary["last_passed"] else "FAIL"
        lines.append(
            f"- **Last run:** {summary['last_run_at']} — {verdict} "
            f"in {summary['last_duration_s']}s"
        )
    else:
        lines.append("- **Last run:** none recorded — no measured RTO yet")
    lines.append("")
    if recent:
        lines.append("## Recent runs")
        lines.append("")
        lines.append("| When | Result | Duration | Checks |")
        lines.append("|---|---|---|---|")
        for r in recent:
            checks = r.get("checks", [])
            passed_n = sum(1 for c in checks if c.get("passed") and not c.get("skipped"))
            total_n = sum(1 for c in checks if not c.get("skipped"))
            verdict = "PASS" if r.get("passed") else "FAIL"
            lines.append(
                f"| {r.get('recorded_at', '')} | {verdict} | "
                f"{r.get('duration_s', '')}s | {passed_n}/{total_n} |"
            )
    return "\n".join(lines) + "\n"


def render_json(summary: dict, recent: list[dict]) -> str:
    return json.dumps({"summary": summary, "recent_runs": recent}, indent=2) + "\n"


def build_report(results_path: Path, system: str | None, last_n: int,
                 fmt: str) -> str:
    """Load history and render the report. Raises ValueError on bad format."""
    if fmt not in ("md", "json"):
        raise ValueError(f"unknown report format: {fmt!r} (want md or json)")
    results = load_history(results_path)
    summary = summarize(results, system)
    runs = [r for r in results if system is None or r.get("label") == system]
    recent = runs[-last_n:] if last_n > 0 else []
    if fmt == "json":
        return render_json(summary, recent)
    return render_markdown(summary, recent)
