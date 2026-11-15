"""Recovery readiness score (Recovery Proof v0.4, Phase 3).

One number per system, 0–100, with a grade — the number an executive or an
auditor can read. The formula is documented here and in the README, and
**every input is a measured fact**: nothing is guessed, nothing is
self-reported, and a component with no data scores 0 and says so.

Formula (fixed weights, missing data = 0):

| Component | Weight | Earned when |
|---|---|---|
| Restore pass rate (last 10 runs) | 40 | 40 × (passes / runs). No runs yet: 0. |
| Freshness (last successful restore) | 20 | 20 × max(0, 1 − days_since_last_success / 30). A success today is 20; none in 30 days (or never) is 0. |
| Measured RTO vs declared RTO | 20 | 20 if the median restore duration ≤ the declared RTO; otherwise 20 × (declared / median), decaying as the measured time exceeds the declared one. No declared RTO: 0. |
| Protection audit (latest) | 20 | 20 × (passed checks / non-skipped checks) from the latest audit for the system. No audit recorded: 0. |

Grades (the same bands as Kavach, the sibling security scanner):
A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

The declared RTO comes from a systems config file (``systems.yaml``:
``{label: {rto_seconds: N}}``) or from ``--rto-seconds`` on the score
command. The audit for a system is the latest audit-history entry whose
``system`` matches the label (the audit config's ``system`` field, default
the bucket name).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("recovery-proof.score")

PASS_RATE_WEIGHT = 40
FRESHNESS_WEIGHT = 20
RTO_WEIGHT = 20
AUDIT_WEIGHT = 20
FRESHNESS_WINDOW_DAYS = 30
PASS_RATE_WINDOW = 10

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(dt: datetime | None, now: datetime) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400)


def compute_score(label: str, runs: list[dict], latest_audit: dict | None,
                  declared_rto_s: float | None,
                  now: datetime | None = None) -> dict:
    """Score one system from its measured history. ``runs`` is chronological
    (oldest first); ``latest_audit`` is the newest audit record for the
    system, or None."""
    now = now or datetime.now(timezone.utc)
    components: list[dict] = []

    # --- 1. Restore pass rate (last 10 runs)
    recent = runs[-PASS_RATE_WINDOW:]
    if not recent:
        components.append({"name": "Restore pass rate (last 10 runs)",
                           "weight": PASS_RATE_WEIGHT, "earned": 0.0,
                           "detail": "no restore runs recorded yet",
                           "status": "no data"})
    else:
        passes = sum(1 for r in recent if r.get("passed"))
        earned = PASS_RATE_WEIGHT * passes / len(recent)
        components.append({"name": "Restore pass rate (last 10 runs)",
                           "weight": PASS_RATE_WEIGHT, "earned": round(earned, 1),
                           "detail": f"{passes}/{len(recent)} recent runs passed",
                           "status": "measured"})

    # --- 2. Freshness (last successful restore)
    successes = [r for r in runs if r.get("passed")]
    last_success = _parse_time(successes[-1].get("recorded_at")) if successes else None
    days = _days_since(last_success, now)
    if days is None:
        components.append({"name": "Freshness (last successful restore)",
                           "weight": FRESHNESS_WEIGHT, "earned": 0.0,
                           "detail": "no successful restore recorded yet",
                           "status": "no data"})
    else:
        earned = FRESHNESS_WEIGHT * max(0.0, 1 - days / FRESHNESS_WINDOW_DAYS)
        components.append({"name": "Freshness (last successful restore)",
                           "weight": FRESHNESS_WEIGHT, "earned": round(earned, 1),
                           "detail": f"last successful restore {days:.1f} days ago",
                           "status": "measured"})

    # --- 3. Measured RTO vs declared RTO
    durations = sorted(float(r["duration_s"]) for r in runs
                       if isinstance(r.get("duration_s"), (int, float)))
    from .history import _percentile  # one median definition, shared with report
    median = _percentile(durations, 50) if durations else 0.0
    if declared_rto_s is None:
        components.append({"name": "Measured RTO vs declared RTO",
                           "weight": RTO_WEIGHT, "earned": 0.0,
                           "detail": "no declared RTO — set rto_seconds for this system",
                           "status": "no data"})
    elif not durations:
        components.append({"name": "Measured RTO vs declared RTO",
                           "weight": RTO_WEIGHT, "earned": 0.0,
                           "detail": "no restore runs recorded yet",
                           "status": "no data"})
    elif median <= declared_rto_s:
        components.append({"name": "Measured RTO vs declared RTO",
                           "weight": RTO_WEIGHT, "earned": float(RTO_WEIGHT),
                           "detail": f"median restore {median:.1f}s ≤ declared RTO "
                                     f"{declared_rto_s:.0f}s",
                           "status": "measured"})
    else:
        earned = RTO_WEIGHT * declared_rto_s / median
        components.append({"name": "Measured RTO vs declared RTO",
                           "weight": RTO_WEIGHT, "earned": round(earned, 1),
                           "detail": f"median restore {median:.1f}s exceeds declared RTO "
                                     f"{declared_rto_s:.0f}s",
                           "status": "measured"})

    # --- 4. Protection audit (latest)
    if latest_audit is None:
        components.append({"name": "Protection audit (latest)",
                           "weight": AUDIT_WEIGHT, "earned": 0.0,
                           "detail": "no protection audit recorded for this system",
                           "status": "no data"})
    else:
        checks = latest_audit.get("checks", [])
        scored = [c for c in checks if not c.get("skipped")]
        passed = sum(1 for c in scored if c.get("passed"))
        if not scored:
            components.append({"name": "Protection audit (latest)",
                               "weight": AUDIT_WEIGHT, "earned": 0.0,
                               "detail": "latest audit had no scored checks",
                               "status": "no data"})
        else:
            earned = AUDIT_WEIGHT * passed / len(scored)
            components.append({"name": "Protection audit (latest)",
                               "weight": AUDIT_WEIGHT, "earned": round(earned, 1),
                               "detail": f"latest audit: {passed}/{len(scored)} checks passed "
                                         f"(bucket {latest_audit.get('bucket', '?')})",
                               "status": "measured"})

    score = int(round(sum(c["earned"] for c in components)))
    return {
        "system": label,
        "score": score,
        "grade": grade_for(score),
        "components": components,
        "measured": {
            "runs": len(runs),
            "median_duration_s": round(median, 1),
            "declared_rto_s": declared_rto_s,
        },
    }


def load_systems_config(path: Path) -> dict:
    """Systems config: {label: {rto_seconds: N}} (YAML or JSON)."""
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"systems config {path} must be a mapping")
    out = {}
    for label, cfg in data.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"systems config {path}: {label!r} must be a mapping")
        rto = cfg.get("rto_seconds")
        out[label] = {"rto_seconds": float(rto) if rto is not None else None}
    return out


def score_systems(results: list[dict], audits: list[dict],
                  systems: dict, rto_seconds: float | None) -> list[dict]:
    """Score every system in the restore history (plus any in the systems
    config that have no runs yet — they score 0 and say so)."""
    labels = sorted({r.get("label") for r in results if r.get("label")})
    for label in systems:
        if label not in labels:
            labels.append(label)
    out = []
    for label in labels:
        runs = [r for r in results if r.get("label") == label]
        sys_audits = [a for a in audits if a.get("system") == label]
        latest_audit = sys_audits[-1] if sys_audits else None
        declared = systems.get(label, {}).get("rto_seconds")
        if declared is None:
            declared = rto_seconds
        out.append(compute_score(label, runs, latest_audit, declared))
    return out


# ---------------------------------------------------------------- CLI
def render_score_text(score: dict) -> str:
    lines = [f"Readiness score — {score['system']}",
             f"Score: {score['score']}/100 (grade {score['grade']})", ""]
    for c in score["components"]:
        mark = "—" if c["status"] == "no data" else f"{c['earned']:.0f}/{c['weight']}"
        lines.append(f"  {mark:>7}  {c['name']} — {c['detail']}")
    lines.append("")
    lines.append(f"Measured median restore: {score['measured']['median_duration_s']}s "
                 f"over {score['measured']['runs']} runs")
    return "\n".join(lines) + "\n"


def render_score_markdown(score: dict) -> str:
    lines = [f"# Readiness report — {score['system']}", "",
             f"**Score: {score['score']}/100 (grade {score['grade']})**", "",
             "| Component | Weight | Earned | Evidence |",
             "|---|---|---|---|"]
    for c in score["components"]:
        lines.append(f"| {c['name']} | {c['weight']} | {c['earned']:.1f} | {c['detail']} |")
    lines.append("")
    lines.append(f"Measured median restore: **{score['measured']['median_duration_s']}s** "
                 f"over {score['measured']['runs']} runs.")
    if score["measured"]["declared_rto_s"] is not None:
        lines.append(f"Declared RTO: **{score['measured']['declared_rto_s']:.0f}s**.")
    lines.append("")
    lines.append("Every input above is a measured fact from the restore history "
                 "and the latest protection audit. A component with no data "
                 "scores 0 and says so.")
    return "\n".join(lines) + "\n"


def parse_score_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Recovery readiness score")
    ap.add_argument("--system", help="system (label) to score (default: all)")
    ap.add_argument("--results", type=Path,
                    default=Path.home() / ".recovery-proof" / "results.jsonl")
    ap.add_argument("--audit-results", type=Path,
                    default=Path.home() / ".recovery-proof" / "audit.jsonl")
    ap.add_argument("--rto-seconds", type=float,
                    help="declared RTO in seconds (applies to the scored system(s))")
    ap.add_argument("--systems", type=Path,
                    help="systems config file: {label: {rto_seconds: N}} (YAML or JSON)")
    ap.add_argument("--format", choices=["text", "md", "json"], default="text")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def score_main(argv=None) -> int:
    args = parse_score_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    from .history import default_results_path, load_history
    systems = {}
    if args.systems:
        try:
            systems = load_systems_config(args.systems)
        except (ValueError, FileNotFoundError, KeyError) as e:
            log.error("systems config error: %s", e)
            return EXIT_INFRA
    results = load_history(args.results)
    audits = load_history(args.audit_results)
    if args.system:
        labels = [args.system]
    else:
        labels = None
    scored = score_systems(results, audits, systems, args.rto_seconds)
    if labels is not None:
        scored = [s for s in scored if s["system"] in labels]
        if not scored:
            # A system with no runs and no config still gets a score: 0, honest.
            scored = [compute_score(args.system, [], None, args.rto_seconds)]
    if args.format == "json":
        out = json.dumps(scored, indent=2) + "\n"
    elif args.format == "md":
        out = "\n".join(render_score_markdown(s) for s in scored)
    else:
        out = "\n".join(render_score_text(s) for s in scored)
    sys.stdout.write(out)
    return EXIT_PASS
