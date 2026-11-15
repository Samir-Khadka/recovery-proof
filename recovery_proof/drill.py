"""Recovery drills and runbooks (Recovery Proof v0.6, Phase 5).

A runbook is a YAML playbook: an ordered list of steps that exercise the
recovery this product already knows how to do — restore a backup, audit
the bucket, score the clean point, compute the readiness score — plus
shell commands and waits for the steps around them.

A drill is a runbook executed end to end, producing a pass/fail scorecard
that names the measured recovery time vs the declared RTO. The measured
recovery time is the time spent in *restore* steps (the actual recovery
work), not the whole drill: a drill that spends an hour waiting on a slow
bucket audit has not taken an hour to recover.

Verdict: PASS means every step passed AND the measured recovery time is
within the declared RTO (when one is declared). A failed step, or a
measured RTO above the declared one, fails the drill — the point of a
drill is to prove you can recover in time, not just that the steps run.

Scheduling is the user's cron, not a built-in daemon: the drill is a
command, and the schedule lives where schedules live. Example (weekly,
Sunday 02:00):
    0 2 * * 0 recovery-proof drill --playbook drill.yaml

Step types:
- restore: run the restore checker. Needs dump (or source_url) + checks;
  engine defaults to postgres. Passes when the restore check passes.
- audit: run the S3 protection audit from a config file. Passes when the
  audit passes. The audit result is recorded in the audit history so a
  later score step in the same drill can see it.
- clean-point: score restore points. Passes when a clean point exists.
- score: compute the readiness score for a system. Passes when the score
  is >= min_score (default 60).
- k8s: verify a K8s workload can be restored (manifests and/or a Velero
  backup). Passes when the verifier reports OK.
- shell: run a command; passes on exit code 0. Playbooks are trusted local
  files — the runner executes what you wrote, and never downloads or
  fetches a playbook.
- wait: sleep N seconds; always passes.

A step that fails stops the drill unless continue_on_failure is set. The
drill result is recorded to ~/.recovery-proof/drills.jsonl, and Telegram +
Slack are notified once at the end (best-effort, kind "Recovery drill").
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("recovery-proof.drill")

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2

STEP_TYPES = {"restore", "audit", "clean-point", "score", "k8s", "shell", "wait"}
DEFAULT_STEP_TIMEOUT_S = 600
DEFAULT_MIN_SCORE = 60


class DrillError(Exception):
    pass


def load_playbook(path: Path) -> dict:
    """Load and validate a runbook. Raises DrillError on any problem."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        raise DrillError(f"playbook not found: {path}") from None
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise DrillError("playbook is YAML but pyyaml is not installed") from None
        data = yaml.safe_load(text) or {}
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise DrillError(f"playbook is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise DrillError("playbook must be a mapping")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise DrillError("playbook needs a non-empty 'name'")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise DrillError("playbook needs a non-empty 'steps' list")
    rto = data.get("rto_seconds")
    if rto is not None and (not isinstance(rto, (int, float)) or rto <= 0):
        raise DrillError("'rto_seconds' must be a positive number")
    system = data.get("system")
    if system is not None and not isinstance(system, str):
        raise DrillError("'system' must be a string")
    for i, step in enumerate(steps):
        _validate_step(step, i)
    return {"name": name.strip(),
            "system": system or name.strip(),
            "rto_seconds": rto,
            "steps": steps}


def _validate_step(step: dict, index: int) -> None:
    where = f"step {index + 1}"
    if not isinstance(step, dict):
        raise DrillError(f"{where}: each step must be a mapping")
    if not isinstance(step.get("name"), str) or not step["name"].strip():
        raise DrillError(f"{where}: each step needs a non-empty 'name'")
    stype = step.get("type")
    if stype not in STEP_TYPES:
        raise DrillError(f"{where} ({step.get('name')}): unknown type {stype!r} "
                         f"(expected one of {sorted(STEP_TYPES)})")
    timeout = step.get("timeout_seconds", DEFAULT_STEP_TIMEOUT_S)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise DrillError(f"{where}: 'timeout_seconds' must be a positive number")
    if not isinstance(step.get("continue_on_failure", False), bool):
        raise DrillError(f"{where}: 'continue_on_failure' must be true/false")
    if stype == "restore":
        if not step.get("dump") and not step.get("source_url"):
            raise DrillError(f"{where}: a restore step needs 'dump' or 'source_url'")
        if not step.get("checks"):
            raise DrillError(f"{where}: a restore step needs 'checks'")
        if step.get("engine") not in (None, "postgres", "mysql"):
            raise DrillError(f"{where}: 'engine' must be postgres or mysql")
    elif stype == "audit":
        if not step.get("config"):
            raise DrillError(f"{where}: an audit step needs 'config'")
    elif stype == "clean-point":
        points = step.get("points")
        if not isinstance(points, list) or not points:
            raise DrillError(f"{where}: a clean-point step needs a non-empty 'points' list")
    elif stype == "score":
        min_score = step.get("min_score", DEFAULT_MIN_SCORE)
        if not isinstance(min_score, (int, float)) or not 0 <= min_score <= 100:
            raise DrillError(f"{where}: 'min_score' must be 0–100")
    elif stype == "k8s":
        if not step.get("manifests") and not step.get("velero"):
            raise DrillError(f"{where}: a k8s step needs 'manifests' or 'velero'")
    elif stype == "shell":
        if not isinstance(step.get("command"), str) or not step["command"].strip():
            raise DrillError(f"{where}: a shell step needs a non-empty 'command'")
    elif stype == "wait":
        seconds = step.get("seconds")
        if not isinstance(seconds, (int, float)) or seconds < 0:
            raise DrillError(f"{where}: a wait step needs 'seconds' >= 0")
        if seconds > timeout:
            raise DrillError(f"{where}: 'seconds' exceeds 'timeout_seconds'")


# ---------------------------------------------------------------- step runners
def _run_restore(step: dict, playbook: dict) -> tuple[bool, str]:
    from .check import parse_check_args, run_check
    argv = ["--engine", step.get("engine") or "postgres",
            "--checks", str(step["checks"]),
            "--label", step.get("system") or playbook["system"],
            "--no-telegram", "--no-slack"]
    if step.get("dump"):
        argv += ["--backup-file", str(step["dump"])]
    else:
        argv += ["--source-url", str(step["source_url"])]
    result = run_check(parse_check_args(argv))
    if result.get("passed"):
        return True, f"restore passed in {result.get('duration_s', 0)}s"
    return False, result.get("failed_reason") or "restore check failed"


def _run_audit(step: dict, playbook: dict) -> tuple[bool, str]:
    from .audit import AuditError, load_audit_config, run_audit
    from .history import append_result, default_audit_results_path
    try:
        cfg = load_audit_config(Path(step["config"]))
        result = run_audit(cfg)
    except (AuditError, FileNotFoundError, ValueError, KeyError) as e:
        return False, f"audit error: {e}"
    append_result(default_audit_results_path(), result)
    if result.get("passed"):
        passed_n = sum(1 for c in result["checks"] if c.get("passed"))
        return True, f"audit passed ({passed_n}/{len(result['checks'])} checks)"
    failed = [c["name"] for c in result["checks"] if not c.get("passed") and not c.get("skipped")]
    return False, "audit failed: " + (", ".join(failed) or "checks failed")


def _run_clean_point(step: dict, playbook: dict) -> tuple[bool, str]:
    from .cleanpoint import load_canaries, run_clean_point
    try:
        canaries = load_canaries(Path(step["canaries"])) if step.get("canaries") else []
        result = run_clean_point([Path(p) for p in step["points"]], canaries,
                                 step.get("threshold", 50))
    except (ValueError, FileNotFoundError, KeyError) as e:
        return False, f"clean-point error: {e}"
    rec = result["recommendation"]
    if rec["clean_point"]:
        return True, f"last clean point: {rec['clean_point']}"
    return False, "no clean point found in the range examined"


def _run_score(step: dict, playbook: dict) -> tuple[bool, str]:
    from .history import default_audit_results_path, default_results_path, load_history
    from .score import score_systems
    system = step.get("system") or playbook["system"]
    min_score = step.get("min_score", DEFAULT_MIN_SCORE)
    results = load_history(default_results_path())
    audits = load_history(default_audit_results_path())
    systems = {system: {"rto_seconds": step.get("rto_seconds")}}
    scores = score_systems(results, audits, systems, step.get("rto_seconds"))
    score = scores[0] if scores else None
    if score is None:
        return False, f"no score computed for {system}"
    detail = f"score {score['score']}/100 (grade {score['grade']})"
    return (score["score"] >= min_score, detail)


def _run_shell(step: dict, playbook: dict) -> tuple[bool, str]:
    timeout = step.get("timeout_seconds", DEFAULT_STEP_TIMEOUT_S)
    try:
        proc = subprocess.run(step["command"], shell=True, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"command timed out after {timeout}s"
    output = (proc.stdout or proc.stderr or "").strip().splitlines()
    tail = output[-1][:200] if output else ""
    if proc.returncode == 0:
        return True, tail or "exit 0"
    return False, f"exit {proc.returncode}: {tail}"


def _run_wait(step: dict, playbook: dict) -> tuple[bool, str]:
    time.sleep(step["seconds"])
    return True, f"waited {step['seconds']}s"


def _run_k8s(step: dict, playbook: dict) -> tuple[bool, str]:
    from .k8s import run_k8s
    try:
        result = run_k8s(
            Path(step["manifests"]) if step.get("manifests") else None,
            Path(step["velero"]) if step.get("velero") else None)
    except ValueError as e:
        return False, f"k8s error: {e}"
    if result["ok"]:
        return True, "K8s workload can be recreated from this backup"
    errors = []
    for part in ("manifests", "velero"):
        if result[part]:
            errors += [f["detail"] for f in result[part]["findings"]
                       if f["severity"] == "error"]
    errors += [f["detail"] for f in result["cross_check"]
               if f["severity"] == "error"]
    return False, "; ".join(errors[:3]) or "K8s verification failed"


_STEP_RUNNERS = {
    "restore": _run_restore,
    "audit": _run_audit,
    "clean-point": _run_clean_point,
    "score": _run_score,
    "k8s": _run_k8s,
    "shell": _run_shell,
    "wait": _run_wait,
}


def run_drill(playbook: dict) -> dict:
    """Execute a validated playbook. Returns the drill result dict."""
    started = time.monotonic()
    steps_out: list[dict] = []
    failed_reason: str | None = None
    for i, step in enumerate(playbook["steps"]):
        s_started = time.monotonic()
        try:
            passed, detail = _STEP_RUNNERS[step["type"]](step, playbook)
        except Exception as e:  # noqa: BLE001 - a step must not kill the drill
            passed, detail = False, f"step raised {type(e).__name__}: {e}"
        duration = round(time.monotonic() - s_started, 2)
        steps_out.append({"name": step["name"], "type": step["type"],
                          "status": "pass" if passed else "fail",
                          "duration_s": duration, "detail": detail})
        if not passed:
            failed_reason = f"step '{step['name']}' failed: {detail}"
            if not step.get("continue_on_failure", False):
                for remaining in playbook["steps"][i + 1:]:
                    steps_out.append({"name": remaining["name"],
                                      "type": remaining["type"],
                                      "status": "skipped", "duration_s": 0,
                                      "detail": "skipped — an earlier step failed"})
                break
    measured_rto = None
    restore_durations = [s["duration_s"] for s in steps_out
                         if s["type"] == "restore" and s["status"] == "pass"]
    if restore_durations:
        measured_rto = round(sum(restore_durations), 2)
    declared = playbook.get("rto_seconds")
    rto_met = None
    if declared is not None and measured_rto is not None:
        rto_met = measured_rto <= declared
    verdict = "PASS"
    if failed_reason:
        verdict = "FAIL"
    elif rto_met is False:
        verdict = "FAIL"
        failed_reason = (f"measured recovery time {measured_rto}s exceeded "
                         f"declared RTO {declared}s")
    return {
        "playbook": playbook["name"],
        "system": playbook["system"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "failed_reason": failed_reason,
        "declared_rto_s": declared,
        "measured_rto_s": measured_rto,
        "rto_met": rto_met,
        "duration_s": round(time.monotonic() - started, 2),
        "steps": steps_out,
    }


def drill_summary(result: dict) -> str:
    """One line for Telegram/Slack."""
    passed_n = sum(1 for s in result["steps"] if s["status"] == "pass")
    total_n = len(result["steps"])
    icon = "✅" if result["verdict"] == "PASS" else "❌"
    line = (f"{icon} Recovery drill ({result['system']}): {result['verdict']} — "
            f"{passed_n}/{total_n} steps in {result['duration_s']}s.")
    if result["measured_rto_s"] is not None and result["declared_rto_s"] is not None:
        line += (f" Measured recovery {result['measured_rto_s']}s vs declared RTO "
                 f"{result['declared_rto_s']}s.")
    if result["failed_reason"]:
        line += f" {result['failed_reason']}"
    return line


def render_text(result: dict) -> str:
    lines = [f"Recovery drill — {result['playbook']}",
             f"Verdict: {result['verdict']}", ""]
    for s in result["steps"]:
        mark = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP"}[s["status"]]
        lines.append(f"  [{mark}] {s['name']} ({s['type']}, {s['duration_s']}s)")
        lines.append(f"        {s['detail']}")
    lines.append("")
    if result["measured_rto_s"] is not None and result["declared_rto_s"] is not None:
        met = "within" if result["rto_met"] else "EXCEEDED"
        lines.append(f"Measured recovery time: {result['measured_rto_s']}s — "
                     f"{met} declared RTO {result['declared_rto_s']}s")
    elif result["measured_rto_s"] is not None:
        lines.append(f"Measured recovery time: {result['measured_rto_s']}s "
                     f"(no declared RTO to compare against)")
    else:
        lines.append("Measured recovery time: not measured (no restore step passed)")
    if result["failed_reason"]:
        lines.append(f"Failed: {result['failed_reason']}")
    lines.append(f"Total drill time: {result['duration_s']}s")
    return "\n".join(lines) + "\n"


def render_markdown(result: dict) -> str:
    lines = [f"# Recovery drill — {result['playbook']}", "",
             f"**Verdict: {result['verdict']}**", "",
             "| Step | Type | Status | Duration | Detail |",
             "|---|---|---|---|---|"]
    for s in result["steps"]:
        lines.append(f"| {s['name']} | {s['type']} | {s['status']} | "
                     f"{s['duration_s']}s | {s['detail']} |")
    lines.append("")
    if result["measured_rto_s"] is not None and result["declared_rto_s"] is not None:
        met = "within" if result["rto_met"] else "**exceeded**"
        lines.append(f"Measured recovery time: **{result['measured_rto_s']}s** — "
                     f"{met} declared RTO **{result['declared_rto_s']}s**.")
    elif result["measured_rto_s"] is not None:
        lines.append(f"Measured recovery time: **{result['measured_rto_s']}s** "
                     f"(no declared RTO to compare against).")
    else:
        lines.append("Measured recovery time: not measured (no restore step passed).")
    if result["failed_reason"]:
        lines.append(f"Failed: {result['failed_reason']}")
    lines.append(f"Total drill time: {result['duration_s']}s.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- CLI
def parse_drill_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run a recovery drill from a YAML runbook and produce a "
                    "pass/fail scorecard.")
    ap.add_argument("--playbook", type=Path, required=True,
                    help="runbook file (YAML or JSON)")
    ap.add_argument("--format", choices=["text", "md", "json"], default="text")
    ap.add_argument("--output", type=Path, help="write the report here as well as stdout")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the playbook without executing it")
    ap.add_argument("--no-history", action="store_true",
                    help="do not record the drill in ~/.recovery-proof/drills.jsonl")
    ap.add_argument("--no-telegram", action="store_true")
    ap.add_argument("--no-slack", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def drill_main(argv=None) -> int:
    args = parse_drill_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        playbook = load_playbook(args.playbook)
    except DrillError as e:
        log.error("playbook error: %s", e)
        return EXIT_INFRA
    if args.dry_run:
        print(f"playbook valid: {playbook['name']} "
              f"({len(playbook['steps'])} steps)")
        return EXIT_PASS
    result = run_drill(playbook)
    if args.format == "json":
        out = json.dumps(result, indent=2) + "\n"
    elif args.format == "md":
        out = render_markdown(result)
    else:
        out = render_text(result)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    if not args.no_history:
        from .history import append_result, default_drills_path
        append_result(default_drills_path(), result)
    if not args.no_telegram or not args.no_slack:
        from .events import send_slack, send_telegram
        text = drill_summary(result)
        if not args.no_telegram:
            token, chat_id = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
            if token and chat_id:
                send_telegram(token, chat_id, text)
        if not args.no_slack:
            webhook = os.environ.get("SLACK_WEBHOOK_URL")
            if webhook:
                send_slack(webhook, text)
    return EXIT_PASS if result["verdict"] == "PASS" else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(drill_main())
