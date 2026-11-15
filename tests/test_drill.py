"""Tests for the drill/runbook runner (Phase 5)."""
import json
import time
from pathlib import Path

import pytest

from recovery_proof.drill import (
    DrillError,
    drill_main,
    load_playbook,
    render_markdown,
    render_text,
    run_drill,
)

FIX = Path(__file__).parent.parent / "fixtures" / "clean-point"
ROOT = Path(__file__).parent.parent


def _playbook(**overrides):
    pb = {
        "name": "test drill",
        "system": "nightly",
        "rto_seconds": 900,
        "steps": [
            {"name": "clean point", "type": "clean-point",
             "points": [str(FIX / "clean"), str(FIX / "clean2")],
             "canaries": str(FIX / "canaries.yaml")},
            {"name": "shell ok", "type": "shell", "command": "true"},
            {"name": "wait a beat", "type": "wait", "seconds": 0.1},
        ],
    }
    pb.update(overrides)
    return pb


def _write_playbook(tmp_path, playbook):
    p = tmp_path / "drill.yaml"
    import yaml
    p.write_text(yaml.safe_dump(playbook))
    return p


# ------------------------------------------------------------ validation
def test_load_playbook_valid(tmp_path):
    pb = load_playbook(_write_playbook(tmp_path, _playbook()))
    assert pb["name"] == "test drill"
    assert len(pb["steps"]) == 3


def test_load_playbook_rejects_bad_inputs(tmp_path):
    cases = [
        ({"steps": [{"name": "x", "type": "shell", "command": "true"}]},
         "needs a non-empty 'name'"),
        ({"name": "x", "steps": []}, "non-empty 'steps' list"),
        ({"name": "x", "rto_seconds": -5,
          "steps": [{"name": "s", "type": "wait", "seconds": 1}]},
         "'rto_seconds' must be a positive number"),
        ({"name": "x", "steps": [{"name": "s", "type": "teleport"}]},
         "unknown type"),
        ({"name": "x", "steps": [{"name": "s", "type": "restore", "checks": "c.yaml"}]},
         "needs 'dump' or 'source_url'"),
        ({"name": "x", "steps": [{"name": "s", "type": "restore", "dump": "d.sql"}]},
         "needs 'checks'"),
        ({"name": "x", "steps": [{"name": "s", "type": "audit"}]},
         "needs 'config'"),
        ({"name": "x", "steps": [{"name": "s", "type": "clean-point", "points": []}]},
         "needs a non-empty 'points' list"),
        ({"name": "x", "steps": [{"name": "s", "type": "score", "min_score": 101}]},
         "'min_score' must be 0–100"),
        ({"name": "x", "steps": [{"name": "s", "type": "wait", "seconds": 700}]},
         "exceeds 'timeout_seconds'"),
        ({"name": "x", "steps": [{"type": "shell", "command": "true"}]},
         "needs a non-empty 'name'"),
    ]
    for data, fragment in cases:
        with pytest.raises(DrillError, match=fragment):
            load_playbook(_write_playbook(tmp_path, data))


def test_load_playbook_missing_file(tmp_path):
    with pytest.raises(DrillError, match="playbook not found"):
        load_playbook(tmp_path / "nope.yaml")


# ------------------------------------------------------------ execution
def test_drill_passes_with_no_docker_steps():
    result = run_drill(_playbook())
    assert result["verdict"] == "PASS"
    assert result["measured_rto_s"] is None  # no restore step passed
    assert result["rto_met"] is None
    assert all(s["status"] == "pass" for s in result["steps"])


def test_drill_stops_at_first_failure_and_skips_the_rest():
    pb = _playbook()
    pb["steps"] = [
        {"name": "shell ok", "type": "shell", "command": "true"},
        {"name": "shell boom", "type": "shell", "command": "exit 3"},
        {"name": "never runs", "type": "shell", "command": "true"},
    ]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert [s["status"] for s in result["steps"]] == ["pass", "fail", "skipped"]
    assert "shell boom" in result["failed_reason"]
    assert "exit 3" in result["steps"][1]["detail"]


def test_continue_on_failure_keeps_going_but_verdict_stays_fail():
    pb = _playbook()
    pb["steps"] = [
        {"name": "shell boom", "type": "shell", "command": "exit 1",
         "continue_on_failure": True},
        {"name": "shell ok", "type": "shell", "command": "true"},
    ]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert [s["status"] for s in result["steps"]] == ["fail", "pass"]


def test_rto_miss_fails_the_drill_even_when_steps_pass(monkeypatch):
    def fake_run_check(args):
        time.sleep(0.2)
        return {"passed": True, "duration_s": 0.2, "failed_reason": None}
    monkeypatch.setattr("recovery_proof.check.run_check", fake_run_check)
    pb = _playbook(rto_seconds=0.1)
    pb["steps"] = [
        {"name": "restore", "type": "restore", "dump": "fixtures/demo.sql",
         "checks": "checks.example.yaml"},
    ]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert result["measured_rto_s"] is not None
    assert result["measured_rto_s"] >= 0.2
    assert result["rto_met"] is False
    assert "exceeded declared RTO" in result["failed_reason"]


def test_rto_met_passes(monkeypatch):
    def fake_run_check(args):
        return {"passed": True, "duration_s": 0.05, "failed_reason": None}
    monkeypatch.setattr("recovery_proof.check.run_check", fake_run_check)
    pb = _playbook(rto_seconds=900)
    pb["steps"] = [
        {"name": "restore", "type": "restore", "dump": "fixtures/demo.sql",
         "checks": "checks.example.yaml"},
    ]
    result = run_drill(pb)
    assert result["verdict"] == "PASS"
    assert result["rto_met"] is True


def test_score_step_with_seeded_history(tmp_path, monkeypatch):
    results = tmp_path / "results.jsonl"
    audits = tmp_path / "audit.jsonl"
    run = {"label": "nightly", "passed": True, "duration_s": 42,
           "recorded_at": "2026-11-15T05:00:00+00:00", "checks": []}
    results.write_text(json.dumps(run) + "\n")
    audit = {"system": "nightly", "passed": True,
             "checks": [{"name": "c1", "passed": True, "skipped": False}]}
    audits.write_text(json.dumps(audit) + "\n")
    monkeypatch.setattr("recovery_proof.history.default_results_path",
                        lambda: results)
    monkeypatch.setattr("recovery_proof.history.default_audit_results_path",
                        lambda: audits)
    pb = _playbook()
    pb["steps"] = [{"name": "score", "type": "score", "system": "nightly",
                    "min_score": 60, "rto_seconds": 900}]
    result = run_drill(pb)
    assert result["verdict"] == "PASS"
    assert "100/100" in result["steps"][0]["detail"]


def test_score_step_below_min_score_fails(tmp_path, monkeypatch):
    results = tmp_path / "results.jsonl"
    results.write_text("")  # no runs at all: score 0
    monkeypatch.setattr("recovery_proof.history.default_results_path",
                        lambda: results)
    monkeypatch.setattr("recovery_proof.history.default_audit_results_path",
                        lambda: tmp_path / "audit.jsonl")
    pb = _playbook()
    pb["steps"] = [{"name": "score", "type": "score", "system": "nightly",
                    "min_score": 60}]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert "0/100" in result["steps"][0]["detail"]


def test_clean_point_step_fails_when_no_clean_point():
    pb = _playbook()
    pb["steps"] = [{"name": "clean point", "type": "clean-point",
                    "points": [str(FIX / "infected")]}]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert "no clean point" in result["steps"][0]["detail"]


def test_k8s_step_passes_and_fails():
    k8s_fix = ROOT / "fixtures" / "k8s"
    pb = _playbook()
    pb["steps"] = [{"name": "k8s", "type": "k8s",
                    "manifests": str(k8s_fix / "manifests"),
                    "velero": str(k8s_fix / "velero-backup")}]
    result = run_drill(pb)
    assert result["verdict"] == "PASS"
    assert "can be recreated" in result["steps"][0]["detail"]

    pb["steps"] = [{"name": "k8s", "type": "k8s",
                    "manifests": str(k8s_fix / "manifests-broken")}]
    result = run_drill(pb)
    assert result["verdict"] == "FAIL"
    assert "shop-config-missing" in result["steps"][0]["detail"]


def test_k8s_step_validation(tmp_path):
    with pytest.raises(DrillError, match="needs 'manifests' or 'velero'"):
        load_playbook(_write_playbook(
            tmp_path, {"name": "x", "steps": [{"name": "k", "type": "k8s"}]}))


# ------------------------------------------------------------ CLI + reports
def test_drill_cli_exit_codes_and_history(tmp_path, monkeypatch, capsys):
    drills = tmp_path / "drills.jsonl"
    monkeypatch.setattr("recovery_proof.history.default_drills_path",
                        lambda: drills)
    good = _write_playbook(tmp_path, _playbook())
    assert drill_main(["--playbook", str(good), "--no-telegram", "--no-slack"]) == 0
    assert "Verdict: PASS" in capsys.readouterr().out
    assert drills.is_file()
    assert json.loads(drills.read_text().splitlines()[0])["verdict"] == "PASS"

    bad_steps = _playbook()
    bad_steps["steps"] = [{"name": "boom", "type": "shell", "command": "exit 1"}]
    bad = _write_playbook(tmp_path, bad_steps)
    assert drill_main(["--playbook", str(bad), "--no-telegram", "--no-slack",
                       "--format", "md"]) == 1
    assert "**Verdict: FAIL**" in capsys.readouterr().out

    assert drill_main(["--playbook", str(tmp_path / "missing.yaml")]) == 2


def test_dry_run_validates_without_executing(tmp_path, capsys):
    good = _write_playbook(tmp_path, _playbook())
    assert drill_main(["--playbook", str(good), "--dry-run"]) == 0
    assert "playbook valid: test drill (3 steps)" in capsys.readouterr().out


def test_render_text_and_markdown_name_measured_vs_declared_rto():
    result = {"playbook": "p", "system": "nightly", "verdict": "PASS",
              "failed_reason": None, "declared_rto_s": 900,
              "measured_rto_s": 38.5, "rto_met": True, "duration_s": 40.0,
              "steps": [{"name": "restore", "type": "restore", "status": "pass",
                         "duration_s": 38.5, "detail": "restore passed in 38s"}]}
    text = render_text(result)
    assert "Measured recovery time: 38.5s — within declared RTO 900s" in text
    md = render_markdown(result)
    assert "Measured recovery time: **38.5s** — within declared RTO **900s**" in md
