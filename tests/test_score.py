"""Tests for the readiness score: the formula, the grades, and the CLI."""
import json
from datetime import datetime, timezone

import pytest

from recovery_proof.score import (
    compute_score,
    grade_for,
    load_systems_config,
    score_main,
    score_systems,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


def _run(passed=True, duration=42, at="2026-11-15T12:00:00+00:00"):
    return {"label": "nightly", "passed": passed, "duration_s": duration,
            "recorded_at": at, "checks": []}


def _audit(passed=6, total=6, bucket="b"):
    checks = [{"name": f"c{i}", "type": "audit", "passed": i < passed,
               "skipped": False, "detail": ""} for i in range(total)]
    return {"bucket": bucket, "system": "nightly", "passed": passed == total,
            "checks": checks}


def test_grade_bands():
    assert grade_for(100) == "A" and grade_for(90) == "A"
    assert grade_for(89) == "B" and grade_for(80) == "B"
    assert grade_for(79) == "C" and grade_for(70) == "C"
    assert grade_for(69) == "D" and grade_for(60) == "D"
    assert grade_for(59) == "F" and grade_for(0) == "F"


def test_score_perfect_is_100():
    runs = [_run() for _ in range(10)]
    s = compute_score("nightly", runs, _audit(), 60, now=NOW)
    assert s["score"] == 100 and s["grade"] == "A"
    assert all(c["earned"] == c["weight"] for c in s["components"])


def test_score_no_data_is_0_and_says_so():
    s = compute_score("nightly", [], None, None, now=NOW)
    assert s["score"] == 0 and s["grade"] == "F"
    assert all(c["status"] == "no data" for c in s["components"])
    assert all(c["earned"] == 0 for c in s["components"])


def test_score_pass_rate_only():
    runs = [_run(passed=(i < 8)) for i in range(10)]
    s = compute_score("nightly", runs, None, None, now=NOW)
    # 8/10 pass = 32; freshness: last success is today = 20; RTO + audit = 0.
    assert s["score"] == 52
    assert s["components"][0]["earned"] == 32.0


def test_score_freshness_decays():
    runs = [_run(at="2026-10-31T12:00:00+00:00")]  # exactly 15 days before NOW
    s = compute_score("nightly", runs, None, None, now=NOW)
    assert s["components"][1]["earned"] == 10.0  # 20 * (1 - 15/30)
    assert "15.0 days ago" in s["components"][1]["detail"]


def test_score_freshness_zero_after_30_days():
    runs = [_run(at="2026-10-01T04:00:00+00:00")]  # 45 days before NOW
    s = compute_score("nightly", runs, None, None, now=NOW)
    assert s["components"][1]["earned"] == 0.0


def test_score_rto_met_and_exceeded():
    runs = [_run(duration=42) for _ in range(5)]
    s = compute_score("nightly", runs, None, 60, now=NOW)
    assert s["components"][2]["earned"] == 20.0
    runs = [_run(duration=120) for _ in range(5)]
    s = compute_score("nightly", runs, None, 60, now=NOW)
    assert s["components"][2]["earned"] == 10.0  # 20 * 60/120


def test_score_audit_partial_credit():
    runs = [_run() for _ in range(5)]
    s = compute_score("nightly", runs, _audit(passed=3, total=6), None, now=NOW)
    assert s["components"][3]["earned"] == 10.0
    assert "3/6 checks passed" in s["components"][3]["detail"]


def test_score_audit_skipped_checks_do_not_count():
    audit = _audit(passed=2, total=3)
    audit["checks"][2]["skipped"] = True
    audit["checks"][2]["passed"] = False
    runs = [_run() for _ in range(5)]
    s = compute_score("nightly", runs, audit, None, now=NOW)
    assert s["components"][3]["earned"] == 20.0  # 2/2 scored checks passed


def test_score_systems_includes_config_only_systems():
    results = [_run()]
    audits = [_audit()]
    out = score_systems(results, audits, {"nightly": {"rto_seconds": 60},
                                           "ghost": {"rto_seconds": 30}}, None)
    assert sorted(s["system"] for s in out) == ["ghost", "nightly"]
    ghost = next(s for s in out if s["system"] == "ghost")
    assert ghost["score"] == 0


def test_load_systems_config_yaml_and_json(tmp_path):
    p = tmp_path / "systems.yaml"
    p.write_text("nightly:\n  rto_seconds: 900\nweekly:\n  rto_seconds: 3600\n")
    assert load_systems_config(p) == {"nightly": {"rto_seconds": 900.0},
                                      "weekly": {"rto_seconds": 3600.0}}
    p2 = tmp_path / "systems.json"
    p2.write_text(json.dumps({"nightly": {}}))
    assert load_systems_config(p2) == {"nightly": {"rto_seconds": None}}


def test_score_main_text_and_json(tmp_path, capsys):
    results = tmp_path / "results.jsonl"
    results.write_text("\n".join(json.dumps(_run()) for _ in range(3)) + "\n")
    audits = tmp_path / "audit.jsonl"
    audits.write_text(json.dumps(_audit()) + "\n")
    assert score_main(["--system", "nightly", "--results", str(results),
                       "--audit-results", str(audits), "--rto-seconds", "60"]) == 0
    out = capsys.readouterr().out
    assert "Readiness score — nightly" in out
    assert "Score: 100/100 (grade A)" in out

    assert score_main(["--system", "nightly", "--results", str(results),
                       "--audit-results", str(audits), "--rto-seconds", "60",
                       "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["score"] == 100 and data[0]["grade"] == "A"


def test_score_main_unknown_system_scores_zero(tmp_path, capsys):
    results = tmp_path / "results.jsonl"
    results.write_text("")
    assert score_main(["--system", "ghost", "--results", str(results)]) == 0
    assert "Score: 0/100 (grade F)" in capsys.readouterr().out
