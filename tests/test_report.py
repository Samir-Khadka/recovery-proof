"""Tests for the measured-RTO report."""
import json

import pytest

from recovery_proof.report import build_report, render_json, render_markdown


def _rows():
    return [
        {"label": "nightly", "passed": True, "duration_s": 40.0,
         "recorded_at": "2026-11-15T00:00:00+00:00",
         "checks": [{"passed": True, "skipped": False}, {"passed": True, "skipped": False}]},
        {"label": "nightly", "passed": False, "duration_s": 60.0,
         "recorded_at": "2026-11-15T01:00:00+00:00",
         "checks": [{"passed": False, "skipped": False}, {"passed": True, "skipped": True}]},
    ]


def test_render_markdown_has_measured_rto(tmp_path):
    from recovery_proof.history import summarize
    s = summarize(_rows(), "nightly")
    text = render_markdown(s, _rows())
    assert "Measured recovery time (median):** 50.0s" in text
    assert "Measured recovery time (p95):** 59.0s" in text
    assert "Runs:** 2 (1 passed, pass rate 50%)" in text
    assert "Last run:** 2026-11-15T01:00:00+00:00 — FAIL in 60.0s" in text
    assert "| 2026-11-15T00:00:00+00:00 | PASS | 40.0s | 2/2 |" in text
    assert "| 2026-11-15T01:00:00+00:00 | FAIL | 60.0s | 0/1 |" in text


def test_render_markdown_empty_history():
    from recovery_proof.history import summarize
    s = summarize([], "nightly")
    text = render_markdown(s, [])
    assert "no measured RTO yet" in text
    assert "Runs:** 0" in text


def test_render_json_roundtrips(tmp_path):
    from recovery_proof.history import summarize
    s = summarize(_rows(), "nightly")
    data = json.loads(render_json(s, _rows()))
    assert data["summary"]["runs"] == 2
    assert len(data["recent_runs"]) == 2


def test_build_report_md_from_file(tmp_path):
    p = tmp_path / "results.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _rows()))
    text = build_report(p, "nightly", 5, "md")
    assert "Recovery report — nightly" in text


def test_build_report_json_from_file(tmp_path):
    p = tmp_path / "results.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in _rows()))
    data = json.loads(build_report(p, None, 1, "json"))
    assert data["summary"]["system"] == "all"
    assert len(data["recent_runs"]) == 1


def test_build_report_missing_file_reports_zero_runs(tmp_path):
    text = build_report(tmp_path / "missing.jsonl", "nightly", 5, "md")
    assert "no measured RTO yet" in text


def test_build_report_bad_format(tmp_path):
    with pytest.raises(ValueError, match="unknown report format"):
        build_report(tmp_path / "x.jsonl", None, 5, "pdf")
