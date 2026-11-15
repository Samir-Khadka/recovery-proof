"""Tests for the static HTML dashboard."""
import json

from recovery_proof.dashboard import build_dashboard, dashboard_main
from test_score import _audit, _run


def test_dashboard_renders_systems_and_scores():
    results = [_run() for _ in range(5)]
    results[0]["label"] = "weekly"
    audits = [_audit()]
    page = build_dashboard(results, audits, {"nightly": {"rto_seconds": 60}}, None)
    assert "nightly" in page and "weekly" in page
    assert "100/100" in page  # nightly: 5 passing runs + audit + RTO met
    assert "grade A" not in page  # grades render as badges, not the words
    assert ">A<" in page or "A</span>" in page
    assert "Measured median restore" in page
    assert "no declared RTO" in page  # weekly has no RTO configured


def test_dashboard_escapes_labels():
    results = [_run()]
    results[0]["label"] = "<script>alert(1)</script>"
    page = build_dashboard(results, [], {}, None)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_dashboard_empty_history_message():
    page = build_dashboard([], [], {}, None)
    assert "No restore runs recorded yet" in page
    assert "recovery-proof check" in page


def test_dashboard_main_writes_file(tmp_path):
    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps(_run()) + "\n")
    out = tmp_path / "dashboard.html"
    assert dashboard_main(["--output", str(out), "--results", str(results),
                           "--audit-results", str(tmp_path / "nope.jsonl")]) == 0
    text = out.read_text()
    assert "nightly" in text and "dashboard" in text.lower()
