"""Tests for the append-only results history and its summary."""
from recovery_proof.history import append_result, load_history, summarize


def _result(label="nightly", passed=True, duration=42.0):
    return {"label": label, "passed": passed, "duration_s": duration, "checks": []}


def test_append_and_load_roundtrip(tmp_path):
    p = tmp_path / "results.jsonl"
    assert append_result(p, _result()) is True
    assert append_result(p, _result(passed=False, duration=55.5)) is True
    rows = load_history(p)
    assert len(rows) == 2
    assert rows[0]["passed"] is True
    assert rows[1]["duration_s"] == 55.5
    assert rows[0]["recorded_at"]  # timestamp added on append


def test_load_history_missing_file(tmp_path):
    assert load_history(tmp_path / "nope.jsonl") == []


def test_load_history_skips_malformed_lines(tmp_path):
    p = tmp_path / "results.jsonl"
    p.write_text('{"label": "a", "passed": true, "duration_s": 10}\nnot json\n{"label": "b", "passed": false, "duration_s": 20}\n')
    rows = load_history(p)
    assert [r["label"] for r in rows] == ["a", "b"]


def test_append_creates_parent_dirs(tmp_path):
    p = tmp_path / "deep" / "nested" / "results.jsonl"
    assert append_result(p, _result()) is True
    assert p.is_file()


def test_append_failure_returns_false_not_raise(tmp_path):
    # A directory where a file is expected: open() fails.
    p = tmp_path / "results.jsonl"
    p.mkdir()
    assert append_result(p, _result()) is False


def test_summarize_empty_history():
    s = summarize([])
    assert s["runs"] == 0 and s["pass_rate"] == 0.0
    assert s["median_duration_s"] == 0.0 and s["p95_duration_s"] == 0.0
    assert s["last_run_at"] is None


def test_summarize_median_and_p95():
    rows = [_result(duration=float(d)) for d in (10, 20, 30, 40, 50)]
    s = summarize(rows)
    assert s["runs"] == 5 and s["passes"] == 5 and s["pass_rate"] == 1.0
    assert s["median_duration_s"] == 30.0
    assert s["p95_duration_s"] == 48.0
    assert s["last_duration_s"] == 50.0


def test_summarize_filters_by_system():
    rows = [_result(label="nightly", duration=10), _result(label="weekly", duration=99),
            _result(label="nightly", passed=False, duration=20)]
    s = summarize(rows, system="nightly")
    assert s["runs"] == 2 and s["passes"] == 1 and s["pass_rate"] == 0.5
    assert s["median_duration_s"] == 15.0
    assert s["last_passed"] is False


def test_summarize_unknown_system_is_empty():
    rows = [_result(label="nightly")]
    s = summarize(rows, system="other")
    assert s["runs"] == 0
