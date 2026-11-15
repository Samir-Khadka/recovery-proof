"""Tests for the timeline event payload and the Telegram summary."""
import json
import urllib.request

import pytest

from recovery_proof.events import (
    build_event_payload,
    post_event,
    send_telegram,
    telegram_summary,
)


def _result(passed=True, reason=None):
    return {
        "label": "nightly", "passed": passed, "duration_s": 42.0,
        "failed_reason": reason,
        "backup": {"size_bytes": 12_000_000, "age_s": 3600},
        "checks": [
            {"name": "a", "passed": True, "skipped": False},
            {"name": "b", "passed": True, "skipped": False},
            {"name": "c", "passed": True, "skipped": True},
        ],
    }


def test_event_payload_pass_counts_only_real_checks():
    result = _result()
    p = build_event_payload("nightly", result)
    assert p["source"] == "restore" and p["type"] == "restore_check"
    assert "PASS (2/2 checks, 42.0s)" in p["title"]
    assert p["payload"] is result
    assert p["occurred_at"]


def test_event_payload_fail_names_reason():
    p = build_event_payload("nightly", _result(passed=False, reason="2/3 checks failed: a, b"))
    assert "FAIL — 2/3 checks failed: a, b" in p["title"]


def test_event_payload_fail_default_reason():
    p = build_event_payload("nightly", _result(passed=False))
    assert "FAIL — checks failed" in p["title"]


def test_telegram_summary_pass():
    text = telegram_summary("nightly", _result())
    assert text.startswith("✅ Restore check (nightly): PASS — 2/2 checks (1 skipped) in 42.0s")
    assert "Backup 12 MB, 1.0h old." in text


def test_telegram_summary_fail():
    text = telegram_summary("nightly", _result(passed=False, reason="restore failed"))
    assert text.startswith("❌ Restore check (nightly): FAIL — restore failed.")
    assert "Backup 12 MB" in text


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_post_event_no_url_is_skipped():
    assert post_event(None, {"a": 1}) == "skipped"
    assert post_event("", {"a": 1}) == "skipped"


def test_post_event_success(monkeypatch):
    seen = {}
    def fake_urlopen(req, timeout=15):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data)
        return FakeResponse(201)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert post_event("http://localhost:8000/", {"source": "restore"}) == "sent"
    assert seen["url"] == "http://localhost:8000/api/events"
    assert seen["body"]["source"] == "restore"


def test_post_event_failure_returns_failed(monkeypatch):
    def boom(req, timeout=15):
        raise ConnectionError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert post_event("http://localhost:8000", {"a": 1}) == "failed"


def test_send_telegram_success(monkeypatch):
    seen = {}
    def fake_urlopen(req, timeout=15):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data)
        return FakeResponse(200)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert send_telegram("TOKEN", "123", "hello") is True
    assert seen["url"] == "https://api.telegram.org/botTOKEN/sendMessage"
    assert seen["body"] == {"chat_id": "123", "text": "hello"}


def test_send_telegram_failure_is_false(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=15: (_ for _ in ()).throw(RuntimeError("no net")))
    assert send_telegram("TOKEN", "123", "hello") is False
