"""Tests for Slack notifications (mocked HTTP — no real Slack)."""
import json
import urllib.request

import pytest

from recovery_proof.events import (
    maybe_notify_slack,
    send_slack,
    slack_summary,
)

RESULT_PASS = {"passed": True, "duration_s": 42, "checks": [
    {"name": "a", "passed": True, "skipped": False},
    {"name": "b", "passed": True, "skipped": False},
], "backup": {"size_bytes": 1_000_000, "age_s": 3600}}
RESULT_FAIL = {"passed": False, "duration_s": 10, "failed_reason": "1/2 checks failed: b",
               "checks": [
                   {"name": "a", "passed": True, "skipped": False},
                   {"name": "b", "passed": False, "skipped": False},
               ], "backup": {}}


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_slack_summary_pass_and_fail():
    assert "PASS" in slack_summary("nightly", RESULT_PASS)
    assert "2/2 checks" in slack_summary("nightly", RESULT_PASS)
    fail = slack_summary("nightly", RESULT_FAIL, kind="S3 protection audit")
    assert "FAIL" in fail and "S3 protection audit" in fail
    assert "1/2 checks failed: b" in fail


def test_slack_not_configured_is_skipped(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    assert maybe_notify_slack("nightly", RESULT_PASS) == "skipped"


def test_slack_send_posts_json_and_returns_sent(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=15):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode())
        seen["method"] = req.get_method()
        return FakeResponse(200)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    assert maybe_notify_slack("nightly", RESULT_PASS) == "sent"
    assert seen["method"] == "POST"
    assert "nightly" in seen["body"]["text"]
    assert "PASS" in seen["body"]["text"]


def test_slack_send_failure_is_failed_not_raised(monkeypatch):
    def boom(req, timeout=15):
        raise ConnectionError("no network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    assert maybe_notify_slack("nightly", RESULT_PASS) == "failed"
    assert send_slack("https://hooks.slack.com/services/T/B/X", "hi") is False
