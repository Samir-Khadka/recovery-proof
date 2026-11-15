"""Reporting: the Copilot timeline event and the Telegram summary.

Both are best-effort — a reporting failure never fails the check. The API
post is optional in Recovery Proof (unlike Incident Copilot, where the API
is the point): with no --api-url and no COPILOT_API_URL, the post is
skipped and logged, and the run still records to the local history.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("recovery-proof.events")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_event_payload(label: str, result: dict) -> dict:
    """Shape the POST /api/events body for a restore-check result."""
    checks = result.get("checks", [])
    passed_n = sum(1 for c in checks if c.get("passed") and not c.get("skipped"))
    total_n = sum(1 for c in checks if not c.get("skipped"))
    dur = result.get("duration_s", 0)
    if result.get("passed"):
        title = f"Restore check ({label}): PASS ({passed_n}/{total_n} checks, {dur}s)"
    else:
        reason = result.get("failed_reason") or "checks failed"
        title = f"Restore check ({label}): FAIL — {reason}"
    return {
        "source": "restore",
        "type": "restore_check",
        "occurred_at": utcnow_iso(),
        "title": title,
        "url": None,
        "payload": result,
    }


def post_event(api_url: str | None, payload: dict, timeout: int = 15) -> str:
    """POST the result to the Copilot API. Returns 'sent' | 'failed' | 'skipped'."""
    if not api_url:
        log.info("no API URL configured — skipping event post")
        return "skipped"
    try:
        req = urllib.request.Request(
            api_url.rstrip("/") + "/api/events",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "sent" if 200 <= resp.status < 300 else "failed"
    except Exception as e:  # noqa: BLE001 - reporting must not fail the check
        log.warning("could not POST result event to %s: %s", api_url, e)
        return "failed"


def telegram_summary(label: str, result: dict, kind: str = "Restore check") -> str:
    checks = result.get("checks", [])
    passed_n = sum(1 for c in checks if c.get("passed") and not c.get("skipped"))
    total_n = sum(1 for c in checks if not c.get("skipped"))
    skipped_n = sum(1 for c in checks if c.get("skipped"))
    dur = result.get("duration_s", 0)
    backup = result.get("backup", {})
    size_mb = (backup.get("size_bytes") or 0) / 1_000_000
    age_h = (backup.get("age_s") or 0) / 3600
    skip_note = f" ({skipped_n} skipped)" if skipped_n else ""
    if result.get("passed"):
        return (f"✅ {kind} ({label}): PASS — {passed_n}/{total_n} checks"
                f"{skip_note} in {dur}s. Backup {size_mb:.0f} MB, {age_h:.1f}h old.")
    reason = result.get("failed_reason") or "checks failed"
    return (f"❌ {kind} ({label}): FAIL — {reason}. "
            f"Backup {size_mb:.0f} MB, {age_h:.1f}h old.")


def send_telegram(token: str, chat_id: str, text: str, timeout: int = 15) -> bool:
    """Send via the Bot API. Returns False (never raises) on failure."""
    try:
        body = json.dumps({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:  # noqa: BLE001 - notify failures are warnings
        log.warning("telegram send failed: %s", e)
        return False


def maybe_notify_telegram(label: str, result: dict, kind: str = "Restore check") -> str:
    """Send the summary if configured; returns 'sent' | 'failed' | 'skipped'."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log.info("Telegram not configured — skipping")
        return "skipped"
    ok = send_telegram(token, chat_id, telegram_summary(label, result, kind))
    return "sent" if ok else "failed"


def slack_summary(label: str, result: dict, kind: str = "Restore check") -> str:
    """The same summary, in Slack's plain-text shape (no markdown needed)."""
    checks = result.get("checks", [])
    passed_n = sum(1 for c in checks if c.get("passed") and not c.get("skipped"))
    total_n = sum(1 for c in checks if not c.get("skipped"))
    skipped_n = sum(1 for c in checks if c.get("skipped"))
    dur = result.get("duration_s", 0)
    skip_note = f" ({skipped_n} skipped)" if skipped_n else ""
    if result.get("passed"):
        return (f":white_check_mark: {kind} ({label}): PASS — "
                f"{passed_n}/{total_n} checks{skip_note} in {dur}s.")
    reason = result.get("failed_reason") or "checks failed"
    return f":x: {kind} ({label}): FAIL — {reason}."


def send_slack(webhook_url: str, text: str, timeout: int = 15) -> bool:
    """POST to a Slack incoming webhook. Returns False (never raises) on failure."""
    try:
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            webhook_url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as e:  # noqa: BLE001 - notify failures are warnings
        log.warning("slack send failed: %s", e)
        return False


def maybe_notify_slack(label: str, result: dict, kind: str = "Restore check") -> str:
    """Send the summary to Slack if SLACK_WEBHOOK_URL is set.
    Returns 'sent' | 'failed' | 'skipped'."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        log.info("Slack not configured — skipping")
        return "skipped"
    ok = send_slack(webhook_url, slack_summary(label, result, kind))
    return "sent" if ok else "failed"
