"""Tests for URL redaction and backup-format detection."""
from pathlib import Path

from recovery_proof.check import detect_format, redact_url


def test_redact_url_hides_password():
    url = "postgresql://samir:s3cret@db.example.com:5432/app"
    assert redact_url(url) == "postgresql://samir:***@db.example.com:5432/app"


def test_redact_url_no_password_keeps_user():
    url = "postgresql://samir@db.example.com/app"
    assert redact_url(url) == "postgresql://samir@db.example.com/app"


def test_redact_url_no_credentials_unchanged():
    url = "postgresql://db.example.com/app"
    assert redact_url(url) == url


def test_redact_url_garbage_returns_marker():
    assert redact_url("://not a url") == "<redacted-url>"


def test_detect_format_custom_magic(tmp_path):
    p = tmp_path / "b.dump"
    p.write_bytes(b"PGDMP" + b"\x00" * 100)
    assert detect_format(p) == "custom"


def test_detect_format_plain_sql(tmp_path):
    p = tmp_path / "b.sql"
    p.write_bytes(b"CREATE TABLE t (id INT);\n")
    assert detect_format(p) == "plain"


def test_detect_format_empty_file_is_plain(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert detect_format(p) == "plain"
