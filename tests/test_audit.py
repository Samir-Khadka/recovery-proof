"""Tests for the S3 protection audit (mocked AWS clients — no real AWS)."""
import json

import pytest

from recovery_proof.audit import (
    AuditError,
    _normalize_arn,
    audit_bucket,
    audit_main,
    load_audit_config,
    render_text,
)

PROD = "arn:aws:iam::123456789012:role/myapp-prod"
WRITER = "arn:aws:iam::123456789012:role/myapp-backup-writer"
READER = "arn:aws:iam::123456789012:role/audit-reader"


class FakeClientError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code, "Message": code}}
        super().__init__(code)


class FakeS3:
    def __init__(self, *, versioning=None, lock=None, head_error=None,
                 versioning_error=None, lock_error=None):
        self.versioning = versioning if versioning is not None else {"Status": "Enabled"}
        self.lock = lock
        self.head_error = head_error
        self.versioning_error = versioning_error
        self.lock_error = lock_error

    def head_bucket(self, Bucket):
        if self.head_error:
            raise FakeClientError(self.head_error)

    def get_bucket_versioning(self, Bucket):
        if self.versioning_error:
            raise FakeClientError(self.versioning_error)
        return self.versioning

    def get_object_lock_configuration(self, Bucket):
        if self.lock_error:
            raise FakeClientError(self.lock_error)
        if self.lock is None:
            raise FakeClientError("ObjectLockConfigurationNotFoundError")
        return {"ObjectLockConfiguration": self.lock}


class FakeIAM:
    def __init__(self, decisions=None, error=None):
        self.decisions = decisions or {}
        self.error = error
        self.seen = None

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns):
        self.seen = {"PolicySourceArn": PolicySourceArn,
                     "ActionNames": ActionNames, "ResourceArns": ResourceArns}
        if self.error:
            raise FakeClientError(self.error)
        return {"EvaluationResults": [
            {"EvalActionName": a, "EvalDecision": self.decisions.get(a, "implicitDeny")}
            for a in ActionNames]}


class FakeSTS:
    def __init__(self, arn=READER, error=None):
        self.arn = arn
        self.error = error

    def get_caller_identity(self):
        if self.error:
            raise FakeClientError(self.error)
        return {"Arn": self.arn}


def _good_lock(days=40, mode="GOVERNANCE"):
    return {"ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": mode, "Days": days}}}


def _cfg(**overrides):
    cfg = {"bucket": "my-app-backups", "region": None, "backup_prefix": "db/",
           "production_role_arn": PROD, "backup_writer_arn": WRITER,
           "min_retention_days": 30, "dwell_days": 35}
    cfg.update(overrides)
    return cfg


def _by_name(result):
    return {c["name"]: c for c in result["checks"]}


def test_audit_all_six_pass():
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock()), FakeIAM(), FakeSTS())
    assert result["passed"] is True
    assert len(result["checks"]) == 6
    assert all(c["passed"] and not c.get("skipped") for c in result["checks"])


def test_audit_object_lock_missing_fails_and_retention_fails():
    result = audit_bucket(_cfg(), FakeS3(lock=None), FakeIAM(), FakeSTS())
    checks = _by_name(result)
    assert checks["Object Lock enabled"]["passed"] is False
    assert "cannot be added later" in checks["Object Lock enabled"]["detail"]
    assert checks["Default retention >= 30 days"]["passed"] is False
    assert checks["Retention outlasts dwell time (>= 35 days)"]["passed"] is False
    assert result["passed"] is False


def test_audit_retention_30_passes_minimum_but_not_dwell():
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock(days=30)), FakeIAM(), FakeSTS())
    checks = _by_name(result)
    assert checks["Default retention >= 30 days"]["passed"] is True
    assert checks["Retention outlasts dwell time (>= 35 days)"]["passed"] is False


def test_audit_retention_in_years_converts():
    lock = {"ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 1}}}
    result = audit_bucket(_cfg(), FakeS3(lock=lock), FakeIAM(), FakeSTS())
    checks = _by_name(result)
    assert checks["Default retention >= 30 days"]["passed"] is True
    assert "365 days" in checks["Default retention >= 30 days"]["detail"]


def test_audit_production_can_delete_fails():
    iam = FakeIAM(decisions={"s3:DeleteObject": "allowed"})
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock()), iam, FakeSTS())
    checks = _by_name(result)
    assert checks["Production role cannot delete backups"]["passed"] is False
    assert "s3:DeleteObject" in checks["Production role cannot delete backups"]["detail"]
    # The simulation was asked about the backup prefix, not the whole bucket.
    assert iam.seen["ResourceArns"] == ["arn:aws:s3:::my-app-backups/db/*"]
    assert iam.seen["PolicySourceArn"] == PROD


def test_audit_simulation_denied_is_skipped():
    iam = FakeIAM(error="AccessDenied")
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock()), iam, FakeSTS())
    checks = _by_name(result)
    assert checks["Production role cannot delete backups"]["skipped"] is True
    assert result["passed"] is True  # a skipped check never fails the audit


def test_audit_writer_is_production_fails():
    result = audit_bucket(_cfg(backup_writer_arn=PROD),
                          FakeS3(lock=_good_lock()), FakeIAM(), FakeSTS())
    checks = _by_name(result)
    assert checks["Separate credentials"]["passed"] is False
    assert "same identity" in checks["Separate credentials"]["detail"]


def test_audit_running_as_production_fails():
    sts = FakeSTS(arn="arn:aws:sts::123456789012:assumed-role/myapp-prod/session-1")
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock()), FakeIAM(), sts)
    checks = _by_name(result)
    assert checks["Separate credentials"]["passed"] is False
    assert "running as the production role" in checks["Separate credentials"]["detail"]


def test_normalize_arn():
    assert _normalize_arn("arn:aws:sts::123:assumed-role/prod/sess") == "arn:aws:iam::123:role/prod"
    assert _normalize_arn("arn:aws:iam::123:role/prod") == "arn:aws:iam::123:role/prod"
    assert _normalize_arn("arn:aws:iam::123:user/alice") == "arn:aws:iam::123:user/alice"


def test_audit_versioning_suspended_fails():
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock(), versioning={"Status": "Suspended"}),
                          FakeIAM(), FakeSTS())
    assert _by_name(result)["Versioning enabled"]["passed"] is False


def test_audit_versioning_unreadable_is_skipped():
    result = audit_bucket(_cfg(), FakeS3(lock=_good_lock(), versioning_error="AccessDenied"),
                          FakeIAM(), FakeSTS())
    assert _by_name(result)["Versioning enabled"]["skipped"] is True
    assert result["passed"] is True


def test_audit_no_bucket_is_infra():
    with pytest.raises(AuditError, match="no bucket"):
        audit_bucket(_cfg(bucket=None), FakeS3(), FakeIAM(), FakeSTS())


def test_audit_missing_bucket_is_infra():
    with pytest.raises(AuditError, match="bucket not found"):
        audit_bucket(_cfg(), FakeS3(lock=_good_lock(), head_error="NoSuchBucket"),
                     FakeIAM(), FakeSTS())


def test_audit_missing_role_arns_skips_those_checks():
    cfg = _cfg(production_role_arn=None, backup_writer_arn=None)
    result = audit_bucket(cfg, FakeS3(lock=_good_lock()), FakeIAM(), FakeSTS())
    checks = _by_name(result)
    assert checks["Production role cannot delete backups"]["skipped"] is True
    assert checks["Separate credentials"]["skipped"] is True
    assert result["passed"] is True


def test_load_audit_config_defaults(tmp_path):
    p = tmp_path / "audit.yaml"
    p.write_text("bucket: b\nproduction_role_arn: r\nbackup_writer_arn: w\n")
    cfg = load_audit_config(p)
    assert cfg["min_retention_days"] == 30 and cfg["dwell_days"] == 35
    assert cfg["backup_prefix"] == ""


def test_load_audit_config_json(tmp_path):
    p = tmp_path / "audit.json"
    p.write_text(json.dumps({"bucket": "b", "min_retention_days": 90}))
    cfg = load_audit_config(p)
    assert cfg["bucket"] == "b" and cfg["min_retention_days"] == 90


def test_load_audit_config_not_a_mapping(tmp_path):
    p = tmp_path / "audit.yaml"
    p.write_text("- a\n- b\n")
    with pytest.raises(AuditError, match="must be a mapping"):
        load_audit_config(p)


def test_render_text_counts():
    result = {"bucket": "b", "passed": False, "checks": [
        {"name": "A", "type": "audit", "passed": True, "skipped": False, "detail": "ok"},
        {"name": "B", "type": "audit", "passed": False, "skipped": False, "detail": "bad"},
        {"name": "C", "type": "audit", "passed": False, "skipped": True, "detail": "n/a"},
    ]}
    out = render_text(result)
    assert "OK   A — ok" in out and "FAIL B — bad" in out and "SKIP C — n/a" in out
    assert "FAIL: 1/2 checks (1 skipped)" in out


def test_audit_main_exit_codes(tmp_path, monkeypatch, capsys):
    import recovery_proof.audit as aud

    cfg_path = tmp_path / "audit.yaml"
    cfg_path.write_text("bucket: b\nproduction_role_arn: r\nbackup_writer_arn: w\n")
    monkeypatch.setattr(aud, "build_clients",
                        lambda *a, **k: (FakeS3(lock=_good_lock()), FakeIAM(), FakeSTS()))
    assert audit_main(["--config", str(cfg_path)]) == 0
    assert "PASS: 6/6 checks" in capsys.readouterr().out

    monkeypatch.setattr(aud, "build_clients",
                        lambda *a, **k: (FakeS3(lock=None), FakeIAM(), FakeSTS()))
    assert audit_main(["--config", str(cfg_path)]) == 1

    assert audit_main(["--config", str(tmp_path / "missing.yaml")]) == 2
