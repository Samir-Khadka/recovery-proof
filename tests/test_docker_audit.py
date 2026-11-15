"""End-to-end S3 audit test against a real S3-compatible store (CI only).

Runs only when invoked with ``pytest -m docker``. The CI docker job starts
Silo — the community-maintained MinIO fork (``pgsty/silo``), used because
MinIO deleted its Docker Hub images in September 2026 and Quay stopped
serving anonymous pulls the same month — and this test creates a bucket with
Object Lock + versioning + a 40-day default retention, then runs the audit
CLI against it. Silo has no IAM policy simulation, so the two IAM-backed
checks degrade to skipped — which is itself asserted: the audit must not
crash on an S3-compatible store that lacks IAM.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

ROOT = Path(__file__).parent.parent
S3_URL = "http://127.0.0.1:9000"
BUCKET = "recovery-proof-audit-test"


def _s3_client():
    import boto3
    return boto3.client(
        "s3", endpoint_url=S3_URL,
        aws_access_key_id="minioadmin", aws_secret_access_key="minioadmin",
        region_name="us-east-1",
    )


def _wait_for_s3(timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            _s3_client().list_buckets()
            return
        except Exception:  # noqa: BLE001 - not up yet, keep waiting
            time.sleep(2)
    raise AssertionError("S3 store did not come up within %ss" % timeout_s)


def test_audit_against_s3_compatible(tmp_path):
    _wait_for_s3()
    s3 = _s3_client()
    try:
        s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    except Exception as e:  # noqa: BLE001 - bucket may already exist from a rerun
        if "BucketAlreadyOwnedByYou" not in str(e) and "BucketAlreadyExists" not in str(e):
            raise
    s3.put_bucket_versioning(Bucket=BUCKET,
                             VersioningConfiguration={"Status": "Enabled"})
    s3.put_object_lock_configuration(
        Bucket=BUCKET,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 40}},
        },
    )
    cfg = tmp_path / "audit.yaml"
    cfg.write_text(
        "bucket: %s\n" % BUCKET
        + "backup_prefix: db/\n"
        + "production_role_arn: arn:aws:iam::123456789012:role/myapp-prod\n"
        + "backup_writer_arn: arn:aws:iam::123456789012:role/myapp-backup-writer\n"
    )
    env = {**os.environ,
           "AWS_ACCESS_KEY_ID": "minioadmin",
           "AWS_SECRET_ACCESS_KEY": "minioadmin",
           "AWS_DEFAULT_REGION": "us-east-1"}
    p = subprocess.run(
        [sys.executable, "-m", "recovery_proof", "audit",
         "--config", str(cfg), "--endpoint-url", S3_URL],
        capture_output=True, text=True, timeout=120, cwd=ROOT, env=env,
    )
    assert p.returncode == 0, f"stdout:\n{p.stdout}\nstderr:\n{p.stderr}"
    # The three S3-side checks pass against the real API.
    assert "OK   Object Lock enabled" in p.stdout
    assert "OK   Default retention >= 30 days" in p.stdout
    assert "OK   Retention outlasts dwell time (>= 35 days)" in p.stdout
    assert "OK   Versioning enabled" in p.stdout
    # MinIO has no IAM simulation, so that check degrades to skipped, not a crash.
    assert "SKIP Production role cannot delete backups" in p.stdout
