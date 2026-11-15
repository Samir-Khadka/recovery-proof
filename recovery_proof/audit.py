"""S3 backup protection audit (Recovery Proof v0.3, Phase 2).

Read-only checks against the bucket that holds the backups, run with a
dedicated reader credential — never the production role, never the backup
writer. Nothing here writes, deletes, or attempts a delete; the
"production role cannot delete" check uses IAM policy simulation
(``iam:SimulatePrincipalPolicy``), not a trial delete.

The six checks (PLAN.md §6):

1. Object Lock enabled on the bucket.
2. Default retention (Governance or Compliance) ≥ the configured minimum
   (default 30 days).
3. Production role cannot delete backups — the production IAM role/user has
   no ``s3:DeleteObject`` / ``s3:DeleteObjectVersion`` on the backup prefix,
   evaluated by IAM policy simulation.
4. Separate credentials — the backup writer identity differs from the
   production identity, and the audit itself is not running as the
   production role.
5. Versioning enabled.
6. Retention outlasts dwell time — retention ≥ the configured dwell window
   (default 35 days). The plan cites no dwell-time statistic: none is
   traceable to a primary source, so 35 days is a configurable default, not
   a claim about attacker behaviour.

A check that cannot be evaluated (missing permission, missing config,
unreachable API) is recorded as **skipped**, never as a pass or a failure.
The bucket itself not existing, or no AWS credentials at all, is an infra
error (exit 2).

Usage:
    python -m recovery_proof audit --config audit.yaml
    python -m recovery_proof audit --config audit.yaml --bucket other --format json
    # S3-compatible stores (MinIO):
    python -m recovery_proof audit --config audit.yaml --endpoint-url http://localhost:9000
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

log = logging.getLogger("recovery-proof.audit")

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2

DELETE_ACTIONS = ["s3:DeleteObject", "s3:DeleteObjectVersion"]


class AuditError(Exception):
    """Infra/usage error for the audit (exit 2)."""


def _normalize_arn(arn: str) -> str:
    """Assumed-role ARNs (arn:aws:sts::123:assumed-role/Name/session) refer
    to the same identity as the role ARN (arn:aws:iam::123:role/Name).
    Normalise so the two compare equal. Everything else passes through."""
    parts = arn.split(":")
    if len(parts) >= 6 and parts[2] == "sts" and parts[5].startswith("assumed-role/"):
        role = parts[5].split("/")[1]
        return f"arn:aws:iam::{parts[4]}:role/{role}"
    return arn


def _check(name: str, passed: bool, detail: str, skipped: bool = False) -> dict:
    return {"name": name, "type": "audit", "passed": passed,
            "skipped": skipped, "detail": detail}


# ---------------------------------------------------------------- config
def load_audit_config(path: Path) -> dict:
    """Load the audit config (YAML preferred, JSON accepted)."""
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise AuditError(
                "audit config is YAML but pyyaml is not installed — "
                "pip install pyyaml or use a .json config"
            ) from None
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise AuditError(f"audit config {path} must be a mapping")
    cfg = {
        "bucket": data.get("bucket"),
        "region": data.get("region"),
        "backup_prefix": (data.get("backup_prefix") or "").lstrip("/"),
        "production_role_arn": data.get("production_role_arn"),
        "backup_writer_arn": data.get("backup_writer_arn"),
        "min_retention_days": int(data.get("min_retention_days", 30)),
        "dwell_days": int(data.get("dwell_days", 35)),
    }
    return cfg


# ---------------------------------------------------------------- clients
def build_clients(profile: str | None, region: str | None,
                  endpoint_url: str | None):
    """Real boto3 clients. Raises AuditError if boto3 is missing."""
    try:
        import boto3
    except ImportError:
        raise AuditError(
            "boto3 is not installed — pip install boto3 (or requirements.txt)"
        ) from None
    import boto3.session
    session = boto3.session.Session(profile_name=profile, region_name=region)
    kw = {"endpoint_url": endpoint_url} if endpoint_url else {}
    try:
        # Client creation resolves credentials eagerly (the chain includes
        # the instance-metadata endpoint), so a missing or unreachable
        # credential source fails here, not at the first API call.
        s3 = session.client("s3", **kw)
        iam = session.client("iam", **kw)
        sts = session.client("sts", **kw)
    except Exception as e:  # noqa: BLE001 - any credential failure is the same user error
        raise AuditError(
            "could not create AWS clients — no usable credentials found. "
            "Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, pass --profile, "
            f"or run where an instance role is available ({e})"
        ) from None
    return s3, iam, sts


# ---------------------------------------------------------------- the checks
def _get_object_lock(s3, bucket: str) -> dict | None:
    """The bucket's Object Lock configuration, or None if it has none."""
    try:
        resp = s3.get_object_lock_configuration(Bucket=bucket)
    except Exception as e:  # noqa: BLE001 - a missing config is a fail, not a crash
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ("ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"):
            return None
        raise
    return resp.get("ObjectLockConfiguration", {}) or {}


def _retention_days(rule: dict) -> int | None:
    """DefaultRetention rule -> days. Years convert at 365 days."""
    ret = rule.get("DefaultRetention") or {}
    if "Days" in ret:
        return int(ret["Days"])
    if "Years" in ret:
        return int(ret["Years"]) * 365
    return None


def audit_bucket(cfg: dict, s3, iam, sts) -> dict:
    """Run the six checks. Returns {bucket, passed, checks}."""
    bucket = cfg["bucket"]
    if not bucket:
        raise AuditError("no bucket — set bucket in the config or pass --bucket")
    result: dict = {"bucket": bucket, "passed": False, "checks": []}

    # The bucket itself must exist and be reachable; anything else is infra.
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception as e:  # noqa: BLE001 - surface as a clear infra error
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket"):
            raise AuditError(f"bucket not found: {bucket}") from None
        if code in ("403", "AccessDenied"):
            raise AuditError(
                f"access denied to bucket {bucket} — the reader credential "
                "needs s3:ListBucket / s3:GetBucketVersioning and friends"
            ) from None
        raise AuditError(f"could not reach bucket {bucket}: {e}") from None

    # --- 1. Object Lock enabled
    lock_read_error = False
    try:
        lock_cfg = _get_object_lock(s3, bucket)
    except Exception as e:  # noqa: BLE001 - an unreadable config is skipped, not fatal
        lock_read_error = True
        result["checks"].append(_check(
            "Object Lock enabled", False,
            f"could not read Object Lock configuration — skipped ({e})", skipped=True))
        lock_cfg = None
    if lock_cfg is not None:
        enabled = lock_cfg.get("ObjectLockEnabled") == "Enabled"
        result["checks"].append(_check(
            "Object Lock enabled", enabled,
            "ObjectLockEnabled: Enabled" if enabled
            else "Object Lock is not enabled on this bucket"))
    elif not any(c["name"] == "Object Lock enabled" for c in result["checks"]):
        result["checks"].append(_check(
            "Object Lock enabled", False,
            "no Object Lock configuration on this bucket (Object Lock must be "
            "enabled at bucket creation — it cannot be added later)"))

    # --- 2 & 6. Retention: default minimum, and outlasting dwell time
    if lock_read_error:
        # The retention rule lives inside the Object Lock configuration; if
        # that could not be read, neither retention check can be evaluated.
        result["checks"].append(_check(
            f"Default retention >= {cfg['min_retention_days']} days", False,
            "Object Lock configuration unreadable — skipped", skipped=True))
        result["checks"].append(_check(
            f"Retention outlasts dwell time (>= {cfg['dwell_days']} days)", False,
            "Object Lock configuration unreadable — skipped", skipped=True))
        days = None
    else:
        rule = (lock_cfg or {}).get("Rule", {}) if lock_cfg else {}
        days = _retention_days(rule)
        mode = ((rule.get("DefaultRetention") or {}).get("Mode") or "unset")
        if days is None:
            result["checks"].append(_check(
                "Default retention >= %d days" % cfg["min_retention_days"], False,
                "no default retention rule on the bucket"))
            result["checks"].append(_check(
                "Retention outlasts dwell time (>= %d days)" % cfg["dwell_days"], False,
                "no default retention rule on the bucket"))
        else:
            result["checks"].append(_check(
                f"Default retention >= {cfg['min_retention_days']} days",
                days >= cfg["min_retention_days"],
                f"default retention is {mode}, {days} days"))
            result["checks"].append(_check(
                f"Retention outlasts dwell time (>= {cfg['dwell_days']} days)",
                days >= cfg["dwell_days"],
                f"default retention is {mode}, {days} days"))

    # --- 3. Production role cannot delete (IAM policy simulation)
    prod = cfg.get("production_role_arn")
    if not prod:
        result["checks"].append(_check(
            "Production role cannot delete backups", False,
            "production_role_arn is not configured — skipped", skipped=True))
    else:
        prefix = cfg["backup_prefix"]
        resource = f"arn:aws:s3:::{bucket}/{prefix}*" if prefix else f"arn:aws:s3:::{bucket}/*"
        try:
            resp = iam.simulate_principal_policy(
                PolicySourceArn=prod,
                ActionNames=DELETE_ACTIONS,
                ResourceArns=[resource],
            )
            allowed = [r["EvalActionName"] for r in resp.get("EvaluationResults", [])
                       if r.get("EvalDecision") == "allowed"]
            if allowed:
                result["checks"].append(_check(
                    "Production role cannot delete backups", False,
                    f"simulation says the production role CAN {', '.join(allowed)} "
                    f"on {resource}"))
            else:
                result["checks"].append(_check(
                    "Production role cannot delete backups", True,
                    "IAM simulation: neither s3:DeleteObject nor "
                    "s3:DeleteObjectVersion is allowed on the backup prefix"))
        except Exception as e:  # noqa: BLE001 - cannot simulate, record and move on
            result["checks"].append(_check(
                "Production role cannot delete backups", False,
                f"could not simulate the production role's policies — skipped ({e})",
                skipped=True))

    # --- 4. Separate credentials
    writer = cfg.get("backup_writer_arn")
    if not prod or not writer:
        result["checks"].append(_check(
            "Separate credentials", False,
            "production_role_arn and backup_writer_arn are both required — skipped",
            skipped=True))
    elif _normalize_arn(writer) == _normalize_arn(prod):
        result["checks"].append(_check(
            "Separate credentials", False,
            "the backup writer and the production role are the same identity"))
    else:
        try:
            caller = _normalize_arn(sts.get_caller_identity().get("Arn", ""))
        except Exception as e:  # noqa: BLE001 - cannot learn the caller, record it
            result["checks"].append(_check(
                "Separate credentials", False,
                f"backup writer differs from production, but the audit caller "
                f"could not be identified — skipped ({e})", skipped=True))
            caller = None
        if caller is not None:
            if caller == _normalize_arn(prod):
                result["checks"].append(_check(
                    "Separate credentials", False,
                    "the audit is running as the production role — use a "
                    "dedicated reader credential"))
            else:
                result["checks"].append(_check(
                    "Separate credentials", True,
                    f"backup writer ({writer}) differs from production ({prod}); "
                    f"audit runs as {caller}"))

    # --- 5. Versioning enabled
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket)
        status = versioning.get("Status")
        result["checks"].append(_check(
            "Versioning enabled", status == "Enabled",
            f"versioning is {status or 'not configured'}"))
    except Exception as e:  # noqa: BLE001 - unreadable versioning is skipped, not fatal
        result["checks"].append(_check(
            "Versioning enabled", False,
            f"could not read versioning — skipped ({e})", skipped=True))

    failed = [c for c in result["checks"] if not c["passed"] and not c.get("skipped")]
    result["passed"] = not failed
    return result


# ---------------------------------------------------------------- CLI
def parse_audit_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Recovery Proof S3 protection audit")
    ap.add_argument("--config", type=Path, required=True,
                    help="audit config file (YAML or JSON)")
    ap.add_argument("--bucket", help="bucket to audit (overrides the config)")
    ap.add_argument("--profile", help="AWS profile (default: the default credential chain)")
    ap.add_argument("--region", help="AWS region (overrides the config)")
    ap.add_argument("--endpoint-url", help="S3-compatible endpoint, e.g. a local MinIO")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--output", type=Path, help="write the report here as well as stdout")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def render_text(result: dict) -> str:
    lines = [f"S3 protection audit — bucket {result['bucket']}", ""]
    for c in result["checks"]:
        mark = "SKIP" if c.get("skipped") else ("OK  " if c["passed"] else "FAIL")
        lines.append(f"{mark} {c['name']} — {c['detail']}")
    passed = sum(1 for c in result["checks"] if c["passed"] and not c.get("skipped"))
    total = sum(1 for c in result["checks"] if not c.get("skipped"))
    skipped = sum(1 for c in result["checks"] if c.get("skipped"))
    lines.append("")
    lines.append(f"{'PASS' if result['passed'] else 'FAIL'}: {passed}/{total} checks"
                 + (f" ({skipped} skipped)" if skipped else ""))
    return "\n".join(lines) + "\n"


def audit_main(argv=None) -> int:
    args = parse_audit_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        cfg = load_audit_config(args.config)
    except (AuditError, FileNotFoundError, ValueError, KeyError) as e:
        log.error("audit config error: %s", e)
        return EXIT_INFRA
    if args.bucket:
        cfg["bucket"] = args.bucket
    if args.region:
        cfg["region"] = args.region
    try:
        s3, iam, sts = build_clients(args.profile, cfg.get("region"), args.endpoint_url)
        result = audit_bucket(cfg, s3, iam, sts)
    except AuditError as e:
        log.error("audit error: %s", e)
        return EXIT_INFRA
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_INFRA
    if args.format == "json":
        out = json.dumps(result, indent=2) + "\n"
    else:
        out = render_text(result)
    sys.stdout.write(out)
    if args.output:
        args.output.write_text(out)
    return EXIT_PASS if result["passed"] else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(audit_main())
