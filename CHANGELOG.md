# Changelog

## 0.3.0 — 2026-11-15

- S3 protection audit (`recovery-proof audit --config audit.yaml`, Phase 2):
  six read-only checks — Object Lock enabled, default retention ≥ 30 days,
  production role cannot delete (IAM policy simulation, never a trial
  delete), separate credentials (backup writer ≠ production, and the audit
  itself is not running as production), versioning enabled, retention
  outlasts dwell time (≥ 35 days, configurable). A check that cannot be
  evaluated is skipped, never a pass. Runs with a dedicated reader
  credential; `--endpoint-url` targets S3-compatible stores (MinIO).
- CI: a MinIO docker test verifies the S3-side checks against a real
  S3-compatible API and that the IAM-backed checks degrade to skipped
  there. Fixed along the way: boto3 resolves credentials eagerly at client
  creation, so a missing credential source now fails cleanly (exit 2, one
  line) instead of a traceback.
- 104 unit tests + 3 real-Docker tests (Postgres + MySQL restore, MinIO audit).

## 0.2.0 — 2026-11-15

- MySQL engine (`--engine mysql`): restores a mysqldump SQL backup into an
  ephemeral `mysql:8.0` container, runs the same checks-file shape (table
  row counts + custom SQL, MySQL dialect), and verifies integrity with
  `CHECK TABLE` over every base table. The password travels via `MYSQL_PWD`,
  never on a command line. Live-source dumps use `mysqldump
  --single-transaction --routines --triggers`.
- Refactor: the checker is now an engine-agnostic orchestrator
  (`recovery_proof/check.py`) over an engine interface
  (`recovery_proof/engines/`). Adding a database means adding an engine.
  The Postgres engine is unchanged in behaviour; the dump-verification
  check is now typed `"dump"` (the backup file itself) rather than
  `"integrity"` (the restored database).
- 85 unit tests + 2 real-Docker restore tests (Postgres + MySQL); CI on
  Python 3.11 + 3.12.

## 0.1.1 — 2026-11-15

- Fixed the amcheck check: it passed the index name as a quoted identifier
  (`bt_index_check("users_pkey")`), which Postgres reads as a column
  reference and fails on every index. The name is now a bound parameter
  (`bt_index_check(%s)` with the schema-qualified name), i.e. a regclass
  value. Found by the CI docker-restore job; the unit tests now assert the
  parameterised form so it cannot regress.
- Failed checks now log their detail line, so a CI failure names the cause
  instead of only the check name.

## 0.1.0 — 2026-11-15

- Postgres restore checker as a standalone package, extracted from the
  Incident Copilot restore checker and extended:
  - Integrity checks: dump verification (`pg_restore --list` for custom
    format) and amcheck btree verification on the restored database.
    Unavailable checks are recorded as skipped, never as a pass or a failure.
  - Append-only results history (`~/.recovery-proof/results.jsonl`) and a
    `recovery-proof report` command that publishes the measured recovery time
    (median + p95 restore duration) instead of a guessed RTO.
  - Standalone CLI — no Copilot API required; the timeline event post is
    optional (`--api-url` / `$COPILOT_API_URL`).
- 64 tests; CI on Python 3.11 + 3.12, plus a real-Docker restore job.
