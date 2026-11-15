# Changelog

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
