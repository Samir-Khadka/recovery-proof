# Recovery Proof

**Prove your backups actually restore.** A vendor-neutral restore-testing
layer: scheduled restores into an isolated sandbox, real integrity and
smoke-test checks, and a **measured recovery time** instead of a guessed RTO.

If we were hit tonight, could we really recover, how fast, and from which
clean point? This answers the first two. Clean-point detection and
clean-room recovery are on the roadmap (see `PLAN.md`).

> **Honest limits, up front.** A green check means the restore worked and
> the checks passed — it is not a guarantee the production recovery will
> work, and the clean-point detection (when it lands) will report "no signs
> found", never "guaranteed clean". The compliance angle is stated
> accurately in `PLAN.md` §10: DORA forces yearly tested recovery, but it
> never says "immutable" or sets a numeric RTO.

## What v0.1 does

- Restores a Postgres backup (`.dump` custom format or `.sql`) into an
  ephemeral `postgres:16.4` container — random password, random localhost
  port, deleted in a `finally` block even when something fails.
- Verifies the dump itself first (`pg_restore --list` for custom format).
- Runs your checks file: per-table minimum row counts, custom SQL queries
  that must return ≥1 row, and — new in v0.1 — **integrity checks**
  (amcheck btree verification on the restored database). A check whose
  prerequisite is unavailable is recorded as **skipped**, never as a pass
  or a failure.
- Records every run to an append-only history
  (`~/.recovery-proof/results.jsonl`) and publishes the **measured recovery
  time** (median + p95 restore duration) with `recovery-proof report`.
- Optionally posts the result to the Incident Copilot timeline
  (`--api-url` / `$COPILOT_API_URL`) and sends a Telegram summary
  (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`). Both are best-effort and
  never fail the check.

Extracted from the Incident Copilot restore checker
(https://github.com/Samir-Khadka/incident-copilot) — the checker, the
checks-file format, the event shape, and the Telegram path all carry over.
See `PLAN.md` §5 for the exact reuse map.

## Quickstart

```bash
pip install -r requirements.txt

# From a backup file
python -m recovery_proof check --backup-file /backups/latest.dump --checks checks.yaml

# Or dump a live source first, then restore the fresh dump
python -m recovery_proof check --source-url "postgresql://user:pw@host/db" --checks checks.yaml

# The measured recovery time, from the history
python -m recovery_proof report --system nightly
python -m recovery_proof report --system nightly --format json
```

Exit codes: `0` = all checks passed, `1` = restore or a check failed,
`2` = infra/usage error (no Docker, missing file, missing tool).

Host prerequisites: Docker, `postgresql-client` (`pg_dump` / `pg_restore` /
`psql`), Python 3.11+.

## Checks file

Copy `checks.example.yaml` to `checks.yaml` and tune it for your database:

```yaml
tables:
  users: 1
  orders: 1
queries:
  - name: "recent orders exist"
    sql: "SELECT 1 FROM orders WHERE created_at > now() - interval '7 days' LIMIT 1"
integrity:
  enabled: true
```

## Safety

- **Read-only access to backups.** The checker never writes to the backup
  store, never modifies the source database, never deletes a backup.
- **Sandbox with no route back to production.** The restore container runs
  on an isolated Docker network; the restored database is reachable only
  from the checker process.
- **No credentials in logs or reports.** URLs are redacted (`user:***@host`).
- **No data values leave the sandbox.** Results and reports contain check
  names and counts, never row contents.

## Roadmap

| Phase | Weeks | Deliverable |
|---|---|---|
| 0. Research | 1–2 | Interview 8–10 people who run backups or have recovered from an attack |
| **1. Restore checker** | **3–5** | **Postgres and MySQL restore tests with pass/fail and timing (this repo, v0.1 = Postgres)** |
| 2. Protection audit | 6–7 | S3 immutability and access checks |
| 3. Dashboard and alerts | 8–9 | Timeline, readiness score, Telegram and Slack alerts |
| 4. Clean point detection | 10–13 | Ransomware heuristics across restore points |
| 5. Drills and runbooks | 14–17 | Scheduled recovery drills and a scorecard |
| 6. Coverage | 18+ | Kubernetes, VM images, file shares, SaaS data |

Full plan: [`PLAN.md`](PLAN.md) (575 lines, verified 15 Nov 2026).

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q -m "not docker"   # unit tests, no Docker needed
python -m pytest tests/test_docker_restore.py -q -m docker  # real restore (needs Docker + psql)
```

## Licence

MIT.
