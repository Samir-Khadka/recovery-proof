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

## What it does

- Restores a Postgres backup (`.dump` custom format or `.sql`) into an
  ephemeral `postgres:16.4` container — random password, random localhost
  port, deleted in a `finally` block even when something fails.
- Verifies the dump itself first (`pg_restore --list` for custom format).
- Runs your checks file: per-table minimum row counts, custom SQL queries
  that must return ≥1 row, and **integrity checks** (amcheck btree
  verification on the restored database). A check whose prerequisite is
  unavailable is recorded as **skipped**, never as a pass or a failure.
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

## What v0.2 does (new)

- **MySQL** (`--engine mysql`): restores a mysqldump SQL backup into an
  ephemeral `mysql:8.0` container and runs the same checks-file shape
  (table row counts + custom SQL, in MySQL dialect — see
  `checks.mysql.example.yaml`). Integrity is `CHECK TABLE` over every base
  table. The password travels via `MYSQL_PWD`, never on a command line.
  The dump restores into `--database` (default `recovery_proof`); use a
  single-database dump without `CREATE DATABASE` (the plain
  `mysqldump <db>` form).
- The checker is now an engine-agnostic orchestrator over an engine
  interface (`recovery_proof/engines/`). Adding a database means adding an
  engine, not touching the orchestrator.

## Readiness score and dashboard (v0.4)

```bash
# One number per system, 0–100, with a grade (A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60)
recovery-proof score --system nightly --rto-seconds 900
recovery-proof score --systems systems.yaml --format md   # the auditor-readable report
recovery-proof score --format json

# A static HTML dashboard from the restore + audit histories
recovery-proof dashboard --output dashboard.html --systems systems.yaml
```

The score's formula (documented in `recovery_proof/score.py`): restore pass
rate over the last 10 runs (40 points), freshness of the last successful
restore (20), measured median restore vs your declared RTO (20), and the
latest protection audit (20). Every input is a measured fact — a component
with no data scores 0 and says so. The declared RTO is the only input that
isn't measured: it is your promise, and the score measures you against it
(see `systems.example.yaml`).

## Slack alerts (v0.4)

Set `SLACK_WEBHOOK_URL` (an incoming webhook) and the restore checker and
the audit notify Slack on every run, alongside Telegram
(`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`). Both are best-effort: a notify
failure is logged and never fails the check. `--no-slack` / `--no-telegram`
skip either one.

## Clean-point detection (v0.5)

When a backup is infected, the question is not "is the latest backup good"
but "which is the last good one". The clean-point scorer compares restore
points and recommends the last clean point — the newest point older than
the earliest flagged one, with the evidence listed for every point:

```bash
# File restore points (directories of files), oldest first
recovery-proof clean-point backups/2026-11-10 backups/2026-11-11 backups/2026-11-12 \
  --canaries canaries.yaml

# Database restore points (plain-SQL dumps, oldest first)
recovery-proof clean-point db-2026-11-10.sql db-2026-11-11.sql db-2026-11-12.sql
```

File points are scored 0–100 (flagged at 50) on five heuristics v1: known
ransomware extensions, ransom-note filenames, canary files (a canary whose
hash differs, or that is gone, flags the point on its own — see
`fixtures/clean-point/canaries.yaml`), high-entropy text-like files, and
the mass-change rate vs the previous point. Database points score the
row-level mass-change rate (each COPY row is hashed; a mysqldump-style file
has no COPY blocks and is reported as not measurable, not guessed).

The language contract is the point: a clean score means **no signs found**,
never "guaranteed clean" — a heuristic can miss an attack. A later point
that scores clean after a flagged one is noted but not recommended; a clean
heuristic score does not prove an infection is gone.

Measured false-positive rate: **0 on 5 clean points** (3 file points —
a clean point, an ordinary day's change, and a 56% mass change — and 2
database points), asserted by the test suite over the fixtures in
`fixtures/clean-point/` (generated deterministically by
`scripts/make_cleanpoint_fixtures.py`).

## Drills and runbooks (v0.6)

A drill proves you can recover in time, not just that the steps run. A
runbook is a YAML playbook of steps; a drill executes it and produces a
pass/fail scorecard that names the measured recovery time vs the declared
RTO:

```bash
recovery-proof drill --playbook drill.yaml            # run it
recovery-proof drill --playbook drill.yaml --dry-run  # validate only
recovery-proof drill --playbook drill.yaml --format md --output drill.md
```

```yaml
name: nightly postgres drill
system: nightly
rto_seconds: 900
steps:
  - name: restore the latest backup
    type: restore
    dump: backups/latest.dump
    checks: checks.yaml
  - name: check the clean point
    type: clean-point
    points: [backups/2026-11-10, backups/2026-11-11]
  - name: readiness score
    type: score
    min_score: 60
```

Six step types: `restore`, `audit`, `clean-point`, `score`, `shell`,
`wait`. A failed step stops the drill unless `continue_on_failure` is
set. The verdict is PASS only when every step passes AND the measured
recovery time — the time spent in restore steps, not the whole drill — is
within the declared RTO. Results record to
`~/.recovery-proof/drills.jsonl`, and Telegram + Slack are notified once
at the end. Scheduling is your cron, not a built-in daemon:
`0 2 * * 0 recovery-proof drill --playbook drill.yaml`.

## S3 protection audit (v0.3)

```bash
# Copy audit.example.yaml, fill in your bucket + role ARNs, then:
python -m recovery_proof audit --config audit.yaml
python -m recovery_proof audit --config audit.yaml --format json --output audit.json

# Against a local MinIO (S3-compatible store):
python -m recovery_proof audit --config audit.yaml --endpoint-url http://localhost:9000
```

Six read-only checks: Object Lock enabled, default retention ≥ 30 days,
production role cannot delete (IAM policy simulation — never a trial
delete), separate credentials, versioning enabled, retention outlasts dwell
time (≥ 35 days). The audit runs with a dedicated reader credential, never
the production role. A check that cannot be evaluated (missing permission,
missing config, an S3-compatible store without IAM) is recorded as
**skipped**, never as a pass. Exit 0 = all pass, 1 = a check failed,
2 = infra error (bad config, missing bucket, no credentials).

## Quickstart

```bash
pip install -r requirements.txt

# Postgres: from a backup file
python -m recovery_proof check --backup-file /backups/latest.dump --checks checks.yaml

# Postgres: dump a live source first, then restore the fresh dump
python -m recovery_proof check --source-url "postgresql://user:pw@host/db" --checks checks.yaml

# MySQL: from a mysqldump file
python -m recovery_proof check --engine mysql --backup-file /backups/latest.sql --checks checks.mysql.yaml

# MySQL: dump a live source first
python -m recovery_proof check --engine mysql --source-url "mysql://user:pw@host:3306/db" --checks checks.mysql.yaml

# The measured recovery time, from the history
python -m recovery_proof report --system nightly
python -m recovery_proof report --system nightly --format json
```

Exit codes: `0` = all checks passed, `1` = restore or a check failed,
`2` = infra/usage error (no Docker, missing file, missing tool).

Host prerequisites: Docker, the engine's client tools (`postgresql-client`
for Postgres, `mysql-client` for MySQL), Python 3.11+.

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
