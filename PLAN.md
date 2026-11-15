# Recovery Proof — Plan v1.0

**Working name:** Recovery Proof (name is an open decision — see §12).
**Status:** Plan v1.0, written 15 Nov 2026. All facts below were verified live on
15 Nov 2026 against the vendors' own pages, the official EU regulation texts
(EUR-Lex), and the original survey reports. Vendor-sponsored figures are flagged
as such; unverifiable figures are excluded and named in §10.
**Relationship to Incident Copilot:** the restore checker is the wedge MVP.
Incident Copilot (public repo https://github.com/Samir-Khadka/incident-copilot)
already ships a nightly Postgres restore checker; Recovery Proof extends it into
a standalone product. **None of that work is wasted** — see §5 for the exact
reuse map (what exists vs what is new).

## 1. The problem

Ransomware is costly mainly because **recovery fails**, not because files get
encrypted. The failures are specific and measurable:

1. **Backups exist but were never test-restored**, so they turn out corrupt or
   incomplete. Veeam's Data Trust & Resilience Report 2026 (900+ senior
   IT/security/risk leaders, Apr 2026) found **90% of organisations were
   confident they could recover within their RTOs, but only 28% fully recovered
   all affected data**; 44% recovered less than 75%, and the average was 72% of
   affected data. Veeam Ransomware Trends Report 2025 (1,300 orgs, 900 hit):
   **fewer than 10% recovered more than 90% of servers within expectations**.
   (Both Veeam figures are vendor-sponsored — Veeam sells backup software.
   They are the largest-sample, most recent figures available; pair them with
   Coveware's ground-truth case data where a cost claim is made.)
2. **Attackers delete or encrypt the backups first.** Sophos, "The Impact of
   Compromised Backups on Ransomware Outcomes" (2024; n=2,974, survey by
   Vanson Bourne): **94% of victims said attackers attempted to compromise
   their backups, and 57% of attempts succeeded**. Veeam 2025 agrees closely:
   89% of organisations had backup repositories targeted, and on average
   **34% of backup repositories were modified or deleted**; only 32% used
   repositories configured as immutable.
3. **Teams restore from a backup that already contains the malware** and get
   hit again. Veeam 2025: **39% restored directly to production** without a
   sandbox scan; only 28% restored to a sandbox first; 8% could not verify
   backup integrity before restoring at all. (Veeam 2024: 63% restored
   directly into production without quarantine or scanning — the problem is
   improving but 39% still restore blind.)
4. **Nobody knows how long a full recovery actually takes**, so the recovery
   time objective is a guess. **No published report gives a planned-vs-actual
   RTO gap** — that gap is itself the product argument: measured restore time
   is the missing metric. Closest proxies: Veeam 2025 ("<10% recovered >90%
   of servers within expectations") and the Sophos State of Ransomware 2025
   recovery-time distribution (n=3,400, Jan–Mar 2025): 16% fully recovered in
   a day, 53% within a week, 97% within three months.

**The cost of getting it wrong.** Sophos 2024 (same compromised-backups
study): median overall recovery cost was **$3M when backups were compromised
vs $375K when intact — 8×**. 67% vs 36% paid the ransom; 26% vs 46% fully
recovered within a week. Sophos State of Ransomware 2025: mean recovery cost
(excluding ransom) $1.53M; median ransom payment $1M; **54% used backups to
restore — a six-year low**. Coveware Q4 2024 (real incident-response cases,
not a survey — the least biased source): 25% paid (record low), average
ransom $553,959, median $110,890. Veeam 2025: **17% of organisations that
paid the ransom still could not recover their data**.

**The question the product answers:** "If we were hit tonight, could we
really recover, how fast, and from which clean point?"

### What NOT to cite

- **"60% of backups incomplete; 50% of restore attempts fail"** — attributed
  to Avast in dozens of MSP blogs, but no original Avast report or page can
  be traced. Do not cite as a primary source. The Veeam 2026 90%-vs-28%
  confidence gap says the same thing with a traceable, recent source.
- **"31% fail to recover; 33% test infrequently or never"** (Kaseya blog,
  27 Apr 2026) — the blog names no primary source. Directional only.
- **"72% of German SMBs rarely or never test"** (DATA REVERSE, Q1 2025) —
  n=285, single country, secondary citation. Do not cite.
- **Median downtime 24 days** (Coveware) — the figure lives in a chart image
  on the Coveware page, not readable text; unverified. Do not cite.
- **"Average attacker dwell time ~33 days"** (Triskele Labs) — practitioner
  observation, no sample size. Do not cite as research.
- **Sophos State of Ransomware 2026 figures** (e.g. $1.7M average recovery
  cost) — only seen via secondary coverage; not verified on the original.
  Do not cite until verified.

## 2. Verified timeline — regulation and market

| Date | Event |
|---|---|
| 16 Jan 2023 | DORA (Regulation (EU) 2022/2554) and NIS2 (Directive (EU) 2022/2555) enter into force |
| 25 May 2018 | GDPR applies (Art. 32 restore + testing duties already in force) |
| 17 Oct 2024 | NIS2 transposition deadline; Commission Implementing Regulation (EU) 2024/2690 in effect 7 Nov 2024 (restore-testing duty for digital providers) |
| 18 Oct 2024 | CER Directive (EU) 2022/2557 measures apply |
| 17 Jan 2025 | **DORA applies** — the yearly recovery-testing duty (Art. 11(6)) is now live law for EU financial entities |
| 17 Apr 2025 | Member States' lists of NIS2 essential/important entities due (Art. 3(3)) |
| 6 Dec 2025 | Germany's NIS2 transposition (NIS2UmsuCG) in force (example of national law) |
| 20 Jan 2026 | Commission proposes targeted NIS2 amendments (COM(2026) 13) — a proposal, not law |
| 17 Jul 2026 | Member States identify CER critical entities |

## 3. Who else is in this space — verified 15 Nov 2026

Every vendor below verifies **only its own backups**. None ingests a
`pg_dump` / `mysqldump` / restic / Borg archive and proves it restores — yet
that is exactly what small and mid-size teams and SaaS stacks actually back
up. Verification that exists is either VM-centric or snapshot threat-scanning,
which answers "is the backup infected?" but not "does the application work
after restore, and how long did it take?"

| Vendor | Verification feature (real name) | What it actually checks | Own backups only? | Postgres / MySQL / managed cloud DB / K8s | Pricing |
|---|---|---|---|---|---|
| **Veeam** | **SureBackup** (in Veeam Backup & Replication) | Full mode boots the VM from backup in an isolated Virtual Lab and runs heartbeat, ping, and application tests (AD via LDAP, SQL Server via port 1433, web via HTTP) plus custom scripts — a real query is possible only via custom script. Scan-only mode does a CRC check + malware/YARA scan with no VM boot. **Does not verify application-level data integrity.** | Yes — Veeam backups only. Needs VMware vSphere or Hyper-V. Excludes backup copy jobs, Cloud Connect repos, archive tier, file-level backups, failover clusters. | **No, not directly.** A `pg_dump` on S3 is out of scope; SureBackup verifies VBR machine/volume images. K8s is a separate product, **Veeam Kasten**, licensed separately. | Data Platform, 3 editions, per-workload Universal License, quote-based; third-party figures ~$155–$227.50/workload/yr. Free Community Edition covers 10 workloads. |
| **Rubrik** | **Data Threat Analytics**: Threat Monitoring, Threat Hunting, Anomaly Detection, plus **Cyber Recovery Simulation** | Scans snapshots for IoCs (file pattern/hash/YARA, up to ~75,000 backups in ~60s), ML anomaly/encryption detection, blast-radius and sensitive-data analysis, walks snapshot history to pinpoint the last clean point. Recovery simulation tests recovery in an isolated environment. No routine "boot the DB and run integrity queries". | Yes — Rubrik snapshots only. | **Partial.** Protects RDS (MySQL, PostgreSQL, MariaDB, SQL Server, Oracle, Aurora) with point-in-time recovery; K8s supported. But file-based threat scanning cannot read inside a managed DB, and record-level restore for RDS is not documented. | Subscription, quote-only; AWS Marketplace entry ~$50,000/yr for 6 back-end TB (third-party figure). |
| **Cohesity** | **DataProtect** with **DataHawk** threat intelligence + ML anomaly detection; "verified clean snapshots"; automated DR testing | Anomaly detection and threat scanning/classification on snapshots, IOC scanning, clean-recovery-point identification, instant mass restore. Automated DR testing "regularly confirms recovery plans actually work". A third-party integrator (Elastio) notes Cohesity's detection does not open files to find zero-day or slow encryption. | Yes — Cohesity snapshots only. | **Partial.** Application-aware backups for SQL Server, Oracle, SAP HANA; automated discovery covers VMs, databases, file systems, K8s containers. Managed cloud DB restore verification not clearly documented. | Quote-based; no published starting figure. |
| **Commvault** | **Cleanroom** + **Threat Scan** + **Synthetic Recovery** (Commvault Cloud Cyber Recovery) | Threat Scan finds clean data across backups (signatures, AI encryption detection, YARA/custom hashes). Synthetic Recovery assembles a composite clean recovery point from the most recent clean file versions. Cleanroom is an on-demand isolated cloud environment for testing, forensics, and staging, with runbooks and documented readiness evidence. **The closest incumbent to this product.** | Yes — Commvault backups only. | **Broadest enterprise coverage.** "VMs, databases, file and object stores, cloud data environments, SaaS apps, and identity providers"; noted for SAP HANA through Kubernetes. Verification is still at the Commvault-backup level. | Commvault Cloud is per-TB/month SaaS (third-party figures ~$58.50/TB/mo file/object, ~$90/TB/mo databases). **Cleanroom is an add-on** (listed under Extras & Add-Ons). |
| **Druva** | **Recovery Intelligence** (in the **Premium Security** package): Threat Watch, Ransomware Detection, **Cyber Recovery Runbooks**, Sandbox Recovery, Curated Recovery | Threat Watch scans snapshots for IoCs 3× daily and auto-quarantines infected snapshots. Ransomware Detection uses ML/behavioural analysis with entropy, MIME-type, and file-integrity checks. Runbooks automate threat-aware recovery of whole application stacks, with Scheduled Cyber Recovery Testing (fire drills) and **Proof of Recovery reports**. Sandbox Recovery validates in an isolated environment before production. | Yes — Druva SaaS backups only. | **Narrower.** The Recovery tab covers VMware, AWS EC2/EBS, Azure VMs, Microsoft 365. Postgres/MySQL and K8s restore verification not clearly documented in the recovery features. | SaaS, quote-based; the recovery features sit in the **Premium Security** package (an upper tier), not the base. |
| **Acronis** | **Automated backup verification** (Acronis Cyber Protect) + at-rest malware scanning + instant restore into isolated cloud environments | Verification that backups are recoverable, with documented proof for audits/insurers; backups scanned for malware before restore; backup anomaly detection; DR failover testing with recovery readiness reports. The depth of the verification (full application smoke test vs mount-and-check) is less clearly documented than Veeam's. | Yes — Acronis backups only. | **Weakest here.** Covers Windows/Linux servers, workstations, Microsoft 365, Google Workspace. Postgres/MySQL and K8s restore verification not clearly documented. | Per workload (per PC, server, or M365 seat) + storage; the most SMB-friendly of the six, but still per-workload licensed. |

### Open-source tools

| Tool | Restore verification offered |
|---|---|
| **restic** | `restic check` verifies repository integrity (hashes; `--read-data` verifies the data itself). Restore is manual (`restic restore`). No scheduled restore testing, no boot, no DB integrity checks, no malware scanning — you script it yourself. |
| **Borg** | `borg check --verify-data` verifies repository/archive integrity. Restore is manual. No scheduled restore testing, no application checks. |
| **Kopia** | Periodic integrity checks validate stored content and manifests; `kopia snapshot verify` verifies snapshots. No scheduled restore testing, no boot, no DB checks. |

Sources: Veeam SureBackup — https://community.veeam.com/blogs-and-podcasts-57/veeam-v13-surebackup-verification-for-vsphere-12908 ;
Veeam editions/pricing — https://www.veeam.com/products/veeam-data-platform/enterprise-packaging-pricing-options.html ;
Veeam Kasten — https://www.veeam.com/products/cloud/kubernetes-backup/pricing.html ;
Rubrik Threat Hunting — https://www.rubrik.com/blog/company/24/4/accelerating-ransomware-recovery-with-rubrik-threat-hunting-for-us-government ;
Rubrik RDS + $50k entry — https://www.eon.io/blog/veeam-alternatives ;
Cohesity DataProtect — https://www.cohesity.com/resources/solution-brief/cohesity-dataprotect/ ;
Cohesity gap (Elastio) — https://elastio.com/platform/cohesity ;
Commvault cyber recovery — https://www.commvault.com/resources/datasheet/commvault-cloud-cyber-resilience ;
Commvault Cleanroom — https://www.commvault.com/capabilities/commvault-cleanroom ;
Druva Premium Security — https://www.druva.com/content/dam/druvaincprogram/collateral/datasheets/premium-security.pdf ;
Druva Recovery Intelligence — https://www.druva.com/content/dam/druvaincprogram/collateral/solution-briefs/solution-brief-recovery-intelligence.pdf ;
Acronis verification — https://www.acronis.com/en/blog/posts/how-to-integrate-cyber-insurance-requirements-into-your-backup-strategy/ ;
restic/Borg/Kopia — https://www.selfhostedguides.com/self-hosted-backup-strategy/ and https://hyehost.org/blog/open-source-vps-backup-tools-restic-borg-kopia

### The gap

Commvault's Cleanroom and Druva's Runbooks come closest to the concept, but
both are enterprise add-ons or upper tiers on top of their own backup
platform. Managed cloud databases are a genuine weak spot: Rubrik backs up
RDS but its file-based scanning cannot read inside it, and record-level
restore is undocumented. Kubernetes is a separate product or licence at Veeam
(Kasten) and uneven elsewhere. Pricing is the other gap: quote-based
enterprise contracts with a ~$50k/yr entry point at Rubrik and add-on tiers
for the recovery features, while the open-source tools that small teams
actually use offer only hash-level integrity checks and leave the "0 errors"
in 3-2-1-1-0 entirely to the user to script.

**The exploitable wedge is narrow and concrete:** a vendor-neutral,
self-serve layer that restores Postgres/MySQL dumps into ephemeral containers,
runs real integrity and smoke-test checks, measures the actual recovery time,
and produces audit-ready proof — for the stacks and budgets the incumbents
price out.

## 4. Product: "Recovery Proof" (working name)

**One line:** a vendor-neutral, developer-friendly layer that proves
recoverability end to end and tells you the exact clean recovery point.

### The five pillars

1. **Restore testing.** Scheduled restores into an isolated sandbox, followed
   by real checks: database integrity, row counts, application boot, a
   smoke-test query. Not "backup succeeded" — "the application works after
   restore".
2. **Recovery time measurement.** Time every restore and publish a **measured
   recovery time** instead of a guess. Track it over time per system, so the
   RTO is a number with a history, not a line in a spreadsheet.
3. **Backup protection audit.** Check immutability and isolation: object lock
   enabled, separate credentials, no delete rights from production, offline or
   air-gapped copies, retention that outlasts attacker dwell time.
4. **Infection-aware point selection.** Compare restore points for ransomware
   signs (sudden mass changes, high-entropy files, canary file changes, known
   extensions) and recommend the **last clean point**. Describe results as
   "no signs found", never "guaranteed clean".
5. **Clean-room recovery.** Restore into a quarantined environment, scan it,
   then promote to production. Plus runbook and drill automation (runnable
   playbooks, scheduled recovery drills with a pass/fail scorecard) and a
   **recovery readiness score** — one number and a report per system that
   executives and auditors understand.

## 5. What exists today — the Incident Copilot reuse map

Incident Copilot's restore checker (`~/workspace/incident-copilot/restore/`,
shipped 3 Nov 2026, CI green) is the wedge. What it already does, verified
against the code on 15 Nov 2026:

| Capability | Status in Incident Copilot | Recovery Proof |
|---|---|---|
| Restore a Postgres backup into an ephemeral container | **Done.** `restore/check.py`: `postgres:16.4` container, random password + random localhost port, `pg_isready` wait, `pg_restore`/`psql`, `docker rm -f` in a `finally` block. Backup from a file (`.dump` or `.sql`) or `pg_dump -Fc` of a live `--source-url` (password never hits logs). | **Reuse as-is.** Move the package into the new repo, keep the CLI contract. |
| Sanity checks | **Done.** `restore/checks.example.yaml`: per-table minimum row counts + custom SQL queries that must return ≥1 row. | **Extend.** Add DB integrity checks (`pg_checksums`-style / `CHECK` verification), an HTTP health check against a booted app, and a smoke-test query template library. |
| Measured restore time | **Partially done.** `duration_s` is recorded in the result and the event payload, and the Telegram summary shows it. It is **not** aggregated, trended, or published as a measured RTO. | **New.** Append-only results table + per-system measured-RTO history and trend. |
| Result recording | **Done.** POSTs an event (`source="restore"`, `type="restore_check"`) to the Copilot API; the web timeline shows it; the Telegram bot answers `/restore` ("Did last night's backup restore OK?"). | **Reuse the pattern.** Recovery Proof gets its own append-only results table (same shape), and the Copilot timeline remains the viewer for the standalone checker. |
| Telegram alerts | **Done.** Summary sent when `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` are set; a Telegram failure never fails the check. | **Reuse; add Slack** (Phase 3). |
| Exit codes | **Done.** 0 = all checks passed, 1 = restore or a check failed, 2 = infra/usage error. | **Keep.** CI and cron depend on it. |
| MySQL restore tests | **Not present.** Postgres only. | **New in Phase 1** (second connector, after Postgres). |
| S3 backup protection audit | **Not present.** | **New in Phase 2.** |
| Clean-point detection | **Not present.** | **New in Phase 4.** |
| Clean-room recovery | **Not present.** (The ephemeral container is isolated, but there is no scan-then-promote flow.) | **New in Phase 4–5.** |
| Readiness score / report | **Not present.** | **New in Phase 3.** |
| Drills and runbooks | **Not present.** | **New in Phase 5.** |
| K8s / VM / file shares / SaaS | **Not present.** | **Phase 6 (unscoped).** |

**Nothing in Incident Copilot is wasted.** The checker, the checks-file format,
the event shape, the Telegram path, and the timeline all carry over. The new
repo starts as the checker extracted + a MySQL connector, not a rewrite.

## 6. Wedge MVP — Phase 1 restore checker (the only scope that ships first)

**Goal:** answer "do our backups actually work?" for one team, in a few weeks,
with nothing else attached.

### What it does

- A scheduled job restores the latest Postgres **or** MySQL backup into a
  temporary container.
- Runs integrity and smoke-test checks, and records **pass/fail plus the
  measured restore time**.
- Adds a backup protection audit for S3: is object lock on, can the
  production role delete backups?
- Sends results to Telegram or Slack and writes them to the timeline from the
  Incident Copilot dashboard.

### CLI (kept compatible with the Incident Copilot checker)

```
recovery-proof check --backup-file /backups/latest.dump --checks checks.yaml
recovery-proof check --source-url postgresql://user:pw@host/db --checks checks.yaml
recovery-proof check --backup-file /backups/latest.sql --engine mysql --checks checks.yaml
recovery-proof audit-s3 --bucket my-backups --profile backup-reader
recovery-proof report --system orders-db --format md|json
```

Exit codes: 0 = all checks passed, 1 = restore or a check failed,
2 = infra/usage error (same contract as the Incident Copilot checker, so
existing cron and CI keep working).

### Checks file (extends `checks.example.yaml`)

```yaml
# Per-table minimum row counts (existing).
tables:
  users: 1
  orders: 1
# Custom SQL queries, each must return at least one row (existing).
queries:
  - name: "recent orders exist"
    sql: "SELECT 1 FROM orders WHERE created_at > now() - interval '7 days' LIMIT 1"
# NEW: database integrity check (engine-specific; Postgres: pg_checksums / amcheck
# where available; MySQL: CHECK TABLE).
integrity:
  enabled: true
# NEW: application boot + HTTP smoke test. The checker starts the app image
# against the restored DB in the sandbox and hits /health.
app:
  image: myapp:latest
  health_url: http://localhost:8080/health
  timeout_s: 60
```

### S3 protection audit (Phase 2, specced now so Phase 1 doesn't block it)

Read-only checks, run with a dedicated reader credential (never the
production role):

| Check | Pass condition |
|---|---|
| Object Lock enabled on the bucket | `ObjectLockEnabled: Enabled` |
| Default retention (Governance or Compliance mode) | Retention period set and ≥ the configured minimum (default 30 days) |
| Production role cannot delete backups | The production IAM role/user has no `s3:DeleteObject` / `s3:DeleteObjectVersion` on the backup prefix (checked via IAM policy simulation, not by attempting a delete) |
| Separate credentials | The backup writer credential is not the production application credential (different access key / role) |
| Versioning enabled | `Versioning: Enabled` |
| Retention outlasts dwell time | Retention ≥ 35 days (covers the commonly cited ~30-day dwell window; configurable, and the plan does **not** cite a dwell-time statistic — none is traceable to a primary source) |

### Safety contract (non-negotiable, from day one)

- **Read-only access to backups.** The checker never writes to the backup
  store, never modifies the source database, never deletes a backup.
- **Sandbox with no route back to production.** The restore container runs on
  an isolated Docker network; no outbound route to production hosts; the
  restored database is reachable only from the checker process.
- **No credentials in logs or reports.** URLs are redacted the way the
  Incident Copilot checker already redacts them (`user:***@host`).
- **Test data may contain personal information.** The sandbox must be locked
  down and encrypted; results and reports contain check names and counts,
  never row contents. A `--redact` default: no data values ever leave the
  sandbox.
- **Detection claims stay honest.** Heuristics report "no signs found", never
  "guaranteed clean".

### Stack (default — see open decisions)

- **Python 3.12, FastAPI** for the orchestrator/API (same stack as Incident
  Copilot, Kavach, Agent Gateway, Crypto Atlas — one stack across the estate).
- **Docker first** for the sandbox; Kubernetes Jobs later (Phase 6).
- **Postgres** for the append-only results table, reusing the Incident Copilot
  timeline shape (`source`, `type`, `payload`, `created_at`).
- **APScheduler or cron** for scheduling in the MVP; a proper job scheduler
  in the orchestrator at Phase 3.
- **MIT licence**, public repo, CI on Python 3.11 + 3.12 (same as the other
  three security repos).

## 7. Architecture

```
                    ┌─────────────────────────┐
  Backup sources    │  Orchestrator (FastAPI) │
  ─────────────     │  - job scheduler        │
  pg_dump /         │  - checks engine        │
  mysqldump /       │  - protection audit     │
  S3-compatible /   │  - clean-point scorer   │
  restic / Borg     │  - runbook runner       │
  snapshots         └──────┬──────────┬───────┘
                           │          │
              ┌────────────┘          └────────────┐
              ▼                                    ▼
   ┌──────────────────┐                ┌──────────────────┐
   │  Sandbox         │                │  Results store   │
   │  (Docker first,  │                │  Postgres,       │
   │   K8s Jobs later)│                │  append-only     │
   │  - ephemeral DB  │                │  results table   │
   │  - app boot      │                │  (timeline shape)│
   │  - no route back │                └──────┬───────────┘
   │    to production │                       │
   └──────────────────┘                       ▼
                                   ┌──────────────────┐
                                   │  Dashboard +     │
                                   │  alerts          │
                                   │  (timeline,      │
                                   │   readiness       │
                                   │   score, Telegram│
                                   │   + Slack)       │
                                   └──────────────────┘
```

- **Connectors:** S3-compatible storage, restic, `pg_dump`, managed database
  snapshots (read-only).
- **Checks engine:** pluggable checks (SQL assertions, HTTP health checks,
  checksum comparison). A check is a small, named, testable unit with a
  pass/fail and a measured duration.
- **Detection:** simple heuristics first (entropy, change-rate, canary files),
  then models. Heuristics are versioned and their false-positive rate is
  measured on every run, not asserted.
- **Storage:** Postgres with an append-only results table, reusing the
  Incident Copilot timeline.
- **Safety:** read-only access to backups, sandbox with no route back to
  production (§6 safety contract).

## 8. Roadmap

| Phase | Weeks | Deliverable | Exit criteria |
|---|---|---|---|
| **0. Research** | 1–2 | Interview 8–10 people who run backups or have recovered from an attack | 8 interviews done; a written list of the 3 most painful recovery failures and the exact stacks they ran (Postgres/MySQL/K8s/file); the wedge scope confirmed or narrowed by what they said |
| **1. Restore checker** | 3–5 | Postgres and MySQL restore tests with pass/fail and timing | Postgres connector = the Incident Copilot checker extracted + integrity check + measured-RTO history; MySQL connector with the same CLI and checks-file shape; 40+ tests; CI green 3.11+3.12; a demo run against a real dump with a published measured time |
| **2. Protection audit** | 6–7 | S3 immutability and access checks | The six audit checks in §6, all read-only, with a per-bucket pass/fail report; tested against a real S3-compatible bucket (or MinIO locally) |
| **3. Dashboard and alerts** | 8–9 | Timeline, readiness score, Telegram and Slack alerts | Per-system readiness score (0–100, formula documented, every input a measured fact); dashboard page; Slack alert path; a PDF/Markdown report an auditor can read |
| **4. Clean point detection** | 10–13 | Ransomware heuristics across restore points | Heuristics (mass-change rate, high-entropy files, canary changes, known extensions) scored per restore point; "last clean point" recommendation with the evidence listed; false-positive rate measured on clean fixtures; language is "no signs found", never "guaranteed clean" |
| **5. Drills and runbooks** | 14–17 | Scheduled recovery drills and a scorecard | Runbooks as runnable YAML playbooks; scheduled drills with a pass/fail scorecard; a drill report that names the measured recovery time vs the declared RTO |
| **6. Coverage** | 18+ | Kubernetes, VM images, file shares, SaaS data | Unscoped — only start when Phases 1–5 are shipped and at least one real team is using the checker weekly |

**Total to a shippable product (Phases 0–5): 17 weeks.** The wedge MVP
(Phase 1) is 3–5 weeks and already answers "do our backups actually work?"

### Phase 0 interview script (the questions that decide the wedge)

1. When did you last restore a backup for real — not a test — and what broke?
2. What do you back up (Postgres? MySQL? files? VMs? K8s?), and where does
   it live (S3? a NAS? a vendor)?
3. Have you ever found a backup corrupt or incomplete? How did you find out?
4. Could your production credentials delete your backups? Who else could?
5. What is your declared RTO, and has anyone ever measured the real one?
6. If I gave you a weekly report that said "restore PASS, 11 minutes, last
   clean point 3 days ago", what would you do with it — and who else would
   need to see it?

## 9. Business model

- **Open-source core** that does the restore tests (the Phase 1 checker,
  MIT licence, public repo). This is the distribution engine: every team that
  runs it is a potential paid user, and every run is evidence the product
  works.
- **Paid platform:** multi-system dashboard, audit-ready reports, clean-room
  automation, SSO, and support.
- **Pricing:** per protected system or per tested backup job, aimed at small
  and mid-size teams. The incumbents' entry points are the anchor to price
  against: Rubrik ~$50k/yr entry (third-party figure), Veeam ~$155–$227.50/
  workload/yr, Commvault ~$58.50–$90/TB/mo (third-party figures), with the
  recovery features as add-ons or upper tiers. The paid tier must be an order
  of magnitude below the Rubrik entry point to be credible for its target
  buyer — the exact number is a Phase 3 decision, after the first real users
  say what they would pay.
- **Compliance angle (verified — see §10):** DORA, NIS2, and GDPR push
  organisations to prove tested recovery and resilience, which gives buyers
  a reason to pay for evidence. The pitch must state the obligations
  accurately (§10) — the compliance angle is the strongest reason to pay, and
  the easiest place to lose credibility by overclaiming.

## 10. Compliance angle — verified obligations (the honest version)

**The strongest pitch line, accurately stated:** "DORA Art. 11(6) forces
every EU financial entity to test its continuity and recovery plans at least
yearly including cyber-attack switchovers, and Art. 12(3) forces restores
onto segregated systems — but neither DORA, NIS2 nor GDPR prescribes *how* a
restore is proven. Commission Implementing Regulation (EU) 2024/2690 comes
closest, requiring digital providers to regularly test recovery of backups
with documented results. That gap — a vendor-neutral, measurable proof layer
— is the product."

| Instrument | Who | Testing duty | Frequency | RTO | Proof / evidence |
|---|---|---|---|---|---|
| DORA Art. 11(6) | EU financial entities | Test BCP + response/recovery plans, incl. cyber-attack + switchover scenarios | At least yearly + after substantive changes | Set per function (Art. 12(6)); no numeric value | Records (11(8)); CSD test results to authority (11(9)) |
| DORA Art. 12(2) | Same | Test backup + restoration/recovery procedures | "Periodically" | — | — |
| DORA Art. 12(3) | Same | Restore on systems physically + logically segregated from source | On every restore | "Timely restoration" | Segregation itself is the evidence |
| DORA Art. 24–25 | Same (non-micro) | Resilience testing programme on critical/important ICT systems | At least yearly | RTO/RPO per asset in RTS Art. 4 | Programme + corrective measures |
| DORA Art. 26 | Designated entities only | Threat-led penetration testing (TIBER-EU) | At least every 3 years | — | Attestation (Art. 26(7)) |
| NIS2 Art. 21(2)(c) | Essential/important entities, 18 sectors | Business continuity incl. backup management + DR | Not fixed in the directive | Not fixed | Effectiveness assessment (21(2)(f)) |
| CIR 2024/2690 Annex 4.2.6 | Digital providers only (DNS, cloud, DC, MSP, MSSP, etc.) | Regularly test recovery of backups/redundancies; integrity checks (4.2.3); documented backup plans incl. recovery times (4.2.2) | "Regularly" / "planned intervals" | Must be in the backup plan | Documented results, management sign-off (per Annex 4.3) |
| GDPR Art. 32(1)(c)+(d) | All EU personal-data controllers/processors | Restore capability + process for regularly testing effectiveness | "Regularly" | "Timely" | The testing process itself |
| CER Art. 13(1)(d) | Designated critical entities | Recover from incidents, with business continuity measures | Not fixed | — | Risk assessment (Art. 12) |

### What the plan must NOT claim

- **DORA never says "immutable", "air gap", "WORM" or "ransomware."** A
  search of the Official Journal texts of DORA and of Delegated Regulation
  (EU) 2024/1774 confirms none of those words appear. The backup protection
  audit (object lock, separate credentials, no delete rights) is a product
  interpretation of Art. 12(3)'s segregation/protection language —
  defensible, but not a literal statutory checkbox. Say so in the product.
- **DORA sets no numeric RTO and no restore-test frequency beyond
  "periodically" (Art. 12) and "at least yearly" (Art. 11(6)).** A product
  claiming "DORA requires a 4-hour RTO" would be wrong.
- **The NIS2 directive text itself never says "restore test" and never fixes
  a testing frequency.** The concrete, auditable restore-testing duty is
  spelled out only in CIR 2024/2690 for digital providers, and is otherwise
  the accepted implementation / auditor expectation, not a directive-level
  frequency. The honest framing is "the evidence auditors expect for
  Art. 21(2)(c)", not "NIS2 mandates quarterly restore tests". (The
  "quarterly for critical systems, annually for the rest" frequency seen in
  vendor checklists is industry practice, not a statutory number.)
- **Numbering trap:** the 2020 DORA *proposal* numbered response-and-recovery
  as Article 10; the **final** Regulation (EU) 2022/2554 has it as
  **Article 11**. Older write-ups citing "DORA Art. 10" for this are quoting
  the proposal. Cite Art. 11.
- **GDPR is the broadest hook, not NIS2.** Art. 32(1)(c)+(d) applies to
  essentially any company handling EU personal data — far broader than DORA
  or NIS2 — and is the most direct "prove your restore works" obligation in
  EU law. Fines under Art. 83 reach €20m or 4% of worldwide turnover.
- **NIS2 gives the broadest addressable market** (thousands of entities
  across 18 sectors) but the weakest direct hook; **DORA gives the sharpest
  hook** (yearly tested recovery + segregated restore, in force since
  17 Jan 2025) but the narrowest market (financial entities). The go-to-market
  order follows from that: DORA-regulated teams first (they have a dated,
  auditable duty), NIS2/GDPR teams second (they need the evidence, and the
  auditor expectation is the lever).
- **UK FCA/PRA operational resilience (PS21/3, SS1/21) was NOT verified in
  this pass.** Do not cite it until verified; note also that DORA does not
  apply in the UK.
- **CER is a weak hook for a cyber product** — it explicitly excludes
  cybersecurity matters covered by NIS2 and prescribes no testing frequency.

Sources: DORA final text — https://www.digital-operational-resilience-act.com/Article_11.html ,
https://www.digital-operational-resilience-act.com/Article_12.html ;
EUR-Lex — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554 ,
https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1774 ;
NIS2 — https://www.nis2dir.eu/en/what-is-nis2 ;
CIR 2024/2690 Annex — https://www.pelorus.tech/regulations/eu/commission-implementing-regulation-eu-2024-2690.html ;
GDPR Art. 32 — https://gdpr-info.eu/art-32-gdpr/

## 11. Honest risks

1. **Incumbents already sell "recovery."** Position as the independent proof
   layer, not another backup product. The moment the product starts storing
   backups itself, it competes with Veeam and Rubrik on their ground and
   loses. Stay vendor-neutral: read backups, never own them.
2. **Restores can be expensive and sensitive.** Test data may contain personal
   information, so the sandbox must be locked down and encrypted (§6 safety
   contract). A restore test that leaks data is worse than no test. The
   sandbox is the product's trust boundary — treat it like one.
3. **Application checks are customer-specific.** Provide good templates and
   make custom checks easy, or false confidence will creep in. A green check
   that doesn't actually test the thing that matters is the worst outcome:
   it certifies a broken recovery.
4. **Detection claims need care.** Heuristics will miss some attacks, so
   describe results as "no signs found", never "guaranteed clean". The
   clean-point recommendation must always list its evidence, so a human can
   disagree with it.
5. **Value is invisible until disaster strikes.** Use readiness scores,
   reports, and audit requirements to make it visible every month. If the
   only output is a green tick in a dashboard nobody opens, the product dies
   quietly. The monthly report and the audit-ready evidence pack are the
   retention mechanism, not the checker.
6. **Least novel of the five ideas.** The winning move is the narrow wedge —
   "restore proof for Postgres and Kubernetes teams" — then expanding. A
   broad launch ("recovery for everything") invites comparison with
   Commvault and loses; a narrow wedge invites comparison with a shell
   script and wins.
7. **The compliance angle cuts both ways.** If the product overclaims a
   regulation ("DORA requires immutable backups"), the first auditor who
   checks will kill the sale and the reputation. §10's limits are part of the
   product, not a footnote.

## 12. Open decisions (Samir's call)

1. **Name.** "Recovery Proof" is the working name. Alternatives: keep it, or
   pick a shorter one-word name in the Kavach / Crypto Atlas style. The repo
   name follows the name.
2. **Postgres-only wedge or Postgres + MySQL from day one?** Default in this
   plan: **Postgres first (weeks 1–2 of Phase 1, reusing the Incident
   Copilot checker), MySQL second (weeks 3–5)** — both inside Phase 1, so
   the MVP still covers both, but Postgres ships first and the MySQL scope
   can be cut if it slips. Veto: Postgres-only Phase 1, MySQL in Phase 2.
3. **Phase 0 interviews vs build-first?** Default: **interviews first** —
   8–10 conversations in 1–2 weeks, because the wedge (which stacks, which
   buyers) is the one thing the plan cannot verify from documents. Veto:
   skip to Phase 1 and interview in parallel; the risk is building the wrong
   second connector.
4. **Repo creation.** New public repo (proposed:
   `github.com/Samir-Khadka/recovery-proof`) at Phase 1, or keep the checker
   inside Incident Copilot until Phase 2 proves the split is worth it?
   Default: **new repo at Phase 1** — the product has its own identity, and
   Incident Copilot stays the incident timeline, not a recovery product.
5. **Language.** Default: **Python (FastAPI)** — same stack as Incident
   Copilot, Kavach, Agent Gateway, Crypto Atlas; the checker is already
   Python. The pitch mentions Go as an alternative; Go buys a single binary
   and lower runtime cost, at the price of a second stack and rewriting the
   checker. Default Python unless there is a reason to switch.
6. **Who is the first real user?** The plan assumes Samir's own stack first
   (Kishan-Bazzar's Postgres, the messaging API, Suraksha) as the dogfood
   target, then 2–3 friendly teams from Phase 0. Confirm or name others.

## 13. How it fits with the other ideas

- **Smallest and fastest to start** of the five; builds directly on Incident
  Copilot, and the audit and timeline pieces overlap with Agent Gateway
  (the audit log and the policy/approval shape), while the "prove it works"
  reports overlap with the Crypto Atlas idea (evidence, not claims).
- **CYBERSURE evidence:** recovery testing and resilience are a natural
  complement to the cryptography track — a tested-restore report is the same
  kind of evidence as a crypto inventory, and the DORA/NIS2 verification in
  §10 is directly usable in a motivation letter about building security
  tooling that organisations can actually prove.
- **Dogfood path:** Kishan-Bazzar (Flask + SQLite — needs a Postgres story
  first), Suraksha (FastAPI + Postgres), and the messaging API are the first
  systems to get a readiness score. Their live demos are suspended on Render
  until 1 Dec, so the first real restore tests run locally, not against the
  suspended services.
- **Trade-off, stated plainly:** it is the least novel of the five. The
  defence is the wedge, not the vision — "restore proof for Postgres and
  Kubernetes teams" is a product; "ransomware-proof recovery" is a pitch.

## 14. Verification log

- **15 Nov 2026:** competitor features verified against the vendors' own
  pages (Veeam SureBackup, Rubrik Data Threat Analytics, Cohesity
  DataProtect/DataHawk, Commvault Cleanroom/Threat Scan/Synthetic Recovery,
  Druva Recovery Intelligence, Acronis automated verification; restic/Borg/
  Kopia check commands).
- **15 Nov 2026:** DORA (Regulation (EU) 2022/2554, Arts. 11, 12, 19, 24–27)
  and NIS2 (Directive (EU) 2022/2555, Arts. 20, 21, 23, 34) verified against
  EUR-Lex and the final-text reproductions; CIR (EU) 2024/2690 Annex 4.2.2/
  4.2.3/4.2.6 and GDPR Art. 32 verified; the "DORA never says immutable /
  air gap / WORM / ransomware" limit confirmed by text search; the Art. 10
  vs Art. 11 numbering trap documented.
- **15 Nov 2026:** ransomware statistics verified against the original
  reports (Veeam Data Trust & Resilience Report 2026; Veeam Ransomware
  Trends Report 2025 PDF; Sophos "The Impact of Compromised Backups" 2024;
  Sophos State of Ransomware 2025 PDF; Coveware Q4 2024). Unverifiable
  figures (Avast "60%/50%", Kaseya "31%/33%", DATA REVERSE "72%",
  Coveware "24 days", Triskele "~33 days", Sophos 2026 "$1.7M") are listed
  in §1 as do-not-cite.
- **15 Nov 2026:** Incident Copilot restore checker read directly from
  `~/workspace/incident-copilot/restore/check.py` and `checks.example.yaml`
  — the reuse map in §5 is grounded in the code, not the README.
- **Not yet verified:** UK FCA/PRA operational resilience (PS21/3, SS1/21);
  the exact paid-tier price; any Phase 0 interviewee. All three are flagged
  where they would be cited.
