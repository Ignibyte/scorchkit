# Project Management & Finding Triage

ScorchKit includes a persistent vulnerability management system backed by PostgreSQL. Projects group targets, scans, and findings together, enabling deduplication across scans, lifecycle triage, posture metrics, module intelligence, and scheduled recurring scans.

This guide covers every aspect of the system from initial setup through advanced workflows.

---

## Table of Contents

1. [Setup](#setup)
2. [Project Lifecycle](#project-lifecycle)
3. [Running Scans with Persistence](#running-scans-with-persistence)
4. [Finding Deduplication](#finding-deduplication)
5. [Finding Triage Workflow](#finding-triage-workflow)
6. [Triage Rationale with --note](#triage-rationale-with---note)
7. [Posture Metrics](#posture-metrics)
8. [Module Intelligence](#module-intelligence)
9. [Scan Scheduling](#scan-scheduling)
10. [Re-scanning and Verifying Fixes](#re-scanning-and-verifying-fixes)

---

## Setup

### Feature Flag

The project management system requires the `storage` Cargo feature. It is not compiled into the default CLI-only build.

```bash
# Build with storage support
cargo build --features storage

# Build with storage + MCP server support (MCP implies storage)
cargo build --features mcp
```

Running any project/finding/schedule command without the `storage` feature produces an error:

```
--project requires the 'storage' feature. Rebuild with: cargo build --features storage
```

### Database Requirements

ScorchKit requires PostgreSQL. Create a database and configure the connection URL using any of these methods (listed by precedence, highest first):

1. **CLI flag**: `--database-url postgresql://user:pass@localhost/scorchkit`
2. **Config file** (`config.toml`):
   ```toml
   [database]
   url = "postgresql://user:pass@localhost/scorchkit"
   max_connections = 5
   migrate_on_startup = true
   ```
3. **Environment variable**: `DATABASE_URL=postgresql://user:pass@localhost/scorchkit`

### Running Migrations

Migrations create the required tables (`projects`, `project_targets`, `scan_records`, `tracked_findings`, `scan_schedules`). They are idempotent and skip already-applied migrations.

```bash
# Explicit migration
scorchkit db migrate

# Automatic on startup (default behavior when migrate_on_startup = true)
# Migrations run automatically when any storage command connects
```

---

## Project Lifecycle

A project is a named scope that groups targets, scan records, and tracked findings. Projects are referenced by name or UUID throughout the CLI.

### Create a Project

```bash
scorchkit project create myapp
scorchkit project create myapp --description "Production web application pentest"
```

Output:
```
success: Project created.
      ID: a1b2c3d4-...
    Name: myapp
    Desc: Production web application pentest
```

### List All Projects

```bash
scorchkit project list
```

Output:
```
Projects

  myapp a1b2c3d4-... (3 scans, 12 findings)
    Production web application pentest
  staging e5f6a7b8-... (1 scan, 4 findings)
```

### Show Project Details

```bash
scorchkit project show myapp
```

Output includes ID, name, description, creation/update timestamps, target count, scan count, finding count, target list, and the last 5 scans.

### Delete a Project

Deletion removes the project and all associated data (targets, scans, findings). It requires confirmation:

```bash
# Preview (no deletion)
scorchkit project delete myapp

# Confirm deletion
scorchkit project delete myapp --force
```

### Manage Targets

Targets are URLs associated with a project. They serve as a registry of in-scope assets.

```bash
# Add a target
scorchkit project target add myapp https://app.example.com
scorchkit project target add myapp https://api.example.com --label "REST API"

# List targets
scorchkit project target list myapp

# Remove a target (by UUID)
scorchkit project target remove myapp a1b2c3d4-e5f6-...
```

Projects can also be created inline during `scorchkit init`:

```bash
scorchkit init https://app.example.com --project myapp
```

---

## Running Scans with Persistence

The `--project` flag on the `run` command associates scan results with a project. When specified, ScorchKit:

1. Connects to PostgreSQL
2. Resolves the project by name (or UUID)
3. Runs the scan normally
4. Creates a `ScanRecord` with profile, modules run/skipped, start/end timestamps, and a JSON summary
5. Saves all findings with fingerprint-based deduplication (new findings are inserted; existing findings have their `seen_count` incremented and `last_seen` updated)
6. Updates module intelligence statistics in the project's settings

```bash
# Basic persistent scan
scorchkit run https://app.example.com --project myapp

# With profile and proxy
scorchkit run https://app.example.com --project myapp --profile thorough --proxy http://127.0.0.1:8080

# With database URL override
scorchkit run https://app.example.com --project myapp --database-url postgresql://localhost/scorchkit

# AI-guided scan with persistence
scorchkit run https://app.example.com --project myapp --plan --analyze
```

After the scan completes, the persistence summary is printed:

```
DB Saved to project 'myapp': 5 new findings, 3 updated
```

The `agent` command also supports `--project` for autonomous scans:

```bash
scorchkit agent https://app.example.com --project myapp --depth thorough
```

The `analyze` command supports `--project` to enrich AI analysis with project history:

```bash
scorchkit analyze report.json --project myapp --focus remediate
```

---

## Finding Deduplication

Findings are deduplicated using a **fingerprint** -- a SHA-256 hash of three fields:

```
fingerprint = SHA-256(module_id | title | affected_target)
```

The pipe character (`|`) is used as a separator between fields in the hash input.

### What Is Included

| Field | Purpose |
|-------|---------|
| `module_id` | Which scanner module produced the finding (e.g., `xss`, `ssl`, `csrf`) |
| `title` | The finding title (e.g., "Reflected XSS", "Missing HSTS Header") |
| `affected_target` | The specific URL, parameter, or resource affected |

### What Is Excluded

Evidence, description, timestamps, severity, and confidence are deliberately **excluded** from the fingerprint. This means the same vulnerability detected in different scans -- potentially with different evidence payloads or at different times -- maps to the same tracked finding.

### Deduplication Behavior

When `save_findings` processes a batch of findings from a scan:

- **If the fingerprint already exists** for this project: the existing row's `last_seen` is set to now, `seen_count` is incremented by 1, `scan_id` is updated to the current scan, and evidence/confidence are refreshed with the latest values.
- **If the fingerprint is new**: a new `TrackedFinding` row is inserted with `seen_count = 1` and status `new`.

This means a finding detected across 10 scans appears once in the database with `seen_count = 10`, not as 10 separate rows.

### Practical Implications

- The same XSS on `/login` and `/register` produces **two** findings (different `affected_target`).
- The same XSS on `/login` found in Monday's scan and Friday's scan produces **one** finding with `seen_count = 2`.
- Changing the evidence payload (e.g., a different proof-of-concept string) does **not** create a new finding.

---

## Finding Triage Workflow

Every tracked finding has a lifecycle status. There are **7 statuses** representing the full vulnerability management lifecycle:

| Status | Description | Category |
|--------|-------------|----------|
| `new` | Newly detected, not yet reviewed | Active |
| `acknowledged` | Reviewed and confirmed as a real issue | Active |
| `false_positive` | Determined to be a false positive after investigation | Resolved |
| `wont_fix` | Known issue, deliberately not fixing (with rationale) | -- |
| `accepted_risk` | Real issue but mitigated by other controls | -- |
| `remediated` | A fix has been applied | Resolved |
| `verified` | Fix confirmed by a subsequent scan | Resolved |

### Listing Findings

```bash
# All findings for a project
scorchkit finding list myapp

# Filter by severity
scorchkit finding list myapp --severity critical
scorchkit finding list myapp --severity high

# Filter by status
scorchkit finding list myapp --status new
scorchkit finding list myapp --status remediated
```

Output:
```
Findings for 'myapp' (12 total)

  a1b2c3d4-... CRITICAL Reflected XSS [new] (seen 3x)
    https://app.example.com/search?q=
  e5f6a7b8-... HIGH Missing HSTS Header [acknowledged] (seen 5x)
    https://app.example.com
  ...
```

### Viewing Finding Details

```bash
scorchkit finding show a1b2c3d4-e5f6-7890-abcd-1234567890ab
```

Output:
```
Finding Details

          ID: a1b2c3d4-...
       Title: Reflected XSS
    Severity: CRITICAL
      Status: new
      Module: xss
      Target: https://app.example.com/search?q=
  First seen: 2026-03-15 14:30 UTC
   Last seen: 2026-04-01 09:15 UTC
  Seen count: 3

  Description
  User input in the 'q' parameter is reflected without encoding...

  Evidence
  <script>alert(1)</script> reflected in response body

  Remediation
  Encode all user input before rendering in HTML context...

  OWASP: A03:2021
     CWE: CWE-79
```

### Updating Finding Status

```bash
# Acknowledge a finding
scorchkit finding status a1b2c3d4-... acknowledged

# Mark as false positive
scorchkit finding status a1b2c3d4-... false_positive --note "Scanner triggered on CSRF token, not actual XSS"

# Accept the risk
scorchkit finding status a1b2c3d4-... accepted_risk --note "Behind WAF with XSS rules, internal-only app"

# Won't fix
scorchkit finding status a1b2c3d4-... wont_fix --note "Legacy system scheduled for decommission in Q3"

# Mark as remediated
scorchkit finding status a1b2c3d4-... remediated --note "Output encoding added in commit abc123"

# Verified by re-scan
scorchkit finding status a1b2c3d4-... verified --note "Confirmed fixed in scan 2026-04-02"
```

Output:
```
success: Finding status updated to 'remediated'.
  Note: Output encoding added in commit abc123
```

### Typical Triage Flow

```
new  -->  acknowledged  -->  remediated  -->  verified
  \                           ^
   \--> false_positive       /
    \--> wont_fix           /
     \--> accepted_risk ---/
```

1. A scan detects a finding. It enters as `new`.
2. A human reviews it and transitions to `acknowledged`, `false_positive`, `wont_fix`, or `accepted_risk`.
3. Once a fix is applied, set it to `remediated`.
4. After re-scanning confirms the issue is gone, set it to `verified`.

---

## Triage Rationale with --note

The `--note` flag on `finding status` records the rationale for a status change. This is critical for audit trails and team communication.

```bash
# Document why it's a false positive
scorchkit finding status <id> false_positive \
  --note "The scanner flagged the anti-CSRF token as reflected XSS. Manual verification confirms no injection point."

# Document risk acceptance
scorchkit finding status <id> accepted_risk \
  --note "TLS 1.0 required for legacy POS terminal integration. Compensating control: network segmentation + VPN-only access."

# Document the fix
scorchkit finding status <id> remediated \
  --note "Patched in v2.4.1, PR #847. Added Content-Security-Policy header with strict-dynamic."
```

The note is stored in the `status_note` field and displayed in `finding show` output under "Status Note".

Without `--note`, the status is updated but the rationale field is set to null. While optional, notes are strongly recommended for `false_positive`, `wont_fix`, and `accepted_risk` transitions to maintain a clear decision record.

---

## Posture Metrics

The `project status` command computes a security posture dashboard from aggregate SQL queries. No additional tables are required -- all metrics are derived from `scan_records` and `tracked_findings`.

```bash
scorchkit project status myapp
```

Output:
```
Security Posture  myapp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scan History
    Total scans:   12
    Last 30 days:  4
    Latest scan:   2026-04-01 09:15

  Finding Summary
    Total:    24
    Active:   8
    Resolved: 16

  By Severity
    critical     2
    high         5
    medium       9
    low          6
    info         2

  By Status
    new              3
    acknowledged     5
    remediated       8
    verified         6
    false_positive   2

  Trend
    Direction: Improving
    MTTR:      n/a (requires status change tracking)

  Regressions (1)
    high Missing X-Frame-Options [clickjacking] was remediated

  Top Unresolved
    critical SQL Injection in login (new, seen 2x, since 2026-03-15 14:30)
    high Open Redirect (acknowledged, seen 4x, since 2026-02-20 10:00)
    ...
```

### Metrics Breakdown

| Section | Source | Description |
|---------|--------|-------------|
| **Scan History** | `scan_records` | Total scans, scans in the last 30 days, latest scan date |
| **Finding Summary** | `tracked_findings` | Total, active (new + acknowledged), resolved (remediated + verified + false_positive) |
| **By Severity** | `tracked_findings` | Count grouped by severity, ordered critical to info |
| **By Status** | `tracked_findings` | Count grouped by lifecycle status |
| **Trend** | Computed | `Improving` if resolved > active, `Declining` if active > 0 and resolved = 0, `Stable` otherwise |
| **Regressions** | `tracked_findings` + `scan_records` | Findings with status `remediated` or `verified` that were re-detected in the latest scan |
| **Top Unresolved** | `tracked_findings` | Up to 10 active findings sorted by severity priority, then by most recently seen |

---

## Module Intelligence

Module intelligence tracks per-module effectiveness statistics across scans. Data accumulates in the project's `settings` JSONB field -- no additional tables or migrations are required.

```bash
scorchkit project intelligence myapp
```

Output:
```
Module Intelligence  myapp
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Target Profile
    Server:  nginx/1.24
    CMS:     WordPress
    Tech:    PHP, jQuery
    WAF:     Cloudflare

  Total scans: 8
  Last updated: 2026-04-01T09:15:00Z

  Module               Runs Findings    C    H    M    L    I  Score
  ──────────────────────────────────────────────────────────
  xss                     8       12    2    5    3    2    0    1.5
  headers                 8        9    0    0    4    3    2    1.1
  ssl                     8        4    0    1    2    1    0    0.5
  csrf                    8        3    0    2    1    0    0    0.4
  cors                    8        1    0    0    1    0    0    0.1
  injection               8        0    0    0    0    0    0    0.0
  ...
```

### Statistics Tracked

For each module that has been executed in a project scan:

| Metric | Description |
|--------|-------------|
| `total_runs` | Number of scans this module participated in |
| `total_findings` | Total findings produced across all runs |
| `critical` / `high` / `medium` / `low` / `info` | Cumulative finding counts by severity |
| `effectiveness_score` | `total_findings / total_runs` -- higher means more productive |

Intelligence is updated automatically at the end of every scan run with `--project`. It is also used by the AI planner (`--plan`) to make data-driven decisions about which modules to run.

### Target Profile

If populated (via `scorchkit init --project` or recon modules), the target profile records:

- **Server**: Web server software and version
- **Technologies**: Detected frameworks and libraries
- **CMS**: Content management system
- **WAF**: Web application firewall

---

## Scan Scheduling

Scan schedules automate recurring scans using cron expressions. Schedules are tied to a project and execute via the `schedule run-due` command (or the `run-due-scans` MCP tool).

### Create a Schedule

```bash
# Daily at midnight
scorchkit schedule create myapp https://app.example.com "0 0 * * *"

# Weekly on Sunday at 2 AM with thorough profile
scorchkit schedule create myapp https://app.example.com "0 2 * * 0" --profile thorough

# Every 6 hours with quick profile
scorchkit schedule create myapp https://app.example.com "0 */6 * * *" --profile quick
```

Output:
```
success: Schedule created.
        ID: f1e2d3c4-...
   Project: myapp
    Target: https://app.example.com
      Cron: 0 0 * * *
   Profile: standard
  Next run: 2026-04-05 00:00 UTC
```

### List Schedules

```bash
scorchkit schedule list myapp
```

Output:
```
Schedules for 'myapp'

  f1e2d3c4-... [enabled] 0 0 * * * -> https://app.example.com (standard)
    Next: 2026-04-05 00:00 UTC  Last: 2026-04-04 00:00 UTC
  a5b6c7d8-... [disabled] 0 */6 * * * -> https://api.example.com (quick)
    Next: 2026-04-04 12:00 UTC  Last: never
```

### Show Schedule Details

```bash
scorchkit schedule show f1e2d3c4-...
```

### Enable / Disable a Schedule

```bash
scorchkit schedule enable f1e2d3c4-...
scorchkit schedule disable f1e2d3c4-...
```

Disabled schedules are skipped by `run-due`.

### Delete a Schedule

```bash
scorchkit schedule delete f1e2d3c4-...
```

### Execute Due Schedules

The `run-due` command finds all enabled schedules whose `next_run` is in the past and executes them sequentially. Each scan's results are persisted to the project with full deduplication.

```bash
scorchkit schedule run-due
```

Output:
```
Running 2 schedules due

  SCAN 0 0 * * * -> https://app.example.com
    OK 14 findings (2 new)
  SCAN 0 2 * * 0 -> https://api.example.com
    OK 6 findings (0 new)
```

Individual scan failures are logged and skipped -- they do not abort the remaining schedules.

This command is designed to be called from an external scheduler (system cron, systemd timer, or CI pipeline):

```bash
# System crontab entry (runs every hour, executes any due ScorchKit schedules)
0 * * * * cd /path/to/project && scorchkit schedule run-due
```

---

## Re-scanning and Verifying Fixes

The deduplication system enables a natural fix-verification workflow.

### The Re-scan Cycle

1. **Initial scan** detects a vulnerability. A `TrackedFinding` is created with `seen_count = 1` and status `new`.

2. **Triage**: You review the finding and set it to `acknowledged`:
   ```bash
   scorchkit finding status <id> acknowledged --note "Confirmed XSS in search parameter"
   ```

3. **Apply a fix** and mark it `remediated`:
   ```bash
   scorchkit finding status <id> remediated --note "Input sanitization added in PR #123"
   ```

4. **Re-scan** the target:
   ```bash
   scorchkit run https://app.example.com --project myapp
   ```

5. **If the vulnerability is still present**: The deduplication system matches the fingerprint, increments `seen_count`, and updates `last_seen`. The finding's status remains `remediated` but it now appears in the **Regressions** section of `project status` -- flagging that a "fixed" issue was detected again.

6. **If the vulnerability is gone**: The finding is not detected, so `seen_count` and `last_seen` remain unchanged. You can verify the fix:
   ```bash
   scorchkit finding status <id> verified --note "Confirmed fixed in scan 2026-04-02"
   ```

### Interpreting seen_count

| Scenario | seen_count | Interpretation |
|----------|------------|----------------|
| First detection | 1 | Brand new finding |
| Seen across 5 scans | 5 | Persistent issue, not yet addressed |
| Was 5, now 6 after remediation | 6 | **Regression** -- fix did not work or was reverted |
| Stays at 5 after re-scan | 5 | Fix is working (finding not re-detected) |

### Regression Detection

The posture metrics system (`project status`) automatically identifies regressions: findings with status `remediated` or `verified` whose `scan_id` matches the project's latest scan. This means the deduplication system updated them during the most recent scan -- the vulnerability came back.

```
Regressions (1)
  high Missing X-Frame-Options [clickjacking] was remediated
```

When you see a regression, investigate whether the fix was reverted, bypassed, or incomplete, then update the status accordingly.

### Complete Workflow Example

```bash
# 1. Create the project and run the first scan
scorchkit project create webapp --description "Main web application"
scorchkit project target add webapp https://app.example.com
scorchkit run https://app.example.com --project webapp

# 2. Review findings
scorchkit finding list webapp --severity critical
scorchkit finding show <finding-id>

# 3. Triage each finding
scorchkit finding status <id-1> acknowledged --note "Confirmed, high priority"
scorchkit finding status <id-2> false_positive --note "CSRF token, not XSS"
scorchkit finding status <id-3> accepted_risk --note "Internal tool, IP-restricted"

# 4. Fix the acknowledged issue, then mark it
scorchkit finding status <id-1> remediated --note "Fixed in v2.1.0"

# 5. Re-scan to verify
scorchkit run https://app.example.com --project webapp

# 6. Check posture and regressions
scorchkit project status webapp

# 7. If the fix held, mark verified
scorchkit finding status <id-1> verified --note "Not detected in scan 2026-04-02"

# 8. Set up ongoing monitoring
scorchkit schedule create webapp https://app.example.com "0 0 * * 1" --profile standard
```
