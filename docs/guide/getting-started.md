# Getting Started with ScorchKit

ScorchKit is a web application security testing toolkit and orchestrator written
in Rust. It ships 31 built-in scanner modules and 32 external tool wrappers,
supports AI-powered analysis via Claude, and outputs findings in five formats.

This guide covers installation, first scan, every CLI command and flag,
configuration, and output formats.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
  - [run](#run)
  - [recon](#recon)
  - [scan](#scan)
  - [analyze](#analyze)
  - [diff](#diff)
  - [modules](#modules)
  - [doctor](#doctor)
  - [init](#init)
  - [agent](#agent)
  - [completions](#completions)
  - [Storage Commands](#storage-commands-requires---features-storage)
  - [serve](#serve-requires---features-mcp)
- [Global Flags](#global-flags)
- [Configuration](#configuration)
- [Output Formats](#output-formats)

---

## Installation

ScorchKit requires a Rust toolchain (1.75+). Clone the repository and build:

```bash
# Standard debug build
cargo build

# Optimized release build (recommended for real scans)
cargo build --release

# Build with persistent storage support (PostgreSQL)
cargo build --features storage

# Build with MCP server support (includes storage)
cargo build --features mcp
```

The `storage` feature adds database-backed project management, finding tracking,
scan scheduling, and trend analysis. It depends on PostgreSQL via sqlx.

The `mcp` feature adds `storage` plus a Model Context Protocol server for
AI agent integration.

After building, the binary is at `target/release/scorchkit` (or
`target/debug/scorchkit` for debug builds).

### External Tools (Optional)

ScorchKit's 32 tool wrapper modules call external binaries (nmap, nuclei,
sqlmap, etc.). These are optional -- built-in modules work without them. Run
the doctor command to check what is installed:

```bash
scorchkit doctor
scorchkit doctor --deep    # version checks and health validation
```

See [docs/tools-checklist.md](../tools-checklist.md) for the full installation
guide.

---

## Quick Start

### First Scan

Run a standard scan against a target:

```bash
scorchkit run https://example.com
```

This runs all built-in modules using the `standard` profile. Output appears in
the terminal with color-coded severity levels (Critical, High, Medium, Low,
Info).

### Quick Scan

For a fast check using only four modules (headers, tech, ssl, misconfig):

```bash
scorchkit run https://example.com --profile quick
```

### Save Output as JSON

```bash
scorchkit run https://example.com -o json
```

Reports are written to the `./reports/` directory by default.

### Scan with AI Analysis

Add `--analyze` to get a Claude-powered executive summary after the scan:

```bash
scorchkit run https://example.com --analyze
```

### Scan Through a Proxy (Burp Suite)

```bash
scorchkit run https://example.com --proxy http://127.0.0.1:8080
```

---

## CLI Commands

### run

Run all default scan modules against a target. This is the primary command.

```
scorchkit run <TARGET> [OPTIONS]
```

**Target specification (one required):**

| Argument | Description |
|----------|-------------|
| `<TARGET>` | Target URL, domain, or IP address |
| `--targets-file <PATH>` | File with one target per line (replaces positional target) |
| `--resume <PATH>` | Resume an interrupted scan from a checkpoint file |

**Module selection:**

| Flag | Description |
|------|-------------|
| `-m, --modules <LIST>` | Comma-separated list of specific modules to run |
| `--skip <LIST>` | Comma-separated list of modules to skip |
| `--profile <NAME>` | Scan profile: `quick`, `standard`, `thorough` (default: `standard`) |

**AI features:**

| Flag | Description |
|------|-------------|
| `--analyze` | Run Claude AI analysis after scan completes |
| `--plan` | Use AI-guided scan planning (recon first, then Claude decides which modules to run) |

**Network and scope:**

| Flag | Description |
|------|-------------|
| `--proxy <URL>` | HTTP proxy URL (e.g., `http://127.0.0.1:8080` for Burp Suite) |
| `-k, --insecure` | Skip TLS certificate verification (for self-signed certs, local dev) |
| `--scope <PATTERN>` | Restrict scope to URLs matching pattern (e.g., `*.example.com`) |
| `--exclude <PATTERN>` | Exclude URLs matching pattern from scanning |

**Filtering and storage:**

| Flag | Description |
|------|-------------|
| `--min-confidence <FLOAT>` | Minimum confidence threshold (0.0-1.0) -- hide findings below this level |
| `--project <NAME>` | Associate scan with a project and persist results to the database |
| `--database-url <URL>` | Database URL override (takes precedence over config and `DATABASE_URL` env) |

**Examples:**

```bash
# Standard scan
scorchkit run https://target.com

# Quick scan, only four fast modules
scorchkit run https://target.com --profile quick

# Thorough scan through Burp proxy
scorchkit run https://target.com --profile thorough --proxy http://127.0.0.1:8080

# Run only specific modules
scorchkit run https://target.com -m headers,ssl,csrf,xss

# Skip slow modules
scorchkit run https://target.com --skip nuclei,sqlmap,nmap

# AI-planned scan: recon first, Claude picks modules
scorchkit run https://target.com --plan

# Scan + AI analysis of results
scorchkit run https://target.com --analyze

# Self-signed cert in local dev
scorchkit run https://localhost:8443 -k

# Hide low-confidence findings
scorchkit run https://target.com --min-confidence 0.7

# Scan multiple targets from a file
scorchkit run --targets-file targets.txt

# Persist results to a project
scorchkit run https://target.com --project "client-audit-2026"

# Resume an interrupted scan
scorchkit run --resume ./reports/checkpoint-abc123.json

# Restrict scope to a subdomain
scorchkit run https://example.com --scope "*.api.example.com"

# Exclude logout and admin paths
scorchkit run https://target.com --exclude "/logout|/admin"

# JSON output, quiet mode (findings only)
scorchkit run https://target.com -o json -q
```

---

### recon

Run only reconnaissance modules. Useful for information gathering before a
full scan.

```
scorchkit recon <TARGET> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-m, --modules <LIST>` | Comma-separated list of specific recon modules to run |

Recon modules include: headers, tech, discovery, subdomain, crawler, waf, dns,
js-analysis, cname-takeover, vhost-discovery, cloud-s3.

**Examples:**

```bash
# Run all recon modules
scorchkit recon https://target.com

# Run only header and tech detection
scorchkit recon https://target.com -m headers,tech
```

---

### scan

Run only vulnerability scanner modules. Useful when recon is already done and
you want to focus on finding vulnerabilities.

```
scorchkit scan <TARGET> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-m, --modules <LIST>` | Comma-separated list of specific scanner modules to run |

Scanner modules include: ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe,
idor, jwt, redirect, sensitive, api-schema, ratelimit, cors, csp, auth, upload,
websocket, graphql, subtakeover, acl, api, waf, smuggling, prototype-pollution,
mass-assignment, clickjacking, dom-xss.

**Examples:**

```bash
# Run all scanner modules
scorchkit scan https://target.com

# Run only injection-related scanners
scorchkit scan https://target.com -m injection,cmdi,xss,ssrf,xxe
```

---

### analyze

Run AI analysis on a previous scan report. Requires the Claude CLI to be
installed and configured.

```
scorchkit analyze <REPORT> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-f, --focus <MODE>` | Analysis focus (default: `summary`) |
| `--project <NAME>` | Enrich analysis with project history context (requires storage feature) |
| `--database-url <URL>` | Database URL override for project context |

**Focus modes:**

| Mode | Aliases | Description |
|------|---------|-------------|
| `summary` | *(default)* | Executive summary with business impact and risk score |
| `prioritize` | `priority`, `prio` | Rank findings by exploitability and attack chain potential |
| `remediate` | `remediation`, `fix` | Actionable fix instructions for each finding |
| `filter` | `false-positives`, `fp` | Identify likely false positives and validate real findings |

**Examples:**

```bash
# Executive summary of a scan report
scorchkit analyze reports/scan-2026-04-04.json

# Get prioritized findings
scorchkit analyze reports/scan-2026-04-04.json -f prioritize

# Remediation guide
scorchkit analyze reports/scan-2026-04-04.json -f remediate

# False positive filtering
scorchkit analyze reports/scan-2026-04-04.json -f filter

# Enrich with project history for better context
scorchkit analyze reports/scan-2026-04-04.json --project "client-audit-2026"
```

---

### diff

Compare two scan reports to see what changed between scans. Useful for tracking
remediation progress or detecting regressions.

```
scorchkit diff <BASELINE> <CURRENT>
```

| Argument | Description |
|----------|-------------|
| `<BASELINE>` | Path to the baseline (older) scan report (JSON) |
| `<CURRENT>` | Path to the current (newer) scan report (JSON) |

**Examples:**

```bash
# Compare baseline to current scan
scorchkit diff reports/baseline.json reports/current.json

# Track remediation progress
scorchkit diff reports/pre-fix.json reports/post-fix.json
```

The diff output shows new findings, resolved findings, and findings that
persist between scans.

---

### modules

List all available modules and their status.

```
scorchkit modules [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--check-tools` | Check which external tools are installed on the system |

**Examples:**

```bash
# List all 63 modules
scorchkit modules

# Check tool availability
scorchkit modules --check-tools
```

---

### doctor

Check external tool installation status. A lightweight way to verify your
environment is set up correctly.

```
scorchkit doctor [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--deep` | Run deep validation: version checks, template freshness, health checks |

**Examples:**

```bash
# Quick tool check
scorchkit doctor

# Full health check with version validation
scorchkit doctor --deep
```

---

### init

Generate a configuration file. When given a target, probes the target to
fingerprint it and generates a tailored configuration.

```
scorchkit init [TARGET] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--project <NAME>` | Create a named project and add the target (requires storage feature) |
| `--database-url <URL>` | Database URL override for project creation |

Without a target, `init` writes a default `config.toml`. With a target, it
probes the URL, fingerprints the technology stack, recommends a scan profile,
and writes a tailored `scorchkit.toml`.

**Examples:**

```bash
# Generate default config.toml
scorchkit init

# Probe target and generate tailored scorchkit.toml
scorchkit init https://target.com

# Probe target and create a project in the database
scorchkit init https://target.com --project "client-audit" --database-url postgresql://localhost/scorchkit
```

---

### agent

Run an autonomous scan agent that drives the full
recon, plan, scan, analyze, report loop. Each phase is independent -- AI
failures fall back to profile-based scanning, and analysis failures are
non-fatal.

```
scorchkit agent <TARGET> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--depth <LEVEL>` | Scan depth: `quick`, `standard`, `thorough` (default: `standard`) |
| `--project <NAME>` | Associate with a project for persistence and intelligence tracking |
| `--database-url <URL>` | Database URL override for project persistence |

The agent runs six phases:
1. Target parsing and validation
2. Reconnaissance
3. AI-guided scan planning (falls back to profile if AI is unavailable)
4. Vulnerability scanning
5. AI analysis
6. Report generation

**Examples:**

```bash
# Standard autonomous scan
scorchkit agent https://target.com

# Quick autonomous scan
scorchkit agent https://target.com --depth quick

# Thorough scan with project tracking
scorchkit agent https://target.com --depth thorough --project "pentest-q2"
```

---

### completions

Generate shell completion scripts for tab completion of commands, flags, and
arguments.

```
scorchkit completions <SHELL>
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

**Examples:**

```bash
# Bash completions
scorchkit completions bash > ~/.local/share/bash-completion/completions/scorchkit

# Zsh completions
scorchkit completions zsh > ~/.zfunc/_scorchkit

# Fish completions
scorchkit completions fish > ~/.config/fish/completions/scorchkit.fish
```

---

### Storage Commands (requires `--features storage`)

These commands are available when ScorchKit is built with the `storage` feature.
They require a PostgreSQL database.

#### db migrate

Run pending database migrations to create or update the schema.

```bash
scorchkit db migrate
```

Run this once after first install and after each ScorchKit upgrade.

#### project

Manage security assessment projects.

```bash
# Create a new project
scorchkit project create "client-audit-2026" -d "Q2 penetration test for Client Corp"

# List all projects
scorchkit project list

# Show project details
scorchkit project show "client-audit-2026"

# Security posture metrics and trend analysis
scorchkit project status "client-audit-2026"

# Module effectiveness intelligence
scorchkit project intelligence "client-audit-2026"

# Delete a project (with confirmation prompt)
scorchkit project delete "client-audit-2026"

# Force delete without confirmation
scorchkit project delete "client-audit-2026" -f
```

**Target management within a project:**

```bash
# Add a target to a project
scorchkit project target add "client-audit-2026" https://app.client.com -l "Main application"

# List targets in a project
scorchkit project target list "client-audit-2026"

# Remove a target by UUID
scorchkit project target remove "client-audit-2026" <target-uuid>
```

#### finding

Query and manage tracked vulnerability findings.

```bash
# List all findings for a project
scorchkit finding list "client-audit-2026"

# Filter by severity
scorchkit finding list "client-audit-2026" -s critical
scorchkit finding list "client-audit-2026" -s high

# Filter by status
scorchkit finding list "client-audit-2026" --status new
scorchkit finding list "client-audit-2026" --status remediated

# Show details for a specific finding
scorchkit finding show <finding-uuid>

# Update finding status
scorchkit finding status <finding-uuid> acknowledged
scorchkit finding status <finding-uuid> false_positive -n "Confirmed not exploitable in this context"
scorchkit finding status <finding-uuid> remediated -n "Fixed in commit abc123"
scorchkit finding status <finding-uuid> verified -n "Confirmed fix is effective"
scorchkit finding status <finding-uuid> wont_fix -n "Accepted risk per stakeholder approval"
scorchkit finding status <finding-uuid> accepted_risk -n "Risk accepted by CISO"
```

**Finding statuses:** `new`, `acknowledged`, `false_positive`, `wont_fix`,
`accepted_risk`, `remediated`, `verified`.

#### schedule

Manage recurring scan schedules using cron expressions.

```bash
# Create a daily scan at midnight
scorchkit schedule create "client-audit-2026" https://app.client.com "0 0 * * *"

# Create a weekly thorough scan on Sundays at 2 AM
scorchkit schedule create "client-audit-2026" https://app.client.com "0 2 * * 0" --profile thorough

# List schedules for a project
scorchkit schedule list "client-audit-2026"

# Show schedule details
scorchkit schedule show <schedule-uuid>

# Disable a schedule
scorchkit schedule disable <schedule-uuid>

# Re-enable a disabled schedule
scorchkit schedule enable <schedule-uuid>

# Delete a schedule
scorchkit schedule delete <schedule-uuid>

# Execute all schedules that are currently due
scorchkit schedule run-due
```

---

### serve (requires `--features mcp`)

Start the MCP (Model Context Protocol) server on stdio transport. This allows
AI agents to interact with ScorchKit programmatically.

```bash
scorchkit serve
```

The MCP feature implies `storage`, so a database connection is required.

---

## Global Flags

These flags apply to all commands:

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to configuration file (default: `config.toml` or `scorchkit.toml`) |
| `-v, --verbose` | Increase verbosity (`-v`, `-vv`, `-vvv`) |
| `-q, --quiet` | Suppress all output except findings |
| `-o, --output <FORMAT>` | Output format override: `terminal`, `json`, `html`, `sarif`, `pdf` |

**Examples:**

```bash
# Use a custom config file
scorchkit -c /path/to/my-config.toml run https://target.com

# Verbose output for debugging
scorchkit -vvv run https://target.com

# Quiet mode with JSON output
scorchkit -q -o json run https://target.com
```

---

## Configuration

ScorchKit reads configuration from a TOML file. Generate one with `scorchkit init`
or create it manually. The file is loaded from the path given to `--config`, or
from `config.toml` / `scorchkit.toml` in the current directory.

Below is a complete reference configuration with all sections and their defaults.

### `[scan]` -- Scan Behavior

```toml
[scan]
# Global scan timeout in seconds (default: 300)
timeout_seconds = 300

# Max modules to run concurrently (default: 4)
max_concurrent_modules = 4

# HTTP User-Agent string (default: "ScorchKit/<version>")
user_agent = "ScorchKit/1.0.0"

# Follow HTTP redirects (default: true)
follow_redirects = true

# Maximum number of redirects to follow (default: 10)
max_redirects = 10

# Max requests per second, 0 = unlimited (default: 0)
rate_limit = 0

# Scan profile: quick, standard, thorough (default: "standard")
profile = "standard"

# HTTP/HTTPS proxy URL, e.g., for Burp Suite (default: none)
# proxy = "http://127.0.0.1:8080"

# Skip TLS certificate verification (default: false)
insecure = false

# Directory containing plugin definition files (.toml) (default: none)
# plugins_dir = "./plugins"

# Additional headers to send with every request
[scan.headers]
# X-Custom-Header = "value"

# Scope: only scan URLs matching these patterns (glob). Empty = target domain only.
# scope_include = ["*.example.com"]

# Exclude URLs matching these patterns from scanning.
# scope_exclude = ["/logout", "/admin/*"]
```

### `[auth]` -- Authentication

Configure authentication for scanning behind login forms or APIs.

```toml
[auth]
# Bearer token for Authorization header
# bearer_token = "eyJhbGciOiJIUzI1NiIs..."

# Raw cookie string to send with requests
# cookies = "session=abc123; csrf=xyz789"

# Basic auth credentials
# username = "admin"
# password = "secret"

# Custom auth header
# custom_header = "X-API-Key"
# custom_header_value = "your-api-key-here"
```

### `[tools]` -- External Tool Paths

Override binary paths for external tools. When not set, ScorchKit looks for
tools on your `PATH`.

```toml
[tools]
# nmap = "/usr/local/bin/nmap"
# nikto = "/opt/nikto/nikto.pl"
# nuclei = "/usr/local/bin/nuclei"
# zap = "/opt/zaproxy/zap.sh"
# wpscan = "/usr/local/bin/wpscan"
# droopescan = "/usr/local/bin/droopescan"
# sqlmap = "/usr/local/bin/sqlmap"
# dalfox = "/usr/local/bin/dalfox"
# feroxbuster = "/usr/local/bin/feroxbuster"
# ffuf = "/usr/local/bin/ffuf"
# arjun = "/usr/local/bin/arjun"
# cewl = "/usr/local/bin/cewl"
# sslyze = "/usr/local/bin/sslyze"
# testssl = "/usr/local/bin/testssl.sh"
# amass = "/usr/local/bin/amass"
# subfinder = "/usr/local/bin/subfinder"
# httpx = "/usr/local/bin/httpx"
# theharvester = "/usr/local/bin/theHarvester"
# wafw00f = "/usr/local/bin/wafw00f"
# hydra = "/usr/local/bin/hydra"
# msfconsole = "/usr/local/bin/msfconsole"
```

### `[ai]` -- AI Analysis

Configure the Claude AI integration for scan analysis and planning.

```toml
[ai]
# Enable AI features (default: true)
enabled = true

# Path to the Claude CLI binary (default: "claude")
claude_binary = "claude"

# Claude model to use (default: "sonnet")
model = "sonnet"

# Maximum spend per analysis call in USD (default: 0.50)
max_budget_usd = 0.50

# Automatically run AI analysis after every scan (default: false)
auto_analyze = false
```

### `[report]` -- Report Output

```toml
[report]
# Directory for report output (default: "./reports")
output_dir = "./reports"

# Include raw evidence in findings (default: true)
include_evidence = true

# Include remediation advice in findings (default: true)
include_remediation = true
```

### `[database]` -- Persistent Storage

Requires the `storage` feature.

```toml
[database]
# PostgreSQL connection URL (default: none -- storage disabled)
url = "postgresql://user:password@localhost:5432/scorchkit"

# Maximum connection pool size (default: 5)
max_connections = 5

# Run migrations automatically on startup (default: true)
migrate_on_startup = true
```

The database URL can also be set via the `DATABASE_URL` environment variable
or the `--database-url` CLI flag (which takes highest precedence).

### `[wordlists]` -- Custom Wordlists

Override the built-in wordlists for brute-force and enumeration modules.

```toml
[wordlists]
# Directory brute-force (used by discovery, feroxbuster, ffuf, gobuster)
# directory = "/opt/SecLists/Discovery/Web-Content/common.txt"

# Subdomain enumeration (one prefix per line)
# subdomain = "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"

# Virtual host discovery (one prefix per line)
# vhost = "/opt/SecLists/Discovery/DNS/namelist.txt"

# Parameter fuzzing (one parameter name per line)
# params = "/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
```

Lines starting with `#` in wordlist files are treated as comments and skipped.

### `[[webhooks]]` -- Webhook Notifications

Configure webhook endpoints to receive scan lifecycle notifications. ScorchKit
POSTs JSON payloads for scan events. Delivery is async and fire-and-forget --
webhook failures never block scanning.

```toml
# Send all events to Slack
[[webhooks]]
url = "https://hooks.slack.com/services/T00/B00/xxxxx"

# Send only critical findings to PagerDuty
[[webhooks]]
url = "https://events.pagerduty.com/v2/enqueue"
events = ["finding_discovered"]

# Send start/complete to a monitoring dashboard
[[webhooks]]
url = "https://internal.example.com/webhooks/scorchkit"
events = ["scan_started", "scan_completed"]
```

**Event types:**

| Event | Trigger |
|-------|---------|
| `scan_started` | A scan begins (includes scan ID, target, profile, module count) |
| `scan_completed` | A scan finishes (includes finding count and duration) |
| `finding_discovered` | A critical or high severity finding is discovered |

---

## Output Formats

ScorchKit supports five output formats, selected with the `-o` / `--output`
global flag:

### Terminal (default)

Color-coded findings printed to stdout. Severity levels are highlighted, and
findings include evidence and remediation advice.

```bash
scorchkit run https://target.com
scorchkit run https://target.com -o terminal
```

### JSON

Machine-readable JSON report. Written to the report output directory. Use this
format for programmatic consumption, CI/CD integration, and as input to the
`analyze` and `diff` commands.

```bash
scorchkit run https://target.com -o json
```

### HTML

Self-contained HTML report suitable for sharing with stakeholders. Includes
styled tables, severity badges, and expandable evidence sections.

```bash
scorchkit run https://target.com -o html
```

### SARIF

Static Analysis Results Interchange Format. Compatible with GitHub Code Scanning,
VS Code SARIF Viewer, and other SARIF-consuming tools.

```bash
scorchkit run https://target.com -o sarif
```

### PDF

PDF report for formal documentation and client deliverables.

```bash
scorchkit run https://target.com -o pdf
```

---

## Scan Profiles

Profiles control which modules run during a scan:

| Profile | Modules | Use Case |
|---------|---------|----------|
| `quick` | headers, tech, ssl, misconfig (4 built-in modules only) | Fast check, CI/CD gates |
| `standard` | All built-in modules (default) | Regular assessments |
| `thorough` | All modules including external tool wrappers | Full penetration test |

```bash
scorchkit run https://target.com --profile quick
scorchkit run https://target.com --profile standard
scorchkit run https://target.com --profile thorough
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection URL (overridden by config file and `--database-url`) |
| `RUST_LOG` | Control log verbosity (e.g., `scorchkit=debug`, `scorchkit=trace`) |

---

## Common Workflows

### CI/CD Security Gate

```bash
scorchkit run https://staging.example.com --profile quick -o sarif -q
```

### Authenticated Scan with Config

```bash
# Create config with auth
cat > config.toml << 'EOF'
[auth]
bearer_token = "eyJhbGciOiJIUzI1NiIs..."

[scan]
rate_limit = 10
scope_exclude = ["/logout", "/admin/delete*"]
EOF

scorchkit -c config.toml run https://target.com
```

### Ongoing Project Tracking

```bash
# Set up the database
scorchkit db migrate

# Create a project
scorchkit project create "webapp-audit" -d "Quarterly security assessment"

# Add targets
scorchkit project target add "webapp-audit" https://app.example.com -l "Production"
scorchkit project target add "webapp-audit" https://api.example.com -l "API"

# Run scans with project tracking
scorchkit run https://app.example.com --project "webapp-audit"
scorchkit run https://api.example.com --project "webapp-audit"

# Check security posture over time
scorchkit project status "webapp-audit"

# Manage findings
scorchkit finding list "webapp-audit" -s critical
scorchkit finding status <uuid> remediated -n "Patched in v2.3.1"

# Schedule recurring scans
scorchkit schedule create "webapp-audit" https://app.example.com "0 2 * * 1" --profile standard
```

### Full Autonomous Assessment

```bash
scorchkit agent https://target.com --depth thorough --project "full-pentest"
```

This runs the complete loop: recon, AI-planned scan selection, vulnerability
scanning, AI analysis, and report generation -- all in one command.
