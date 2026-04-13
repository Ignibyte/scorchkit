<p align="center">
  <img src="logo.png" alt="ScorchKit" width="280">
</p>

<p align="center">
  <strong>Web Application Security Testing Toolkit</strong><br>
  <em>77 scan modules. AI-powered analysis. Built for Claude Code.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#claude-code-integration">Claude Code</a> &middot;
  <a href="#modules">Modules</a> &middot;
  <a href="#documentation">Docs</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

ScorchKit is a modular security scanner and orchestrator written in Rust. It combines 45 built-in vulnerability scanners with 32 external tool wrappers behind a single CLI, and integrates with Claude AI for intelligent scan planning and analysis. Use it standalone or as a conversational security assistant inside [Claude Code](https://claude.ai/claude-code).

## Features

- **77 scan modules** — 10 recon, 35 vulnerability scanners, 32 external tool wrappers
- **OWASP Top 10 coverage** — SQLi, XSS, SSRF, XXE, CSRF, IDOR, and more
- **AI-powered analysis** — Claude integration for scan planning, prioritization, and remediation guidance
- **4 output formats** — Terminal, JSON, HTML, SARIF (CI/CD ready)
- **Scan profiles** — Quick (4 modules), Standard (45), Thorough (all 77)
- **Scan templates** — web-app, api, graphql, wordpress, spa, network
- **Proxy support** — Route through Burp Suite or ZAP
- **Scan diffing** — Compare scans to track security posture over time
- **Project management** — Persistent vulnerability tracking with PostgreSQL
- **MCP server** — 24 tools for native Claude Code integration
- **Concurrent execution** — Async modules via tokio with semaphore-based throttling

## Quick Start

### Build

```bash
git clone https://github.com/Ignibyte/scorchkit.git
cd scorchkit
cargo build
```

### Check available tools

```bash
cargo run -- doctor
```

### Run your first scan

```bash
# Quick scan (4 modules — headers, tech, SSL, misconfig)
cargo run -- run https://your-target.com --profile quick

# Standard scan (all 45 built-in modules)
cargo run -- run https://your-target.com

# With AI analysis
cargo run -- run https://your-target.com --analyze

# Through Burp Suite
cargo run -- run https://your-target.com --proxy http://127.0.0.1:8080
```

### AI analysis on a previous scan

```bash
cargo run -- analyze scorchkit-report.json -f summary
cargo run -- analyze scorchkit-report.json -f remediate
```

### Compare two scans

```bash
cargo run -- diff baseline.json current.json
```

## Claude Code Integration

ScorchKit ships with slash commands that turn Claude Code into a conversational security testing assistant.

### Slash Commands

| Command | What it does |
|---------|-------------|
| `/scan` | Run security scans — guided profile selection, auth, proxy |
| `/analyze` | AI analysis — summary, prioritize, remediate, filter |
| `/diff` | Compare scans — track posture changes |
| `/doctor` | Health check — tool installation guidance |
| `/modules` | Explore 77 modules — capabilities, recommendations |
| `/report` | Generate reports — JSON, HTML, SARIF, PDF |
| `/tutorial` | Guided walkthrough for new users |
| `/project` | Project management — targets, scans, posture metrics |
| `/finding` | Finding triage — lifecycle management |
| `/schedule` | Recurring scans — cron scheduling |
| `/coder` | Development assistant for contributors |

### Example session

```
> /scan https://example.com quick

ScorchKit runs a quick profile scan (headers, tech, SSL, misconfig),
presents findings by severity, explains what each means, and suggests
next steps like /analyze for AI insights or /project to track over time.
```

### MCP Server (Advanced)

For native tool integration, ScorchKit includes an MCP server with 24 tools:

```bash
# Build with MCP support (requires PostgreSQL)
cargo build --features mcp

# Configure in .claude/mcp.json
```

See `.claude/mcp.json` for the configuration template.

## Modules

### Recon (10)

| Module | Detects |
|--------|---------|
| `headers` | Security headers, server info, technology hints |
| `tech` | Technology stack fingerprinting |
| `discovery` | Directory and file enumeration |
| `subdomain` | Subdomain discovery |
| `crawler` | Link extraction, form discovery, parameter mapping |
| `dns` | DNS record analysis |
| `js_analysis` | Secrets, API endpoints, source maps in JavaScript |
| `cname_takeover` | Dangling CNAME records, subdomain takeover risk |
| `vhost` | Virtual host discovery |
| `cloud` | Cloud provider detection, S3 bucket enumeration |

### Vulnerability Scanners (35)

| Category | Modules |
|----------|---------|
| **Injection** | `injection` (SQLi), `cmdi`, `xss`, `ssrf`, `xxe`, `nosql`, `ldap`, `ssti`, `crlf` |
| **Auth & Access** | `auth`, `idor`, `jwt`, `acl`, `mass_assignment` |
| **Config** | `ssl`, `misconfig`, `cors`, `csp`, `csrf`, `clickjacking`, `redirect` |
| **API** | `api_schema`, `api`, `graphql`, `ratelimit`, `websocket` |
| **Advanced** | `smuggling`, `host_header`, `path_traversal`, `prototype_pollution`, `dom_xss`, `sensitive`, `upload`, `subtakeover`, `waf` |

### External Tool Wrappers (32)

Wraps industry-standard tools behind a unified interface:

`nmap` `nuclei` `nikto` `sqlmap` `feroxbuster` `sslyze` `zap` `ffuf` `metasploit` `wafw00f` `testssl` `wpscan` `amass` `subfinder` `dalfox` `hydra` `httpx` `theharvester` `arjun` `cewl` `droopescan` `katana` `gau` `paramspider` `trufflehog` `prowler` `trivy` `dnsx` `gobuster` `dnsrecon` `enum4linux` `interactsh`

Install external tools for expanded scanning:

```bash
cargo run -- doctor          # See what's installed
cargo run -- doctor --deep   # Version checks + template freshness
```

## Project Management

Track vulnerabilities over time with persistent storage (requires PostgreSQL):

```bash
# Build with storage support
cargo build --features storage

# Set up database
export DATABASE_URL="postgres://user:pass@localhost/scorchkit"
cargo run --features storage -- db migrate

# Create a project and scan
cargo run --features storage -- project create my-app
cargo run --features storage -- run https://my-app.com --project my-app

# Track findings
cargo run --features storage -- finding list my-app
cargo run --features storage -- project status my-app
```

Finding lifecycle: `new` → `acknowledged` → `remediated` → `verified`

## Scan Profiles

| Profile | Modules | Time | Use Case |
|---------|---------|------|----------|
| `quick` | 4 | Seconds | CI/CD, quick checks |
| `standard` | 45 (all built-in) | 1-3 min | Comprehensive web assessment |
| `thorough` | 77 (all) | 5-15 min | Deep-dive assessment |

```bash
cargo run -- run https://target.com --profile quick
cargo run -- run https://target.com --profile thorough
```

## Output Formats

```bash
cargo run -- run https://target.com -o json     # Machine-readable, diff-compatible
cargo run -- run https://target.com -o html     # Shareable report
cargo run -- run https://target.com -o sarif    # GitHub/GitLab security tab
cargo run -- run https://target.com -o pdf      # Formal pentest deliverable
```

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Module Development Guide](docs/architecture/modules.md)
- [Built-in Module Docs](docs/modules/) — per-module documentation
- [Tool Wrapper Docs](docs/tools/) — per-tool documentation
- [Tools Installation Guide](docs/tools-checklist.md)

## Contributing

ScorchKit is written in Rust. Use the `/coder` command in Claude Code for guided development, or read the architecture docs directly.

```bash
cargo build          # Build
cargo test           # Run tests
cargo clippy         # Lint
cargo fmt            # Format
```

Key patterns:
- Implement `ScanModule` trait for new scanners
- Use `Finding::new(...).with_evidence(...).with_remediation(...)` builder
- Register modules in `register_modules()`
- See `docs/architecture/modules.md` for the full guide

## License

[MIT](LICENSE) — Copyright (c) 2026 Ignibyte
