<p align="center">
  <img src="logo.png" alt="ScorchKit" width="280">
</p>

<p align="center">
  <strong>Security Testing Toolkit & Orchestrator</strong><br>
  <em>80 modules. DAST + SAST. AI-powered analysis. Built for Claude Code.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#code-scanning-sast">SAST</a> &middot;
  <a href="#claude-code-integration">Claude Code</a> &middot;
  <a href="#modules">Modules</a> &middot;
  <a href="#roadmap">Roadmap</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

ScorchKit is a modular security scanner and orchestrator written in Rust. It combines dynamic web application testing (DAST) with static code analysis (SAST) behind a single CLI, and integrates with Claude AI for intelligent scan planning and analysis. Use it standalone or as a conversational security assistant inside [Claude Code](https://claude.ai/claude-code).

## Features

- **80 scan modules** — 45 DAST (web scanning) + 3 SAST (code analysis) + 32 external tool wrappers
- **DAST + SAST** — scan running web apps AND source code from one tool
- **OWASP Top 10 coverage** — SQLi, XSS, SSRF, XXE, CSRF, IDOR, and more
- **AI-powered analysis** — Claude integration for scan planning, prioritization, and remediation guidance
- **4 output formats** — Terminal, JSON, HTML, SARIF (CI/CD ready)
- **Scan profiles** — Quick, Standard, Thorough for both DAST and SAST
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

### Scan a web application (DAST)

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

### Scan source code (SAST)

```bash
# Scan a codebase for vulnerabilities, secrets, and dependency issues
cargo run -- code ./my-project

# Quick scan (secrets + dependency audit only)
cargo run -- code ./my-project --profile quick

# Scan with specific tools
cargo run -- code ./my-project -m semgrep,gitleaks
```

### AI analysis

```bash
cargo run -- analyze scorchkit-report.json -f summary
cargo run -- analyze scorchkit-report.json -f remediate
```

### Compare two scans

```bash
cargo run -- diff baseline.json current.json
```

## Code Scanning (SAST)

ScorchKit includes static application security testing alongside its web scanning capabilities. The `code` subcommand scans source code, dependencies, and secrets.

```bash
scorchkit code <path> [--language rust] [--profile standard] [--modules semgrep,gitleaks]
```

### SAST Tools

| Tool | Category | What It Scans |
|------|----------|--------------|
| **Semgrep** | SAST | Multi-language code patterns, security anti-patterns |
| **OSV-Scanner** | SCA | Dependency vulnerabilities across all ecosystems (Google OSV database) |
| **Gitleaks** | Secrets | Hardcoded API keys, tokens, credentials in source code |

### SAST Profiles

| Profile | Tools | Use Case |
|---------|-------|----------|
| `quick` | Secrets + SCA (Gitleaks, OSV-Scanner) | CI/CD, fast checks |
| `standard` | All SAST tools | Comprehensive code analysis |
| `thorough` | All SAST tools | Same as standard (grows with more tools) |

### Language Detection

ScorchKit auto-detects your project's language from manifest files (`Cargo.toml`, `package.json`, `go.mod`, `requirements.txt`, `pom.xml`, etc.). Override with `--language`.

### Secret Redaction

Gitleaks findings automatically redact secret values in reports — only the first 8 characters are shown. Reports never contain full exposed credentials.

## Claude Code Integration

ScorchKit ships with slash commands that turn Claude Code into a conversational security testing assistant.

### Slash Commands

| Command | What it does |
|---------|-------------|
| `/scan` | Run security scans — guided profile selection, auth, proxy |
| `/analyze` | AI analysis — summary, prioritize, remediate, filter |
| `/diff` | Compare scans — track posture changes |
| `/doctor` | Health check — tool installation guidance |
| `/modules` | Explore 80 modules — capabilities, recommendations |
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

### DAST: Recon (10)

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

### DAST: Vulnerability Scanners (35)

| Category | Modules |
|----------|---------|
| **Injection** | `injection` (SQLi), `cmdi`, `xss`, `ssrf`, `xxe`, `nosql`, `ldap`, `ssti`, `crlf` |
| **Auth & Access** | `auth`, `idor`, `jwt`, `acl`, `mass_assignment` |
| **Config** | `ssl`, `misconfig`, `cors`, `csp`, `csrf`, `clickjacking`, `redirect` |
| **API** | `api_schema`, `api`, `graphql`, `ratelimit`, `websocket` |
| **Advanced** | `smuggling`, `host_header`, `path_traversal`, `prototype_pollution`, `dom_xss`, `sensitive`, `upload`, `subtakeover`, `waf` |

### DAST: External Tool Wrappers (32)

`nmap` `nuclei` `nikto` `sqlmap` `feroxbuster` `sslyze` `zap` `ffuf` `metasploit` `wafw00f` `testssl` `wpscan` `amass` `subfinder` `dalfox` `hydra` `httpx` `theharvester` `arjun` `cewl` `droopescan` `katana` `gau` `paramspider` `trufflehog` `prowler` `trivy` `dnsx` `gobuster` `dnsrecon` `enum4linux` `interactsh`

### SAST: Code Analysis (3)

| Tool | Category | What It Scans |
|------|----------|--------------|
| `semgrep` | SAST | Multi-language static analysis with curated security rules |
| `osv-scanner` | SCA | Dependency vulnerabilities via Google OSV database |
| `gitleaks` | Secrets | Hardcoded secrets, API keys, credentials |

```bash
cargo run -- doctor    # See what's installed (DAST + SAST tools)
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

Finding lifecycle: `new` -> `acknowledged` -> `remediated` -> `verified`

## Scan Profiles

### DAST (Web Scanning)

| Profile | Modules | Time | Use Case |
|---------|---------|------|----------|
| `quick` | 4 | Seconds | CI/CD, quick checks |
| `standard` | 45 (all built-in) | 1-3 min | Comprehensive web assessment |
| `thorough` | 77 (all DAST) | 5-15 min | Deep-dive assessment |

### SAST (Code Scanning)

| Profile | Tools | Time | Use Case |
|---------|-------|------|----------|
| `quick` | Secrets + SCA | Seconds | CI/CD, pre-commit |
| `standard` | All SAST tools | 1-2 min | Full code analysis |

## Output Formats

```bash
cargo run -- run https://target.com -o json     # Machine-readable, diff-compatible
cargo run -- run https://target.com -o html     # Shareable report
cargo run -- run https://target.com -o sarif    # GitHub/GitLab security tab
cargo run -- run https://target.com -o pdf      # Formal pentest deliverable
```

## Roadmap

ScorchKit is evolving from a web application scanner into a full-stack security platform.

| Version | Milestone | Status |
|---------|-----------|--------|
| **v1.0** | DAST (45 built-in + 32 tool wrappers) + SAST foundation (Semgrep, OSV-Scanner, Gitleaks) | Current |
| **v1.1** | More SAST tools (Bandit, Checkov, Hadolint, Grype), built-in dependency auditor | Planned |
| **v1.2** | Snyk integration (paid tier), DAST+SAST AI correlation | Planned |
| **v1.3** | `/code` Claude Code command, MCP tools for code scanning | Planned |
| **v2.0** | Infrastructure scanning (CVE/NVT matching, service detection) | Future |
| **v2.1** | Cloud security posture (AWS/GCP/Azure config auditing) | Future |
| **v2.2** | Compliance frameworks (CIS benchmarks, PCI-DSS, SOC2) | Future |
| **v3.0** | Full-stack AI correlation — network + web app + code + cloud in one assessment | Future |

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [SAST Architecture](docs/architecture/sast.md)
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
- Implement `ScanModule` trait for new DAST scanners
- Implement `CodeModule` trait for new SAST analyzers
- Use `Finding::new(...).with_evidence(...).with_remediation(...)` builder
- Register modules in `register_modules()`
- See `docs/architecture/modules.md` (DAST) and `docs/architecture/sast.md` (SAST)

## License

[MIT](LICENSE) -- Copyright (c) 2026 Ignibyte
