<p align="center">
  <img src="logo.png" alt="ScorchKit" width="280">
</p>

<p align="center">
  <strong>Web · Code · Infrastructure security testing in one Rust binary</strong><br>
  <em>95 modules across DAST, SAST, and Infra. AI-powered analysis. Built for Claude Code.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#unified-assessment-v20">Unified <code>assess</code></a> &middot;
  <a href="#infrastructure-scanning-v20">Infra (v2.0)</a> &middot;
  <a href="#code-scanning-sast">SAST</a> &middot;
  <a href="#claude-code-integration">Claude Code</a> &middot;
  <a href="#modules">Modules</a> &middot;
  <a href="#roadmap">Roadmap</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

ScorchKit is a modular security testing toolkit and orchestrator written in Rust. It combines **dynamic web application testing (DAST)**, **static code analysis (SAST)**, and **infrastructure scanning** — including CVE correlation against NVD or OSV — behind a single CLI. Use it standalone or as a conversational security assistant inside [Claude Code](https://claude.ai/claude-code).

**v2.0 highlights:** Infrastructure scanning is here — service fingerprinting, CVE matching against NVD or OSV, non-HTTP TLS hygiene (SMTPS / LDAPS / IMAPS / POP3S + STARTTLS on SMTP / IMAP / POP3), and DNS hygiene (wildcard / DNSSEC / CAA / NS). All five `InfraCategory` slots ship populated. The new `assess` command runs DAST, SAST, and infra concurrently against the same target.

## Features

- **95 modules across three families** — 77 DAST (web) + 13 SAST (code) + 5 Infra (host/network)
- **Unified `assess`** — `--url`, `--code`, `--infra` in one command, three orchestrators in parallel, results merged
- **CVE correlation** — built-in NVD 2.0 and OSV.dev backends behind a `CveLookup` trait; per-backend disk cache, rate limiting, negative caching, env-var-precedence API key
- **TLS infra hygiene** — STARTTLS + implicit-TLS handshake + cert analysis on mail and directory ports
- **DNS hygiene** — wildcard, DNSSEC, CAA, NS via native async resolver
- **OWASP Top 10 coverage** — SQLi, XSS, SSRF, XXE, CSRF, IDOR, and more
- **AI-powered analysis** — Claude integration for scan planning, prioritization, and remediation
- **5 output formats** — Terminal, JSON, HTML, SARIF (CI/CD), PDF
- **Scan profiles** — Quick / Standard / Thorough for DAST and SAST
- **Scan templates** — web-app, api, graphql, wordpress, spa, network
- **Proxy support** — route through Burp Suite or ZAP
- **Scan diffing** — compare scans to track security posture over time
- **Project management** — persistent vulnerability tracking with PostgreSQL
- **MCP server** — tools for native Claude Code integration
- **Concurrent execution** — async modules via tokio with semaphore-based throttling

## Quick Start

### Build

```bash
git clone https://github.com/Ignibyte/scorchkit.git
cd scorchkit
cargo build                          # default features (DAST + SAST)
cargo build --features infra         # add infrastructure scanning
cargo build --features mcp           # implies storage; for MCP server
```

### Check available tools

```bash
cargo run -- doctor
```

### Unified assessment (v2.0)

```bash
# DAST + SAST + Infra against the same target, concurrently
cargo run --features infra -- assess \
    --url   https://your-target.com \
    --code  ./your-target-source \
    --infra your-target.com
```

### Scan a web application (DAST)

```bash
# Quick scan (4 modules — headers, tech, SSL, misconfig)
cargo run -- run https://your-target.com --profile quick

# Standard scan (all built-in DAST modules)
cargo run -- run https://your-target.com

# With AI analysis
cargo run -- run https://your-target.com --analyze

# Through Burp Suite
cargo run -- run https://your-target.com --proxy http://127.0.0.1:8080
```

### Scan source code (SAST)

```bash
cargo run -- code ./my-project                    # All SAST tools
cargo run -- code ./my-project --profile quick    # Secrets + dependency audit only
cargo run -- code ./my-project -m semgrep,gitleaks
```

### Scan infrastructure (v2.0)

```bash
# Full infra scan: port probe, fingerprint, CVE match, TLS hygiene, DNS hygiene
cargo run --features infra -- infra mail.example.com

# Just CVE correlation (after configuring [cve] in scorchkit.toml)
cargo run --features infra -- infra mail.example.com --modules cve_match

# DNS hygiene only
cargo run --features infra -- infra example.com --modules dns_infra
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

## Unified Assessment (v2.0)

The `assess` command runs DAST, SAST, and infra orchestrators **concurrently** via `tokio::join!` and merges results into a single `ScanResult`. Per-domain failures are logged and skipped — partial results still return. At least one of `--url`, `--code`, `--infra` is required.

```bash
cargo run --features infra -- assess \
    --url   https://api.example.com \
    --code  ./services/api \
    --infra api.example.com \
    --analyze
```

Best for security reviews where you want one pass over the same target from three angles. Each domain reuses the same `[scope]`, `[auth]`, `[ai]`, and `[report]` config — no duplicate setup.

## Infrastructure Scanning (v2.0)

Add `--features infra` at build time to enable. Probes hosts, IPs, and CIDR ranges via the new `InfraModule` trait, parallel to `ScanModule` (DAST) and `CodeModule` (SAST).

| Module | Category | Description |
|--------|----------|-------------|
| `tcp_probe` | PortScan | Privilege-free TCP-connect reachability against a configurable port list |
| `nmap` (infra) | PortScan + Fingerprint | `nmap -sV` invocation; publishes `ServiceFingerprint`s for downstream CVE matching |
| `cve_match` | CveMatch | Correlates fingerprints against the configured `CveLookup` backend (NVD or OSV) |
| `tls_infra` | TlsInfra | TLS handshake + cert analysis on SMTPS/LDAPS/IMAPS/POP3S + STARTTLS on SMTP/IMAP/POP3 |
| `dns_infra` | Dns | Wildcard A/AAAA detection, DNSSEC presence (DNSKEY), CAA record presence, NS enumeration |

### CVE backends

Two production `CveLookup` impls behind the same trait. Pick one (or run separate scans for each) via `[cve]` in `scorchkit.toml`:

```toml
[cve]
backend = "nvd"        # or "osv" or "mock" or "disabled" (default)

[cve.nvd]
api_key = "your-key"   # optional; or set SCORCHKIT_NVD_API_KEY (env wins over config)
# Defaults: cache_dir = $XDG_CACHE_HOME/scorchkit/cve, cache_ttl_secs = 86400

[cve.osv]
# OSV is keyless. Defaults: cache_dir = $XDG_CACHE_HOME/scorchkit/cve-osv,
# cache_ttl_secs = 86400, max_rps = 10
```

| | NVD | OSV |
|---|-----|-----|
| **Best for** | System software (nginx, OpenSSH, OpenSSL, Apache HTTPD) | Language packages (npm, PyPI, Maven, Go, crates, gems, NuGet, Composer) |
| **API key** | Optional (`SCORCHKIT_NVD_API_KEY` or config) | Keyless |
| **Rate limit** | 5/30s anonymous, 50/30s with key | Conservative 10 RPS (under OSV's ~25 QPS fair-use) |
| **Score precision** | Numeric base scores from NVD | CVSS vector → in-process v3.1 base-score computation |

Both backends own their own `reqwest::Client` (separate from the scan client so pen-test proxy / insecure-TLS settings never leak into vendor calls), wrap a `governor::RateLimiter`, and consult a sha256-keyed file-system TTL cache with negative caching. Per-backend cache directories prevent cross-contamination.

See [docs/modules/cve-nvd.md](docs/modules/cve-nvd.md) and [docs/modules/cve-osv.md](docs/modules/cve-osv.md) for the full operator references.

### TLS infra

Probes the common TLS-bearing mail and directory services and runs the same four cert checks the DAST `ssl` module uses (expired, self-signed, weak signature, host mismatch). HTTPS (443) stays with the DAST path — `tls_infra` covers everything else:

| Port | Mode | Service |
|-----:|------|---------|
| 465 | Implicit | SMTPS |
| 636 | Implicit | LDAPS |
| 993 | Implicit | IMAPS |
| 995 | Implicit | POP3S |
| 25 / 587 | STARTTLS (SMTP) | SMTP / Submission |
| 143 | STARTTLS (IMAP) | IMAP |
| 110 | STARTTLS (POP3) | POP3 |

Closed ports surface as Info findings — operators see the probe coverage without false-positive noise. See [docs/modules/tls-infra.md](docs/modules/tls-infra.md).

### DNS infra

Native async DNS hygiene checks:

| Check | Severity | Trigger |
|-------|---------:|---------|
| Wildcard DNS | Medium | A random non-existent subdomain (16-hex random label) resolves |
| DNSSEC missing | Medium | No `DNSKEY` records at the apex |
| CAA missing | Low | No `CAA` records at the apex |
| NS enumeration | Info | Surfaces the authoritative-server list |

See [docs/modules/dns-infra.md](docs/modules/dns-infra.md).

## Code Scanning (SAST)

```bash
scorchkit code <path> [--language rust] [--profile standard] [--modules semgrep,gitleaks]
```

### SAST tools (13 total in v2.0)

| Tool | Category | What It Scans |
|------|----------|--------------|
| **dep_audit** (built-in) | SCA | Cargo / npm / Python / Go lockfiles — duplicate versions, unpinned deps, known-risky packages |
| **Semgrep** | SAST | Multi-language code patterns, security anti-patterns |
| **OSV-Scanner** | SCA | Dependency vulnerabilities across all ecosystems (Google OSV) |
| **Gitleaks** | Secrets | Hardcoded API keys, tokens, credentials in source code |
| **Bandit** | SAST | Python-specific security analysis |
| **Gosec** | SAST | Go-specific security analysis |
| **PHPStan** | SAST | PHP-specific security analysis |
| **ESLint security** | SAST | JS/TS-specific security rules |
| **Checkov** | IaC | Terraform / CloudFormation / Kubernetes / Dockerfile config |
| **Hadolint** | IaC | Dockerfile best-practices |
| **Grype** | SCA + Containers | Container image and dependency vulnerabilities |
| **Snyk Code** | SAST | Commercial SAST (free tier) |
| **Snyk Test** | SCA | Commercial SCA (free tier) |

### SAST profiles

| Profile | Tools | Use Case |
|---------|-------|----------|
| `quick` | Secrets + SCA (dep_audit, Gitleaks, OSV-Scanner) | CI/CD, fast checks |
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
| `/scan` | Run DAST web scans — guided profile selection, auth, proxy |
| `/code` | Run SAST code analysis — secrets, dependencies, code patterns |
| `/analyze` | AI analysis — summary, prioritize, remediate, filter |
| `/diff` | Compare scans — track posture changes |
| `/doctor` | Health check — tool installation guidance |
| `/modules` | Explore modules — capabilities, recommendations |
| `/report` | Generate reports — JSON, HTML, SARIF, PDF |
| `/tutorial` | Guided walkthrough for new users |
| `/project` | Project management — targets, scans, posture metrics |
| `/finding` | Finding triage — lifecycle management |
| `/schedule` | Recurring scans — cron scheduling |
| `/coder` | Development assistant for contributors |

### MCP Server (Advanced)

For native tool integration, ScorchKit includes an MCP server:

```bash
cargo build --features mcp           # Requires PostgreSQL
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

### SAST: Code Analysis (13)

`dep_audit` (built-in) `semgrep` `osv-scanner` `gitleaks` `bandit` `gosec` `phpstan` `eslint_security` `checkov` `hadolint` `grype` `snyk_code` `snyk_test`

### Infra: Host / Network (5, gated `--features infra`)

`tcp_probe` `nmap` (infra variant) `cve_match` `tls_infra` `dns_infra`

```bash
cargo run -- doctor                  # See what's installed (DAST + SAST tools)
cargo run -- modules --check-tools   # List every module
```

## Project Management

Track vulnerabilities over time with persistent storage (requires PostgreSQL):

```bash
cargo build --features storage
export DATABASE_URL="postgres://user:pass@localhost/scorchkit"
cargo run --features storage -- db migrate
cargo run --features storage -- project create my-app
cargo run --features storage -- run https://my-app.com --project my-app
cargo run --features storage -- finding list my-app
cargo run --features storage -- project status my-app
```

Finding lifecycle: `new` → `acknowledged` → `remediated` → `verified`

## Scan Profiles

### DAST (web scanning)

| Profile | Modules | Time | Use Case |
|---------|---------|------|----------|
| `quick` | 4 | Seconds | CI/CD, quick checks |
| `standard` | 45 (all built-in) | 1-3 min | Comprehensive web assessment |
| `thorough` | 77 (all DAST) | 5-15 min | Deep-dive assessment |

### SAST (code scanning)

| Profile | Tools | Time | Use Case |
|---------|-------|------|----------|
| `quick` | Secrets + SCA | Seconds | CI/CD, pre-commit |
| `standard` | All SAST tools | 1-2 min | Full code analysis |

### Infra (v2.0)

| Profile | Modules | Time | Use Case |
|---------|---------|------|----------|
| `quick` | `tcp_probe` only | Seconds | Reachability check |
| `standard` | All registered infra modules + `cve_match` if configured | Minutes | Full host posture |

## Output Formats

```bash
cargo run -- run https://target.com -o json     # Machine-readable, diff-compatible
cargo run -- run https://target.com -o html     # Shareable report
cargo run -- run https://target.com -o sarif    # GitHub/GitLab security tab
cargo run -- run https://target.com -o pdf      # Formal pentest deliverable
```

## Roadmap

ScorchKit is a full-stack security platform spanning web, code, and infrastructure.

| Version | Milestone | Status |
|---------|-----------|--------|
| **v1.0** | DAST (45 built-in + 32 wrappers) + SAST foundation (Semgrep, OSV-Scanner, Gitleaks) | Released 2026-04-13 |
| **v2.0** | **Infrastructure scanning — service fingerprinting, CVE correlation (NVD + OSV), TLS hygiene, DNS hygiene; unified `assess` command; SAST tool family expanded to 13** | **Released 2026-04-14 — current** |
| **v2.1** | API endpoint discovery integration (Vespasian wrapper); authenticated network scanning (SSH/SMB/SNMP credentialed probes); RDP-TLS support | Planned |
| **v2.2** | Cloud security posture (AWS/GCP/Azure config auditing, Prowler deep integration) | Planned |
| **v2.3** | Compliance frameworks (CIS benchmarks, PCI-DSS, SOC 2, HIPAA) | Planned |
| **v3.0** | AI attack-chain correlation across DAST + SAST + Infra; risk scoring engine; executive dashboard | Future |

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Engine Internals](docs/architecture/engine.md) — `Finding`, `Severity`, traits, shared helpers
- [SAST Architecture](docs/architecture/sast.md)
- [Module Development Guide](docs/architecture/modules.md)
- [Infra Modules](docs/modules/) — `cve-nvd.md`, `cve-osv.md`, `tls-infra.md`, `dns-infra.md`
- [Built-in Module Docs](docs/modules/) — per-module documentation
- [Tool Wrapper Docs](docs/tools/) — per-tool documentation
- [Tools Installation Guide](docs/tools-checklist.md)

## Contributing

ScorchKit is written in Rust. Use the `/coder` command in Claude Code for guided development, or read the architecture docs directly.

```bash
cargo build                        # Default features
cargo build --features infra       # Add infrastructure scanning
cargo test                         # Run tests (default)
cargo test --features infra        # Run tests with infra
cargo clippy                       # Lint
cargo fmt                          # Format
```

Key patterns:
- Implement `ScanModule` trait for new DAST scanners
- Implement `CodeModule` trait for new SAST analyzers
- Implement `InfraModule` trait for new infra probes (gated `infra`)
- Use `Finding::new(...).with_evidence(...).with_remediation(...)` builder
- Register modules in the appropriate `register_modules()`
- For new CVE backends, implement `CveLookup` and add a `CveBackendKind` variant + factory dispatch
- See `docs/architecture/` for full guidance

## License

[MIT](LICENSE) — Copyright (c) 2026 Ignibyte
