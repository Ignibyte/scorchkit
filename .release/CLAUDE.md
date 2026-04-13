# ScorchKit

Rust security testing toolkit and orchestrator. 80 modules — 45 DAST (web scanning) + 3 SAST (code analysis) + 32 external tool wrappers. Claude AI integration, 4 output formats, proxy support, authenticated scanning, scan profiles, scan diffing.

## Quick Reference

```bash
cargo build                                       # Build
cargo test                                        # Run tests
cargo run -- run <url>                            # Scan a target
cargo run -- run <url> --profile quick            # Fast scan (4 modules)
cargo run -- run <url> --analyze                  # Scan + AI analysis
cargo run -- run <url> --proxy http://127.0.0.1:8080  # Through Burp
cargo run -- analyze <report.json> -f remediate   # AI remediation guide
cargo run -- diff baseline.json current.json      # Compare two scans
cargo run -- doctor                               # Check tool installation
cargo run -- modules --check-tools                # List all 80 modules
cargo run -- code ./src                           # SAST scan on source code
cargo run -- code ./src --profile quick           # Secrets + deps only
cargo run -- completions bash                     # Shell completions
```

## Claude Code Commands

ScorchKit includes Claude Code slash commands for conversational security testing. Use these inside Claude Code for a guided experience.

### Scanning & Analysis

| Command | Purpose |
|---------|---------|
| `/scan` | Run security scans — profile selection, auth, proxy, module filtering |
| `/analyze` | AI-powered analysis — summary, prioritize, remediate, filter |
| `/diff` | Compare two scans — track security posture changes |
| `/report` | Generate reports — JSON, HTML, SARIF, PDF |

### Setup & Exploration

| Command | Purpose |
|---------|---------|
| `/tutorial` | Guided walkthrough for new users |
| `/doctor` | Check tool installation, get setup help |
| `/modules` | Explore 77 scan modules and capabilities |

### Project Management (requires PostgreSQL + `--features storage`)

| Command | Purpose |
|---------|---------|
| `/project` | Manage projects — create, targets, status, intelligence |
| `/finding` | Triage findings — lifecycle management, status transitions |
| `/schedule` | Recurring scans — cron-based scheduling |

### Contributing

| Command | Purpose |
|---------|---------|
| `/coder` | Development assistant — architecture docs, module patterns |

## MCP Server Integration

ScorchKit includes an MCP (Model Context Protocol) server that lets Claude use scanning tools directly. See `.claude/mcp.json` for configuration.

Build with MCP support:
```bash
cargo build --features mcp
```

The MCP server exposes 24 tools covering scanning, project management, finding lifecycle, scheduling, and AI analysis.

## Project Structure

```
src/
  main.rs              Entry point (tokio runtime, tracing)
  lib.rs               Module tree
  engine/              Core: Target, Finding, Severity, ScanModule trait, ScanContext, ScanResult, ScorchError
  cli/                 Clap CLI (args.rs), command dispatch (runner.rs), shell completions, doctor
  config/              TOML: ScanConfig, AuthConfig, ToolsConfig, AiConfig, ReportConfig
  runner/              Orchestrator (concurrent via semaphore), subprocess management, progress, hooks
  recon/               headers, tech, discovery, subdomain, crawler, dns, js_analysis, cname_takeover, vhost, cloud
  scanner/             ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive,
                       api_schema, ratelimit, cors, csp, auth, upload, websocket, graphql, subtakeover, acl,
                       api, path_traversal, ssti, nosql, ldap, crlf, host_header, smuggling,
                       prototype_pollution, mass_assignment, clickjacking, dom_xss, waf
  tools/               nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f,
                       testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl,
                       droopescan, katana, gau, paramspider, trufflehog, prowler, trivy, dnsx, gobuster,
                       dnsrecon, enum4linux, interactsh
  agent/               Autonomous scan agent (recon -> plan -> scan -> analyze loop)
  ai/                  Claude CLI integration (analyst, planner, prompts, response parser)
  report/              terminal, json, html, sarif, pdf, diff
  mcp/                 MCP server (rmcp, stdio transport, 24 tools, resources)
  storage/             PostgreSQL persistence (sqlx, projects, findings, schedules, metrics, intelligence)
tests/
  cli.rs               CLI integration tests
docs/
  architecture/        System design docs
  modules/             Individual docs for each built-in module
  tools/               Individual docs for each external tool wrapper
  tools-checklist.md   Installation guide for all external tools
```

## Key Conventions

- **Module naming**: `engine/` not `core/` (avoids `std::core` shadow)
- **Error handling**: `engine::error::Result<T>` with `ScorchError` via `thiserror`
- **No unwrap/expect**: denied by clippy
- **Async**: tokio, concurrent module execution via semaphore
- **Module pattern**: implement `ScanModule` trait, register in `register_modules()`
- **Finding builder**: `Finding::new(...).with_evidence(...).with_remediation(...).with_owasp(...).with_cwe(...)`
- **Proxy**: reqwest `.proxy()` support, configured via `--proxy` flag or `config.toml`
- **Cookie jar**: `cookie_store(true)` on HTTP client for session persistence
- **Profiles**: quick (4 modules), standard (all built-in), thorough (everything)
- **Scope**: `--scope` and `--exclude` flags, config file support
- **Feature flags**: `storage` for PostgreSQL, `mcp` for MCP server (implies storage)

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Module Development Guide](docs/architecture/modules.md)
- [Built-in Module Docs](docs/modules/) (per-module documentation)
- [Tool Wrapper Docs](docs/tools/) (per-tool documentation)
- [Tools Installation Guide](docs/tools-checklist.md)
