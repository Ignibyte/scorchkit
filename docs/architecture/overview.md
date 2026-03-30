# Architecture Overview

## What ScorchKit Is

ScorchKit is a modular web application security testing toolkit written in Rust. It operates as both:

1. **A native scanner** - built-in Rust modules that perform security checks directly (HTTP headers, SSL analysis, injection detection, etc.)
2. **An orchestrator** - wraps and coordinates external pentesting tools (nmap, sqlmap, nuclei, etc.) behind a unified interface

The tool targets OWASP Top 10 web vulnerabilities and integrates Claude AI for intelligent analysis of findings.

## System Architecture

```
     ┌──────────────┐              ┌──────────────────┐
     │   CLI (clap) │              │   MCP Server     │
     │   args.rs    │              │  (rmcp stdio)    │
     └──────┬───────┘              │  20 tools        │
            │                      │  6 resources     │
     ┌──────▼───────┐              └──────┬───────────┘
     │   Runner     │                     │
     │  runner.rs   │                     │
     └──────┬───────┘                     │
            │                             │
            └──────────┬──────────────────┘
                       │
          ┌────────────▼────────────────┐
          │        Orchestrator         │
          │      orchestrator.rs        │
          │                             │
          │  ┌─────┐ ┌─────┐ ┌───────┐ │
          │  │Mod 1│ │Mod 2│ │ Mod N │ │  ← ScanModule trait
          │  └──┬──┘ └──┬──┘ └───┬───┘ │
          └─────┼───────┼────────┼──────┘
                │       │        │
       ┌────────▼──┐ ┌──▼────┐ ┌─▼──────────┐
       │  Built-in │ │ HTTP  │ │  External   │
       │  Analysis │ │ Reqs  │ │  Tool Exec  │
       └───────────┘ └───────┘ └─────────────┘
                │       │        │
                └───────┼────────┘
                        │
                 ┌──────▼───────┐
                 │ Vec<Finding> │
                 └──────┬───────┘
                        │
          ┌─────────────▼─────────────┐
          │                           │
   ┌──────▼──────┐  ┌────────▼─────┐  ┌──────▼──────┐
   │   Report    │  │ AI Analysis  │  │   Storage   │
   │ (term/json) │  │ (claude -p)  │  │ (PostgreSQL)│
   └─────────────┘  └──────────────┘  └─────────────┘
```

The CLI and MCP server are two entry points into the same engine. The CLI dispatches commands directly; the MCP server exposes the same operations as tools that AI assistants call conversationally. Both share the Orchestrator for scanning and the Storage layer for persistence. See [mcp.md](mcp.md) for MCP server details.

## Data Flow

1. **User** invokes `scorchkit run <target>` with optional flags
2. **CLI** parses arguments via clap, loads `AppConfig` from TOML
3. **Target** is parsed from the input string (URL, domain, or IP)
4. **ScanContext** is built: Target + AppConfig (Arc) + reqwest::Client
5. **Orchestrator** discovers modules, applies filters (category, include, exclude)
6. **Orchestrator** checks external tool availability, skips unavailable modules
7. **Modules** run concurrently (up to `max_concurrent_modules`), each returning `Vec<Finding>`
8. **Findings** are aggregated, sorted by severity (critical first)
9. **ScanResult** is constructed with findings, metadata, and summary stats
10. **Reports** are generated: JSON saved to disk, terminal output printed
11. **(Optional)** AI analysis via Claude CLI subprocess

## Core Abstractions

### ScanModule Trait
The central abstraction. Every scanner implements this trait, providing a uniform interface for the orchestrator. See [modules.md](modules.md).

### Finding
The universal data currency. Modules produce them, the orchestrator collects them, AI analyzes them, reports render them. See [engine.md](engine.md).

### ScanContext
Shared state passed to every module: the target, config, and a pooled HTTP client. See [engine.md](engine.md).

### ScorchError
Unified error type covering all failure domains (HTTP, tool execution, config, parsing, I/O). See [engine.md](engine.md).

## Design Principles

1. **Modular** - Adding a new scanner is: implement trait, register in mod.rs. No other files change.
2. **Fail gracefully** - A module error skips that module, doesn't abort the scan. Tool not installed? Skip and report.
3. **No unsafe** - `unsafe_code` is denied at the lint level.
4. **Async-first** - All network I/O and subprocess calls are async via tokio.
5. **Structured output** - Every finding has severity, OWASP category, CWE ID, evidence, and remediation.
6. **Config-driven** - All behavior is configurable via TOML, with sensible defaults.
7. **CLI-first** - No GUI, no web server. Fast terminal workflow.

## Module Categories

ScorchKit ships with **63 modules** (6 recon + 24 scanner + 32 tools + user plugins):

| Category | Count | Purpose | Examples |
|----------|-------|---------|---------|
| **Recon** | 6 | Information gathering, no active exploitation | Headers, tech fingerprinting, directory discovery, subdomain enum, crawler, DNS security |
| **Scanner** | 24 | Active vulnerability detection | SQLi, XSS, SSRF, XXE, CSRF, CORS, CSP, JWT, upload, WebSocket, GraphQL, ACL, API security |
| **Tools** | 32 | External tool wrappers | nmap, nuclei, sqlmap, feroxbuster, ffuf, dalfox, interactsh, prowler, trivy, trufflehog |
| **Plugins** | variable | User-defined modules via TOML | Custom tool wrappers loaded from a plugins directory |

## Additional Subsystems

### Compliance Mapping (`engine/compliance.rs`)
Maps OWASP Top 10 and CWE identifiers to compliance framework controls: NIST 800-53, PCI-DSS 4.0, SOC2 TSC, and HIPAA. Findings can carry compliance references via `.with_compliance()`. See [engine.md](engine.md).

### Scope Management (`engine/scope.rs`)
Structured scope rules supporting exact domain, wildcard (`*.example.com`), and CIDR (`192.168.1.0/24`) matching. Used to enforce target boundaries. See [engine.md](engine.md).

### Evidence Capture (`engine/evidence.rs`)
`HttpEvidence` struct captures full HTTP request/response pairs and attaches them to findings for PoC replay. Response bodies are truncated to 10KB. See [engine.md](engine.md).

### Webhook Notifications (`runner/hooks.rs`)
Fire-and-forget JSON webhook delivery for scan lifecycle events (`ScanStarted`, `ScanCompleted`, `FindingDiscovered`). Configured via `WebhookConfig` with optional event type filtering. See [runner.md](runner.md).

### Plugin System (`runner/plugin.rs`)
TOML-based user-defined scan modules. Define a command, arguments (with `{target}` substitution), output format, and severity. Loaded from a configurable plugins directory. See [runner.md](runner.md).

### Agent SDK Support (`agent/`)
Configuration, system prompts, and manifest generation for integrating ScorchKit with the Claude Agent SDK. Produces JSON manifests that Agent SDK clients consume for autonomous pentest operations. See [agent.md](agent.md).

### Out-of-Band Detection (`engine/oob.rs`)
Wraps `interactsh-client` as a long-running subprocess to provide OOB callback URLs for blind vulnerability detection (SSRF, XXE, RCE, SQLi).

## Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` 4 | CLI argument parsing with derive macros |
| `tokio` 1 | Async runtime |
| `reqwest` 0.12 | HTTP client (rustls-tls, cookies, JSON) |
| `scraper` | HTML parsing for content analysis |
| `serde` + `serde_json` + `toml` | Serialization |
| `thiserror` 2 | Error type derivation |
| `chrono` | Timestamps in findings and reports |
| `indicatif` | Progress bars and spinners |
| `colored` | Terminal color output |
| `async-trait` | Async trait support for ScanModule |
| `uuid` | Scan ID generation |
| `tracing` + `tracing-subscriber` | Structured logging |
