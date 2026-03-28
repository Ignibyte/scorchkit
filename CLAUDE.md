# Forge Integration

This project is connected to a Forge RLM server for centralized knowledge management.

> **[CONSTITUTION.md](CONSTITUTION.md)** — Immutable rules governing all phases. Read it. Follow it. No exceptions.

## Commands (`.claude/commands/`)

All work runs in the user's conversation via slash commands. **No agent spawning.** Each phase command independently verifies the previous phase's work before proceeding.

### Pipeline Commands

| Command | Phase | Purpose |
|---------|-------|---------|
| **/work** | 1 | **Entry point** — Creates pipeline doc + Forge ticket, classifies work |
| **/design** | 2 | Architecture & design blueprint (file manifest, types, testing strategy) |
| **/implement** | 3 | Write code following the design, run quality gates |
| **/validate** | 4 | Code review + test execution — independently re-runs quality gates |
| **/verify** | 5 | Full test suite — catches regressions |
| **/complete** | 6 | Docs, changelog, AAR, knowledge recording, pipeline archival |

### Other Commands

| Command | Purpose |
|---------|---------|
| **/commit** | Ship it — full validation gauntlet, create branch, commit, push, PR via `gh` |
| **/brainstorm** | Research & Q&A — non-pipeline exploration (Constitution §16) |
| **/seek** | Adversarial code audit — finds security issues, dead code, smells |
| **/sync** | Synchronize command files from Forge MCP server |
| **/forge-connect** | Register a project with Forge and configure MCP |
| **/contribute** | Push local pipeline enhancements back to Forge for admin review |

### Workflow

```
/work "Add MCP server transport"       → Creates pipeline, presents spec
/design                                 → Designs architecture, file manifest
/implement                              → Writes code, runs fmt/clippy/test
/validate                               → Reviews code, re-runs all quality gates
/verify                                 → Full test suite
/complete                               → Docs, changelog, archive pipeline
/commit                                 → Full validation, branch, commit, push, PR
```

Each command verifies the previous phase before starting. `/validate` re-runs `cargo fmt`, `cargo clippy`, and `cargo test` regardless of what `/implement` claimed. `/verify` re-runs everything regardless of what `/validate` claimed. Trust is verified, not assumed.

## Hook Enforcement

Hooks enforce the Constitution automatically. They fire on tool use and conversation end — no way to bypass them.

### PreToolUse Hooks (Block Before Writing)

| Hook | Trigger | What It Prevents |
|------|---------|-----------------|
| `enforce-agent-scope.sh` | Write\|Edit | Writing files outside the current phase's scope |
| `enforce-docs-before-code.sh` | Write\|Edit | Writing code before calling `search-architecture-docs` (§16) |

### Stop Hooks (Block Before Finishing)

| Hook | What It Enforces |
|------|-----------------|
| `enforce-completion.sh` | Forge MCP calls: bootstrap, recall, learn (universal); architecture-set (Phase 2); save-generation-trace (Phase 6); Bash execution (Phases 3-5) |
| `enforce-quality.sh` | `cargo fmt`, `cargo clippy`, doc comments, banned ` ```ignore ` doctests, `#[allow]` without justification, `#[ignore]` on tests, crate-level suppressions |
| `enforce-sast.sh` | Semgrep security rules, `cargo audit` dependency vulnerabilities, `cargo deny` license compliance |
| `enforce-tests-ran.sh` | `cargo test` actually executed (transcript verification) |
| `enforce-pipeline-completion.sh` | Completed pipelines archived from `active/` to `completed/` |
| `enforce-pipeline-checklist.sh` | Final pipeline checklist at Phase 6 — code quality, knowledge recording, documentation |

## ScorchKit

Rust web application security testing toolkit and orchestrator. 41 modules (20 built-in + 21 external tool wrappers), Claude AI integration, 4 output formats, proxy support, authenticated scanning, scan profiles, scan diffing.

### Quick Reference

```
cargo build                                       # Build
cargo test                                        # Run tests (21 tests)
cargo run -- run <url>                            # Scan a target
cargo run -- run <url> --profile quick            # Fast scan (4 modules)
cargo run -- run <url> --analyze                  # Scan + AI analysis
cargo run -- run <url> --proxy http://127.0.0.1:8080  # Through Burp
cargo run -- analyze <report.json> -f remediate   # AI remediation guide
cargo run -- diff baseline.json current.json      # Compare two scans
cargo run -- doctor                               # Check tool installation
cargo run -- modules --check-tools                # List all 41 modules
cargo run -- completions bash                     # Shell completions
cargo clippy                                      # Lint (0 warnings)
```

### Project Structure

```
src/
  main.rs              Entry point (tokio runtime, tracing)
  lib.rs               Module tree
  engine/              Core: Target, Finding, Severity, ScanModule trait, ScanContext, ScanResult, ScorchError
  cli/                 Clap CLI (args.rs), command dispatch (runner.rs), shell completions, doctor
  config/              TOML: ScanConfig (proxy, scope, rate_limit), AuthConfig, ToolsConfig, AiConfig, ReportConfig
  runner/              Orchestrator (concurrent via semaphore), subprocess mgmt, progress spinners
  recon/               headers, tech, discovery, subdomain, crawler, waf
  scanner/             ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive, api-schema, ratelimit
  tools/               nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan
  ai/                  Claude CLI integration (analyst, prompts, response parser)
  report/              terminal, json, html, sarif, diff
tests/
  cli.rs               CLI integration tests (11 tests)
docs/
  architecture/        System design docs
  modules/             Individual docs for each built-in module
  tools/               Individual docs for each external tool wrapper
  tools-checklist.md   Installation guide for all external tools
  planning/pipeline/   Pipeline documents (active/, completed/, templates/)
```

### Key Conventions

- **Module naming**: `engine/` not `core/` (avoids `std::core` shadow)
- **Error handling**: `engine::error::Result<T>` with `ScorchError` via `thiserror`
- **No unwrap/expect**: denied by clippy. No warnings.
- **Async**: tokio, concurrent module execution via semaphore
- **Module pattern**: implement `ScanModule` trait, register in `register_modules()`. Template: `recon/headers.rs`
- **Finding builder**: `Finding::new(...).with_evidence(...).with_remediation(...).with_owasp(...).with_cwe(...)`
- **Proxy**: reqwest `.proxy()` support, configured via `--proxy` flag or `config.toml`
- **Cookie jar**: `cookie_store(true)` on HTTP client for session persistence
- **Profiles**: quick (headers, tech, ssl, misconfig), standard (all built-in), thorough (everything)
- **Scope**: `--scope` and `--exclude` flags, `scope_include`/`scope_exclude` in config

## Workflow

Every coding session should follow this flow:

1. **Bootstrap** — Call `bootstrap` to load project context
2. **Check Tickets** — Call `ticket-next` to pick up highest-priority work
3. **Recall** — Call `recall` with agent name and phase for targeted knowledge
4. **Search Architecture Docs** — Call `search-architecture-docs` before writing code
5. **Build** — Implement using architecture decisions and recalled knowledge
6. **Learn** — Call `learn` to record lessons
7. **Report Failures** — Call `report-failure` for issues encountered
8. **Update Tickets** — Call `ticket-update` to transition status
9. **Record Decisions** — Call `architecture-set` for architectural decisions

## Available MCP Tools

### Context
- `bootstrap` — Project context refresh
- `recall` — Primary knowledge retrieval
- `search-knowledge` — Full-text cross-entity search

### Knowledge
- `learn` — Record a new lesson
- `report-failure` — Report a failure
- `save-generation-trace` — Save generation trace data
- `list-failures` / `list-lessons` / `list-prevention-rules` / `list-distilled-lessons` / `list-patterns`

### Tickets
- `ticket-create` / `ticket-list` / `ticket-get` / `ticket-update`
- `ticket-claim` / `ticket-next` / `ticket-close` / `ticket-comment`

### Architecture
- `architecture-set` / `architecture-get` / `architecture-list`

### Documentation
- `search-docs` — Search framework docs
- `search-architecture-docs` — Search project-level architecture documentation
- `search-patterns` — Search golden example code
- `example-feedback` — Report golden example effectiveness
- `upload-golden-example` — Upload successful code patterns

### Pipeline
- `pipeline-status` — View pipeline ticket status
- `pipeline-advance` — Advance a pipeline ticket
- `pipeline-context` — Get phase-matched context

### Contributions
- `compare-pipeline-hashes` — Compare local files against canonical
- `contribute-pipeline` — Submit enhancements to Forge

### System
- `health` — System health check
- `stats` — Project-specific KPIs

## Documentation Index

- [Architecture Overview](docs/architecture/overview.md)
- [Module Development Guide](docs/architecture/modules.md)
- [Built-in Module Docs](docs/modules/) (20 files)
- [Tool Wrapper Docs](docs/tools/) (21 files)
- [Tools Installation Guide](docs/tools-checklist.md)
