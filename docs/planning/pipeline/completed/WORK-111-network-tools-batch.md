# Work Pipeline: Network/Infra tool batch (7 wrappers)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Status** | Complete (archived) |
| **Forge Ticket** | #111 |
| **Forge Ticket ID** | 019d8e98-a7fa-722f-aeae-edbe597ba039 |

## Phase 1-2 — PASS

7 new `ScanModule` tool wrappers under `src/tools/`, each following the canonical pattern (single-file impl, subprocess::run_tool dispatch, pure parser, parser unit tests, registered in `tools::register_modules()` and `cli::doctor::tool_specs()`):

| Module file | Tool | Probe behavior |
|-------------|------|----------------|
| `src/tools/masscan.rs` | masscan | Mass TCP port scan against `ctx.target.domain` (top 1000 ports default) |
| `src/tools/naabu.rs` | naabu | ProjectDiscovery port scanner against `ctx.target.domain` |
| `src/tools/smbmap.rs` | smbmap | SMB share enumeration; surfaces world-readable / writable shares |
| `src/tools/nxc.rs` | nxc | NetExec (crackmapexec successor); SMB protocol auth/null-session check |
| `src/tools/kerbrute.rs` | kerbrute | Kerberos user enumeration against discovered KDC; uses small built-in user list |
| `src/tools/ssh_audit.rs` | ssh-audit | SSH server hardening check on host:22 |
| `src/tools/onesixtyone.rs` | onesixtyone | SNMP scanner with `public`/`private` community list |

All use `requires_external_tool() = true` so absent tools are skipped gracefully.

## Phase 3-6 — PASS (2026-04-15)

### Files created
- `src/tools/masscan.rs` (greppable-output parser)
- `src/tools/naabu.rs` (JSON-Lines parser)
- `src/tools/smbmap.rs` (table parser, READ/WRITE classification)
- `src/tools/nxc.rs` (text parser, null-session detection)
- `src/tools/kerbrute.rs` (text parser + built-in 10-name user list + tempfile)
- `src/tools/ssh_audit.rs` (JSON parser, weak-algo aggregation)
- `src/tools/onesixtyone.rs` (text parser + built-in 5-entry community list + tempfile)
- `docs/tools/{masscan,naabu,smbmap,nxc,kerbrute,ssh-audit,onesixtyone}.md` stubs

### Files modified
- `Cargo.toml` — add `tempfile = "3"` to runtime deps (was dev-only)
- `src/tools/mod.rs` — declare 7 new modules + register in `register_modules()`
- `src/cli/doctor.rs` — 7 new `ToolSpec` entries with install hints
- `CHANGELOG.md` — WORK-111 bullet under `[Unreleased] / Added`

### Quality gates
- `cargo fmt` ✓
- `cargo clippy -- -D warnings` ✓ (5 fixes during iteration: smbmap parser logic bug surfaced by tests, doc_markdown backticks, useless format!, let-else for tempfile errors)
- `cargo test` ✓ — **594 passed** (+52 vs 542 baseline)
- Lib + tools build clean across default/mcp/infra
- No new advisories