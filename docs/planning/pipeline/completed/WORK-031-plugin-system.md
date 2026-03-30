# Work Pipeline: Plugin System for User-Defined Scan Modules

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #31 |
| **Forge Ticket ID** | 019d3a84-d2d9-7072-8719-0044d07550db |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** Plugin system for user-defined scan modules
- **Type:** Feature
- **Scope:** Script-based plugin system (like nuclei templates) where users define custom scan modules via YAML config files. Each plugin specifies: id, name, category, description, command, args, output_format (json/text), and severity mapping. `PluginModule` struct implements `ScanModule` trait — runs the command via `subprocess::run_tool()` and parses output. Plugin loader discovers `.yaml` files from a configurable plugins directory. No WASM or FFI — shell commands keep it simple and accessible.
- **Files Expected:** ~4 files (plugin module, plugin loader, config update, orchestrator integration)
- **Dependencies:** Existing `ScanModule` trait, `subprocess::run_tool()`, `Finding` builder
- **Risks:**
  - YAML parsing needs a serde_yaml dependency (check if already present or use toml instead)
  - Shell command execution has security implications — plugins run arbitrary commands
  - Plugin validation: malformed YAML should fail gracefully, not crash
- **Acceptance Criteria:**
  - `PluginDef` struct deserializes from YAML/TOML config files
  - `PluginModule` implements `ScanModule` trait
  - Plugin loader discovers and registers plugins from a directory
  - CLI `--plugins-dir` flag to specify plugin directory
  - Plugins run via `subprocess::run_tool()` and produce `Finding` objects
  - `cargo test` passes with no regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 166 default passed |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=[...])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` for project patterns before writing code

These are enforced by `enforce-completion.sh`. Skipping them blocks the conversation from ending.

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Completed:** 2026-03-30

### Architecture

**Approach:** TOML-based plugin definitions (not YAML — avoids new dep, consistent with config.toml). Each plugin is a `.toml` file defining metadata + command + output parsing. `PluginModule` implements `ScanModule` by running the command via `subprocess::run_tool()` and parsing output based on `output_format`.

**Plugin Definition Format:**
```toml
id = "my-scanner"
name = "My Custom Scanner"
description = "Custom security check"
category = "scanner"  # or "recon"
command = "my-tool"
args = ["--json", "--quiet", "{target}"]
timeout_seconds = 120
output_format = "json_lines"  # or "lines" or "json"
severity = "medium"  # default severity for findings
```

**Key Components:**
- `PluginDef` — deserialized from TOML, validated
- `PluginModule` — wraps PluginDef, implements ScanModule
- `load_plugins(dir)` — discovers .toml files, returns Vec<Box<dyn ScanModule>>
- `{target}` placeholder in args replaced with actual target at runtime
- Config: `plugins_dir: Option<PathBuf>` in ScanConfig

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/runner/plugin.rs` | Create | PluginDef, PluginModule, load_plugins() |
| 2 | `src/runner/mod.rs` | Modify | Add `pub mod plugin` |
| 3 | `src/runner/orchestrator.rs` | Modify | Load plugins in register_default_modules |
| 4 | `src/config/types.rs` | Modify | Add plugins_dir to ScanConfig |

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_plugin_def_deserialize` | `src/runner/plugin.rs` | TOML parsing |
| 2 | `test_plugin_module_metadata` | `src/runner/plugin.rs` | ScanModule trait methods |
| 3 | `test_plugin_arg_substitution` | `src/runner/plugin.rs` | {target} replacement |
| 4 | `test_plugin_parse_lines` | `src/runner/plugin.rs` | Line-based output parsing |
| 5 | `test_plugin_parse_json` | `src/runner/plugin.rs` | JSON output parsing |
| 6 | `test_load_plugins_empty_dir` | `src/runner/plugin.rs` | Empty dir returns empty vec |

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Completed:** 2026-03-30
- Created: runner/plugin.rs (PluginDef, PluginModule, load_plugins)
- Modified: runner/mod.rs, runner/orchestrator.rs, config/types.rs
- Quality: fmt 0 diffs, clippy 0 new actionable, tests 281 mcp (+6)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Completed:** 2026-03-30
- Entry verification: all gates pass, semgrep clean, no banned patterns

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Completed:** 2026-03-30
- 281 tests, 0 regressions (was 275)

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Completed:** 2026-03-30
- CHANGELOG v0.27.0, knowledge recorded, pipeline archived
