# Work Pipeline: ScorchKit Agent SDK Support

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
| **Forge Ticket** | #46 |
| **Forge Ticket ID** | 019d3a8d-e1d8-703d-8083-135d925a36f1 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** ScorchKit agent SDK support for autonomous pentest operations
- **Type:** Feature
- **Scope:** Rust-side agent support infrastructure. New `src/agent/` module providing:
  1. **Agent system prompt** — PTES-based pentest methodology encoded as a const string, guiding Claude through autonomous recon → plan → scan → analyze → report workflow
  2. **AgentConfig** — Configuration struct for agent runs: authorized targets (scope rules), max scan depth, safety constraints (rate limit, evidence logging, scope enforcement)
  3. **Agent manifest generator** — Produces a JSON config file for Claude Agent SDK consumption, including MCP server connection details, system prompt, and tool permissions
  4. **CLI `agent` subcommand** — `scorchkit agent init` generates agent config, `scorchkit agent config` outputs the manifest JSON for piping to the Agent SDK
  5. Not a Python/TS package — that's downstream consumer work. This provides the Rust-side infrastructure that Agent SDK clients connect to.
- **Files Expected:** ~5 files (agent module with config/prompt/manifest, CLI handler, mod updates)
- **Dependencies:** Existing MCP server, ScopeRule from engine/scope, AppConfig
- **Risks:**
  - Agent SDK is external (Python/TS) — we can only provide the config, not control the runtime
  - Safety constraints must be well-defined since autonomous agents can cause harm
  - System prompt is critical for effective agent behavior
- **Acceptance Criteria:**
  - `AgentConfig` struct with scope, depth, safety settings
  - Agent system prompt covering PTES methodology
  - `scorchkit agent config` outputs JSON manifest for Agent SDK
  - Safety constraints documented (scope enforcement, rate limiting)
  - `cargo test` passes with no regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 172 default passed |

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

**Approach:** New `src/agent/` module providing Rust-side infrastructure for Claude Agent SDK integration. Three components: agent system prompt (PTES methodology), agent configuration (safety + scope), and manifest generator (JSON output for SDK consumption).

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/agent/mod.rs` | Create | Module root with generate_manifest() |
| 2 | `src/agent/config.rs` | Create | AgentConfig struct with safety constraints |
| 3 | `src/agent/prompt.rs` | Create | AGENT_SYSTEM_PROMPT const |
| 4 | `src/lib.rs` | Modify | Add `pub mod agent` |

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_agent_config_serialize` | `src/agent/config.rs` | JSON serialization |
| 2 | `test_agent_config_defaults` | `src/agent/config.rs` | Default values |
| 3 | `test_agent_prompt_nonempty` | `src/agent/prompt.rs` | Prompt is non-empty |
| 4 | `test_generate_manifest` | `src/agent/mod.rs` | Manifest has required fields |
| 5 | `test_manifest_includes_prompt` | `src/agent/mod.rs` | System prompt in manifest |

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Completed:** 2026-03-30
- Created: agent/mod.rs, agent/config.rs, agent/prompt.rs
- Modified: lib.rs
- Quality: fmt 0 diffs, clippy 0 new actionable, tests 287 mcp (+6)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Completed:** 2026-03-30
- Entry verification: all gates pass, no banned patterns

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Completed:** 2026-03-30
- 287 tests, 0 regressions (was 281)

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Completed:** 2026-03-30
- CHANGELOG v0.28.0, knowledge recorded, pipeline archived
