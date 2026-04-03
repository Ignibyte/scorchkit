# Work Pipeline: Custom Wordlists Configuration

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 1: Plan |
| **Created** | 2026-04-03 |
| **Last Updated** | 2026-04-03 |
| **Last Command** | /work |
| **Next Step** | Human review spec, then run `/design` |
| **Blocked** | No |
| **Forge Ticket** | TBD |
| **Forge Ticket ID** | TBD |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-03
**Completed:** 2026-04-03

### Work Spec
- **Title:** Configurable Custom Wordlists
- **Type:** Feature
- **Scope:** Add wordlist configuration to `config.toml` and CLI flags. Supports per-purpose wordlists: directory brute-force, subdomain enumeration, virtual host discovery, parameter fuzzing, password lists. Modules and tool wrappers read wordlist paths from config. Ships with small default wordlists embedded in the binary, with override paths for SecLists/custom lists.
- **Files Expected:** 4-6 files — modify `src/config/types.rs` (WordlistConfig section), modify `src/cli/args.rs` (wordlist flags), modify relevant modules (discovery, vhost, etc.) to use configured wordlists, default wordlists as embedded resources, tests
- **Dependencies:** None — extends existing config system
- **Risks:** Low. Config extension pattern is well-established. Default wordlists must be small enough to embed without bloating the binary.
- **Acceptance Criteria:**
  - New `[wordlists]` section in `config.toml` with paths for each purpose
  - CLI flags: `--wordlist-dir <path>`, `--wordlist-sub <path>`, `--wordlist-vhost <path>`
  - CLI flags override config.toml values
  - Small default wordlists embedded via `include_str!` (top 1000 dirs, top 500 subdomains)
  - Discovery module uses configured directory wordlist
  - Tool wrappers (feroxbuster, ffuf, gobuster) pass wordlist path to external tools
  - Wordlist file existence validated at scan start
  - All existing tests pass, config parsing tested
  - `cargo clippy` zero warnings

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | TBD |
| Toolchain | TBD |
| Security tools | TBD |
| Hooks wired | TBD |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- TBD — recall at design phase

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
**Status:** Not Started

---

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started

---

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** Not Started

---

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
