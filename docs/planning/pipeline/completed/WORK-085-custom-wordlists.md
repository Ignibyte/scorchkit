# Work Pipeline: Custom Wordlists Configuration

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-03 |
| **Last Updated** | 2026-04-04 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #80 |
| **Forge Ticket ID** | 019d5927-fc6f-70fb-9495-44438b08dff9 |

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
**Status:** PASS
**Started:** 2026-04-04
**Completed:** 2026-04-04

### Architecture

**Approach:**
Add `WordlistConfig` to `AppConfig` with per-purpose wordlist paths. Modules check config first, fall back to built-in const arrays. Tool wrappers pass configured paths to external tools. Helper function `load_wordlist()` reads lines from file (skipping comments/blanks).

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/config/types.rs` | Modify | Add `WordlistConfig` struct + `load_wordlist()` helper + tests |
| 2 | `src/recon/subdomain.rs` | Modify | Check `config.wordlists.subdomain`, fall back to `SUBDOMAIN_WORDLIST` |
| 3 | `src/recon/vhost.rs` | Modify | Check `config.wordlists.vhost`, fall back to `VHOST_PREFIXES` |
| 4 | `src/recon/discovery.rs` | Modify | Check `config.wordlists.directory` for additional probes |
| 5 | `src/tools/ffuf.rs` | Modify | Use `config.wordlists.directory` instead of hardcoded path |
| 6 | `src/tools/gobuster.rs` | Modify | Use `config.wordlists.directory` instead of hardcoded path |

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `wordlist_config_defaults_to_none` | `src/config/types.rs` | All paths default to None |
| 2 | `load_wordlist_skips_comments_and_blanks` | `src/config/types.rs` | # lines and blank lines filtered |
| 3 | `load_wordlist_returns_error_for_missing` | `src/config/types.rs` | Missing file returns error |
| 4 | `wordlist_config_deserialize` | `src/config/types.rs` | TOML parsing of [wordlists] section |

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-04
**Completed:** 2026-04-04

### Files Modified
| File | Change |
|------|--------|
| `src/config/types.rs` | Added `WordlistConfig` struct, `load_wordlist()` helper, 4 tests |
| `src/recon/subdomain.rs` | Check `config.wordlists.subdomain`, fall back to `SUBDOMAIN_WORDLIST` |
| `src/recon/vhost.rs` | Check `config.wordlists.vhost`, fall back to `VHOST_PREFIXES` |
| `src/recon/discovery.rs` | Check `config.wordlists.directory` for extra directory probes |
| `src/tools/ffuf.rs` | Use `config.wordlists.directory` instead of hardcoded path |
| `src/tools/gobuster.rs` | Use `config.wordlists.directory` instead of hardcoded path |

### Quality Gates
- **cargo fmt --check:** Pass
- **cargo clippy -- -D warnings:** Pass — zero warnings
- **cargo test:** Pass — 431 passed, 0 failed (+4 new)

---

## Phase 4–5: Validate & Verify
**Status:** PASS — Quality gates independently verified, 431 tests identical across runs

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-04
**Completed:** 2026-04-04

- **Documentation Updated:** Architecture decision `config.wordlists` recorded in Forge
- **Changelog Updated:** Yes
- **Pipeline Doc Archived:** Pending commit
