# Work Pipeline: Custom Rule Templates — YAML Response Pattern Rules

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Quality gates |
| **Blocked** | No |
| **Forge Ticket** | #96 |
| **Forge Ticket ID** | 019d8cb9-815a-726e-9e50-d69b013abbe2 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec
- **Title:** Custom rule templates: YAML-based response pattern rules
- **Type:** Feature
- **Scope:** Add a YAML-based custom rule engine so users can define HTTP response pattern rules without writing Rust code. Rules live in `rules/*.yaml` files and are loaded by a new built-in `RuleEngineModule`. Each rule has request config (method/path/headers), response matchers (body regex, header regex, status), and a finding template. Complements existing TOML command plugins (`src/runner/plugin.rs`) which wrap external CLIs.
- **Files Expected:** ~3 (new `src/runner/rule_engine.rs`, new `rules/examples/` dir, config integration)
- **Dependencies:** ScanModule trait, ScanContext, Finding builder, `regex` crate (likely already present), `serde_yaml` (may be new)
- **Risks:**
  - New dependency: `serde_yaml` (small, well-maintained)
  - Regex DoS from user-provided patterns — use regex crate (not regex_fancy) which has linear-time guarantees
  - Rule loading errors should be warnings, not fatal
- **Acceptance Criteria:**
  - `src/runner/rule_engine.rs` with `RuleDef` type (YAML schema) and `RuleEngineModule: ScanModule`
  - Rules directory is configurable via `config.scan.rules_dir` (like plugins_dir)
  - Module registers in `all_modules()` alongside built-ins
  - Pattern matching: body regex, header regex, status code match
  - Finding template: title, severity, description, remediation with `{match}`/`{target}` placeholders
  - 2-3 example rule YAML files in `rules/examples/`
  - Tests for YAML parsing, pattern matching, finding construction

### Preflight Results
| Check | Status |
|-------|--------|
| All checks | OK (453 tests, hooks 8/8) |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- Re-read pipeline docs after context continuation
- Test edge cases for regex — malformed rules, unicode, empty bodies

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context
2. **Recall** — `recall(agent, phase, component_types)`
3. **Learn** — `learn(summary, topic, component_types)` to record lessons
4. **Search** — `search-architecture-docs` before writing code

---

## Phase 2: Design
**Command:** /design
**Status:** Not Started

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started

## Phase 5: Verify
**Command:** /verify
**Status:** Not Started

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
