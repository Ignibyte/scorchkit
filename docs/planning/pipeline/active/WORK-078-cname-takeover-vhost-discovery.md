# Work Pipeline: CNAME Takeover + Virtual Host Discovery Recon

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
- **Title:** CNAME Takeover Detection and Virtual Host Discovery
- **Type:** Feature
- **Scope:** Two new recon modules. (1) CNAME takeover: resolves CNAME records for subdomains and checks if they point to deprovisioned services (GitHub Pages, Heroku, AWS S3, Azure, Shopify, etc.) that could be claimed by an attacker. (2) Virtual host discovery: brute-forces Host header values against the target IP to discover hidden virtual hosts not in public DNS.
- **Files Expected:** 4-5 files — `src/recon/cname_takeover.rs`, `src/recon/vhost.rs`, modify `src/recon/mod.rs`, tests
- **Dependencies:** Subdomain module output enhances CNAME takeover coverage. DNS resolution capability (already in dns.rs).
- **Risks:** Low for CNAME takeover. Medium for vhost — brute-force can be noisy and rate-limited; needs configurable wordlist and rate limiting.
- **Acceptance Criteria:**
  - **CNAME Takeover module:**
    - Resolves CNAME records for discovered subdomains
    - Maintains fingerprint database of vulnerable services (GitHub, Heroku, S3, Azure, Shopify, Fastly, etc.)
    - Checks CNAME targets against fingerprints (NXDOMAIN, specific error pages)
    - CWE-923 (Improper Restriction of Communication Channel), severity High
  - **Virtual Host Discovery module:**
    - Sends requests with different Host headers to target IP
    - Compares response size/status/content to baseline to detect unique vhosts
    - Uses built-in common vhost wordlist
    - Rate-limited to avoid overwhelming target
    - Informational findings for discovered vhosts
  - OWASP A05:2021 Security Misconfiguration
  - All existing tests pass, both modules have unit tests
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
