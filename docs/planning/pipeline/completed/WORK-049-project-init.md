# Work Pipeline: Project Init with Target Fingerprinting

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 3: Implement |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` for Phase 4 |
| **Blocked** | No |
| **Forge Ticket** | #49 |
| **Forge Ticket ID** | 019d3f0f-3ed6-709d-b4d3-0f716094644e |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** Project init command with target fingerprinting
- **Type:** Feature
- **Scope:** Replace bare `init` with target-aware `init <url>` that probes target, fingerprints tech/WAF/server, checks available tools, recommends a profile, and generates tailored scorchkit.toml. Optional `--project` flag creates DB project.
- **Dependencies:** #48 (doctor --deep) — complete
- **Risks:** Medium — async HTTP probing, recon module reuse boundaries

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Architecture

**Approach:**
New `src/cli/init.rs` module with lightweight target probing. Single HTTP GET to target, parse response headers and body for tech/WAF/CMS fingerprints. Does NOT reuse recon module internals (those are coupled to ScanContext/Finding pipeline — overkill for init). Checks available tools via `doctor::is_tool_available()`. Recommends profile based on detected tech + available tools. Generates tailored TOML config with scope, profile, and comments. Backward compatible: `init` (no args) still writes default config.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/cli/init.rs` | Create | TargetFingerprint, probe_target, recommend_profile, generate_config, run_init |
| 2 | `src/cli/args.rs` | Modify | Add `target: Option<String>`, `--project`, `--database-url` to Init variant |
| 3 | `src/cli/mod.rs` | Modify | Add `pub mod init;` |
| 4 | `src/cli/runner.rs` | Modify | Update Init dispatch to call `init::run_init(...)`, remove old `init_config()` |

**Key Types:**

```rust
/// Fingerprint from probing a target URL.
struct TargetFingerprint {
    server: Option<String>,        // "Nginx/1.24", "Apache/2.4"
    technologies: Vec<String>,     // ["PHP", "jQuery", "React"]
    cms: Option<String>,           // "WordPress", "Drupal", "Joomla"
    waf: Option<String>,           // "Cloudflare", "Akamai", "AWS WAF"
    is_https: bool,
    status_code: u16,
}

/// Profile recommendation with rationale.
struct InitRecommendation {
    profile: String,               // "quick", "standard", "thorough"
    suggested_modules: Vec<String>, // ["wpscan", "nuclei", ...] 
    notes: Vec<String>,            // ["WordPress detected — wpscan recommended", ...]
    available_tool_count: usize,
    total_tool_count: usize,
}
```

**Probe Logic (single GET, ~10 detection checks):**
1. Server header → server tech (Nginx, Apache, IIS, etc.)
2. X-Powered-By → framework (PHP, Express, ASP.NET)
3. cf-ray/x-sucuri-id/x-akamai headers → WAF detection (5-6 patterns)
4. Body scan for CMS patterns: `wp-content/` → WordPress, `sites/default/` → Drupal, `media/system/` → Joomla
5. Body scan for framework patterns: `_next/` → Next.js, `__nuxt` → Nuxt, `data-reactroot` → React
6. Cookie names: PHPSESSID → PHP, JSESSIONID → Java, connect.sid → Node
7. HTTPS status from URL scheme

**Profile Recommendation Logic:**
- Count available external tools (via doctor::is_tool_available)
- If `available >= 15` → "thorough" (enough tools for deep scan)
- If `available >= 5` → "standard"
- Else → "quick" (rely on built-in modules)
- CMS-specific: WordPress → suggest wpscan; Drupal → suggest droopescan
- WAF detected → note rate limiting may be needed

**Config Generation:**
- Start from `AppConfig::default()`
- Set `scan.profile` to recommended profile
- Set `scan.scope_include` to target domain (e.g., `["*.example.com"]`)
- If WAF detected → set `scan.rate_limit = 10` (requests/sec)
- If HTTPS → leave defaults; if HTTP → note in comment
- Serialize to TOML with header comments explaining detected tech

**Storage Integration (feature-gated):**
- If `--project <name>` passed AND storage feature enabled:
  - Connect to DB via database_url or config
  - Call `projects::create_project(pool, name, desc)` where desc = fingerprint summary
  - Call `projects::add_target(pool, project_id, url, label)` where label = fingerprint summary
  - Store fingerprint as JSON in project `settings` field
- If `--project` passed WITHOUT storage feature → runtime error with build hint

**Error Handling:**
- HTTP probe failure → warn + fallback to default config (target may be unreachable)
- Config write failure → ScorchError::Io
- DB connection failure → ScorchError::Database

**Testing Strategy:**
- Unit tests for fingerprint extraction from sample headers/body (no network I/O)
- Unit tests for profile recommendation logic (given fingerprint → expected profile)
- Unit test for config generation (given fingerprint → valid TOML with expected fields)
- No integration tests that hit real URLs (would be flaky)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_fingerprint_server_nginx` | `src/cli/init.rs` | Extracts "Nginx" from Server header |
| 2 | `test_fingerprint_wordpress` | `src/cli/init.rs` | Detects WordPress from body wp-content pattern |
| 3 | `test_fingerprint_waf_cloudflare` | `src/cli/init.rs` | Detects Cloudflare from cf-ray header |
| 4 | `test_fingerprint_cookie_php` | `src/cli/init.rs` | Detects PHP from PHPSESSID cookie |
| 5 | `test_recommend_thorough` | `src/cli/init.rs` | Many tools available → thorough profile |
| 6 | `test_recommend_quick` | `src/cli/init.rs` | Few tools available → quick profile |
| 7 | `test_recommend_wordpress_modules` | `src/cli/init.rs` | WordPress fingerprint → suggests wpscan |
| 8 | `test_generate_config_has_scope` | `src/cli/init.rs` | Generated config includes target domain in scope |

**Architectural Decisions:**
- **Lightweight inline detection** instead of reusing recon modules — init is a setup command, not a scan. ScanContext/Finding pipeline is overkill. Detection patterns are a minimal subset (~20 patterns vs tech.rs's 67).
- **Single GET request** — sufficient for init fingerprinting. Multi-request probing is what the actual scan is for.
- **Async handler** — `execute()` in runner.rs is already async, so init can be async with no extra runtime setup.
- **No new deps** — uses existing reqwest (already in Cargo.toml) for the HTTP probe.

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1 (architecture decision)
- **Failures:** 0
- **Component Types:** cli, config

### Human Confirmed
- [ ] Design reviewed and confirmed

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
