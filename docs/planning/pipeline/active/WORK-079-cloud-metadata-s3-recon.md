# Work Pipeline: Cloud Metadata + S3 Bucket Enumeration Recon

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
- **Title:** Cloud Metadata Detection and S3/GCS Bucket Enumeration
- **Type:** Feature
- **Scope:** Two new recon modules. (1) Cloud metadata: detects SSRF vectors to cloud metadata endpoints (AWS `169.254.169.254`, GCP, Azure, DigitalOcean), checks for IMDSv1 exposure, and identifies cloud provider from headers/responses. (2) S3/GCS bucket enumeration: derives potential bucket names from the target domain, checks for public listing, write access, and common misconfigurations.
- **Files Expected:** 4-5 files — `src/recon/cloud_metadata.rs`, `src/recon/bucket_enum.rs`, modify `src/recon/mod.rs`, tests
- **Dependencies:** None — standalone recon modules
- **Risks:** Low. Cloud metadata detection checks for indicators in existing SSRF module findings. Bucket enum uses only HEAD/GET requests to public endpoints.
- **Acceptance Criteria:**
  - **Cloud Metadata module:**
    - Checks for cloud provider indicators in response headers (Server, X-Amz-*, X-Goog-*)
    - Tests SSRF to metadata endpoints via known parameter injection points
    - AWS: `http://169.254.169.254/latest/meta-data/`
    - GCP: `http://metadata.google.internal/computeMetadata/v1/`
    - Azure: `http://169.254.169.254/metadata/instance`
    - Detects IMDSv1 (no token required) vs IMDSv2
    - CWE-918 (SSRF) + CWE-200 (Info Exposure), severity Critical
  - **Bucket Enumeration module:**
    - Derives bucket names from domain: `{domain}`, `{domain}-assets`, `{domain}-backup`, `{domain}-dev`, etc.
    - Tests S3: `https://{bucket}.s3.amazonaws.com/`
    - Tests GCS: `https://storage.googleapis.com/{bucket}/`
    - Checks: public listing (XML directory), public read, public write
    - CWE-284 (Improper Access Control), severity High for public write, Medium for public read
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
