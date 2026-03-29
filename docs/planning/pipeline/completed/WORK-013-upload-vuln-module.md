# Work Pipeline: File Upload Vulnerability Testing Module

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` for Phase 4 |
| **Blocked** | No |
| **Forge Ticket** | #13 |
| **Forge Ticket ID** | 019d3a83-6e90-7106-ae2e-54c72917d6e0 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** File upload vulnerability testing module
- **Type:** Feature
- **Scope:** New built-in scanner module (`scanner/upload.rs`) that detects file upload vulnerabilities. Discovers upload forms via HTML parsing (file input elements, multipart forms), then submits test payloads to probe for: unrestricted file type acceptance (PHP, JSP, ASP, etc.), double extension bypass (.php.jpg), Content-Type mismatch (image Content-Type with script body), polyglot files (GIF89a header + PHP payload), null byte injection in filenames, path traversal in filenames (../../etc), and oversized file handling. Does NOT attempt upload-then-execute verification (would require knowing the upload destination path) — focuses on whether the server accepts dangerous uploads.
- **Files Expected:** ~2 files (1 new scanner module `scanner/upload.rs`, modification to `scanner/mod.rs`)
- **Dependencies:** Existing `ScanModule` trait, `ScanContext` with `http_client`, `reqwest` multipart support (already a dependency), `scraper` crate for HTML form parsing (already used by SSRF, XSS modules)
- **Risks:**
  - Upload endpoints vary wildly across applications — form-based, API-based, drag-and-drop JS
  - False positives: server accepting a file doesn't necessarily mean it's stored/executed
  - Multipart form construction must match the target's expected field names
  - Some targets may rate-limit or block after multiple upload attempts
- **Acceptance Criteria:**
  - `UploadModule` in `scanner/upload.rs` implements `ScanModule`
  - Discovers upload forms via HTML parsing (`<input type="file">`)
  - Tests: unrestricted file types, double extensions, Content-Type mismatch, polyglot payloads, null byte filenames, path traversal filenames
  - Pure functions for payload generation (testable without HTTP)
  - Graceful no-op when no upload forms are found
  - Unit tests for form detection and payload generation
  - `cargo test` passes with no regressions
  - `cargo clippy` clean, `cargo fmt` clean
  - Registered as 22nd built-in scanner module

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0, rustc 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 78 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap first (lesson from auth/misconfig boundary)

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
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Architecture

**Approach:**
New built-in scanner module `scanner/upload.rs` implementing `ScanModule`. Two-phase approach:

1. **Discovery** — Fetch the target URL, parse HTML with `scraper` to find `<form>` elements containing `<input type="file">`. Extract the form's `action` URL, `method`, `enctype`, and the file input's `name` attribute. This reuses the same `scraper` HTML parsing pattern used by CSRF, XSS, injection, and SSRF modules.

2. **Testing** — For each discovered upload form, submit a series of test payloads via `reqwest::multipart::Form`. Each payload tests a different bypass technique. The server's response (status code, body content) determines whether the upload was accepted or rejected.

**Key Design Decisions:**

- **Add `multipart` feature to reqwest** — Required for `reqwest::multipart::Form` and `reqwest::multipart::Part`. This is a feature flag on an existing dependency, not a new crate. Minimal impact — only enables multipart encoding support.
- **Discovery via HTML forms only** — Detects `<form enctype="multipart/form-data">` and forms containing `<input type="file">`. Does NOT detect JavaScript-based uploaders (dropzone, etc.) — those require browser rendering which ScorchKit doesn't have. This is the same limitation as the CSRF module's form detection.
- **Acceptance heuristic** — A 200/201/302 response with no error keywords in the body suggests the upload was accepted. This is a heuristic, not proof of storage/execution. Each accepted upload is a finding with appropriate severity and caveats in the description.
- **Pure payload generation** — All test payloads (filenames, bodies, content types) are generated by pure functions. The upload submission is a thin async wrapper. This follows the auth module pattern of maximizing testable pure logic.

**Upload Test Payloads:**
| # | Test | Filename | Content-Type | Body | Severity | CWE |
|---|------|----------|-------------|------|----------|-----|
| 1 | PHP upload | `test.php` | `application/x-php` | `<?php echo 'scorchkit'; ?>` | Critical | 434 |
| 2 | JSP upload | `test.jsp` | `application/octet-stream` | `<% out.println("scorchkit"); %>` | Critical | 434 |
| 3 | Double extension | `test.php.jpg` | `image/jpeg` | `<?php echo 'scorchkit'; ?>` | High | 434 |
| 4 | Content-Type mismatch | `test.php` | `image/png` | `<?php echo 'scorchkit'; ?>` | High | 434 |
| 5 | Polyglot GIF+PHP | `test.gif` | `image/gif` | `GIF89a<?php echo 'scorchkit'; ?>` | High | 434 |
| 6 | Null byte | `test.php%00.jpg` | `image/jpeg` | `<?php echo 'scorchkit'; ?>` | High | 434 |
| 7 | Path traversal | `../../test.php` | `application/x-php` | `<?php echo 'scorchkit'; ?>` | Critical | 22 |
| 8 | SVG XSS | `test.svg` | `image/svg+xml` | `<svg onload="alert(1)">` | Medium | 79 |
| 9 | HTML upload | `test.html` | `text/html` | `<script>alert(1)</script>` | Medium | 79 |

**Form Discovery Data Structure:**
```rust
struct UploadForm {
    action_url: String,       // Resolved form action URL
    field_name: String,       // Name of the file input field
    other_fields: Vec<(String, String)>,  // Other form fields (hidden inputs)
}
```

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/upload.rs` | Create | `UploadModule` implementing `ScanModule` — form discovery + upload payload testing |
| 2 | `src/scanner/mod.rs` | Modify | Add `mod upload;` and register `UploadModule` |
| 3 | `Cargo.toml` | Modify | Add `"multipart"` to reqwest features |

**Type and Trait Changes:**

Internal types in `upload.rs`:
- `UploadForm` — parsed upload form metadata (action URL, field name, hidden fields)
- `UploadPayload` — test payload with filename, content_type, body, description, severity, CWE
- Pure functions: `discover_upload_forms()` (HTML → Vec<UploadForm>), `generate_upload_payloads()` (→ Vec<UploadPayload>)

No trait changes. No modifications to `ScanModule`, `ScanContext`, or public types.

**Error Handling Strategy:**
- `ScorchError::Http` for fetch failures (existing variant, `?` propagation)
- Multipart submission failures → skip payload gracefully (target may reject specific uploads)
- No new error variants needed

**Testing Strategy:**
- Unit tests in `scanner/upload.rs` (`#[cfg(test)] mod tests`):
  - `discover_upload_forms()` against sample HTML with various form structures
  - `generate_upload_payloads()` produces all 9 payload types
  - Payload content verification (polyglot has GIF89a header, double ext has .php.jpg, etc.)
  - Form parsing edge cases (no file input, multiple file inputs, missing action)
  - `is_upload_accepted()` heuristic against success/error response bodies
- No live integration tests (would require an upload-capable target)
- Existing `tests/cli.rs::test_modules_list` auto-verifies upload module appears

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 78+ tests pass, no regressions |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_discover_upload_forms` | `src/scanner/upload.rs` | HTML parsing finds file upload forms |
| 4 | `test_discover_no_upload_forms` | `src/scanner/upload.rs` | No false positives on non-upload forms |
| 5 | `test_generate_payloads` | `src/scanner/upload.rs` | All 9 payload types generated with correct content |
| 6 | `test_polyglot_payload` | `src/scanner/upload.rs` | GIF89a header present in polyglot |
| 7 | `test_upload_accepted_heuristic` | `src/scanner/upload.rs` | Acceptance detection on success/error bodies |
| 8 | `test_form_hidden_fields` | `src/scanner/upload.rs` | Hidden inputs extracted for form submission |
| 9 | `test_modules_list` | `tests/cli.rs` | upload appears in module listing |

**Architectural Decisions:**
- **reqwest `multipart` feature** — Adding a feature flag to an existing dep, not a new crate. Necessary because multipart/form-data encoding is the only way to submit file uploads. No alternative in the existing dep set.
- **Heuristic acceptance detection** — Cannot definitively confirm file storage without knowing the upload destination. Response analysis (status code + body keywords) is the best available signal. Findings document this limitation clearly.

### Deferred Items
- Upload-then-execute verification (requires knowing upload destination path)
- JavaScript-based uploader detection (requires browser rendering)
- API-based upload detection (JSON file upload via PUT/POST with binary body)

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** scanner

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Files Created
| File | Path |
|------|------|
| Upload vulnerability scanner | `src/scanner/upload.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/scanner/mod.rs` | Added `mod upload;` and registered `UploadModule` |
| `Cargo.toml` | Added `"multipart"` to reqwest features |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from upload.rs
- **cargo test:** Pass — 86 passed, 0 failed (was 78, +8 new upload unit tests)

### Notes
- Followed design exactly — HTML form discovery + 9 upload payloads
- Added `#[allow(clippy::too_many_lines)]` on `generate_upload_payloads()` with justification (data function: 9 structs x 10 fields)
- 8 unit tests cover: form discovery, no-false-positives, payload generation, polyglot verification, acceptance heuristic, hidden fields, action resolution, default field name
- reqwest `multipart` feature flag added to Cargo.toml (first feature flag addition to existing dep)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification
- **cargo fmt --check:** Pass
- **cargo clippy:** Pass — 0 warnings in upload.rs
- **cargo test:** Pass — 86 default, 0 failed
- **```ignore / #[ignore]:** 0
- **#[allow]:** 1 (`too_many_lines` — justified data function)
- **semgrep:** Clean

### Code Review
- Documentation: All pub items documented, //! module doc present
- Error Handling: No unwrap/expect in library code, `?` propagation, graceful `let...else` on multipart failures
- Type Design: All types Debug+Clone, no unnecessary allocations
- Safety: No unsafe, Send+Sync
- Code Quality: Iterators (filter_map, any), pure form discovery and payload generation

### Test Results
- **Default:** 86 passed (was 78, +8)
- **MCP:** 183 passed (was 175, +8)

### Regression Test Plan: 9/9 passing

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Regression Analysis
- **Phase 4 mcp count:** 183
- **Phase 5 mcp count:** 183
- **Delta:** 0
- **Regressions:** 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Self-Reflection
1. **Workarounds:** One `#[allow(too_many_lines)]` — justified data function, not a workaround.
2. **Cleanest version:** Yes — pure form discovery + payload generation, heuristic acceptance with clear caveats.
3. **Senior Rust approval:** Yes — follows existing scraper pattern, proper multipart usage, no unwrap/expect.

### CHANGELOG: v0.14.0
### Knowledge: save-generation-trace + learn recorded
