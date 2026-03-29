# Work Pipeline: Professional PDF Pentest Report Generation

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
| **Forge Ticket** | #26 |
| **Forge Ticket ID** | 019d3a84-8daf-7126-928d-74417e028216 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Professional PDF pentest report generation
- **Type:** Feature
- **Scope:** New report format (`report/pdf.rs`) that generates professional pentest reports as PDF files. Uses the existing HTML report renderer as a base template, enhanced with professional styling (executive summary, methodology, scope, risk matrix, finding detail pages with severity/CVSS/evidence/remediation/OWASP/CWE mapping). Renders HTML to PDF via an external tool — `weasyprint` (Python-based HTML-to-PDF converter, widely available). Follows the same pattern as external tool wrappers: check for tool availability, invoke via subprocess, graceful degradation if not installed. New CLI flag `--format pdf` alongside existing `terminal`, `json`, `html`, `sarif`. DOCX deferred — PDF is the primary professional deliverable.
- **Files Expected:** ~4 files (1 new report module `report/pdf.rs`, modifications to `report/mod.rs`, `cli/args.rs` for `--format pdf`, `cli/runner.rs` for PDF dispatch)
- **Dependencies:** `weasyprint` CLI (external Python tool, not a Rust crate). Existing `report/html.rs` for HTML template generation. Existing `subprocess::run_tool` for process management.
- **Risks:**
  - `weasyprint` not installed — must handle gracefully (clear error message with install instructions)
  - CSS styling for professional look — inline CSS in the HTML template
  - Large reports (many findings) may be slow to render
  - PDF quality depends on weasyprint version
- **Acceptance Criteria:**
  - `report/pdf.rs` generates professional HTML with enhanced CSS, then converts to PDF via weasyprint
  - Professional sections: executive summary, methodology, scope, risk matrix, finding details, appendices
  - CLI `--format pdf` flag works alongside existing formats
  - Graceful error when weasyprint not installed
  - Unit tests for HTML template generation (pure function, no weasyprint needed)
  - `cargo test` passes with no regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 119 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
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
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Architecture

**Approach:**
New report module `report/pdf.rs` that generates professional pentest reports as PDF files. Two-step process: (1) render an enhanced HTML template with professional CSS styling (print-optimized, professional layout with sections), (2) convert HTML to PDF via `weasyprint` CLI subprocess. The existing `report/html.rs` pattern is the template — `pdf.rs` generates a richer HTML variant with additional sections (executive summary, methodology, scope, risk matrix) and print-optimized CSS, then pipes it through weasyprint.

**Report Structure (HTML template sections):**
1. **Cover Page** — ScorchKit branding, target, date, classification
2. **Executive Summary** — High-level risk assessment, finding count by severity, overall risk rating
3. **Scope & Methodology** — Target URL, modules run, scan profile, duration
4. **Risk Matrix** — Severity distribution table (Critical/High/Medium/Low/Info with counts)
5. **Findings Detail** — Each finding as a full page: severity badge, title, description, evidence, remediation, OWASP/CWE mapping
6. **Appendix** — Module list, scan metadata, tool version

**Key Design Decisions:**

- **weasyprint as external tool** — Best HTML-to-PDF converter for print-quality output. Python-based, widely packaged (`pip install weasyprint`, `apt install weasyprint`). Uses the same `subprocess::run_tool` pattern as nmap/nuclei wrappers but with stdin piping (HTML → PDF).
- **stdin piping, not temp file** — Pipe HTML to weasyprint's stdin via `weasyprint - output.pdf`. Avoids temp file management. weasyprint supports `-` for stdin input.
- **Print-optimized CSS** — White background, black text, `@page` rules for margins/headers/footers, `page-break-before` for each finding, proper `@media print` styling. The dark-themed HTML report is for screens; the PDF report uses professional light-themed print CSS.
- **`Pdf` variant in `OutputFormat` enum** — Simple addition to existing clap enum. Dispatch in runner.rs alongside existing Json/Html/Sarif.
- **Graceful degradation** — If weasyprint is not installed, return `ScorchError::ToolNotFound` with a helpful error message including install instructions.
- **Pure `render_pdf_html()` function** — The HTML template generation is a pure function (takes `&ScanResult`, returns `String`). Testable without weasyprint. The PDF conversion is a thin subprocess wrapper.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/report/pdf.rs` | Create | `save_report()` + `render_pdf_html()` — professional HTML template + weasyprint subprocess |
| 2 | `src/report/mod.rs` | Modify | Add `pub mod pdf;` |
| 3 | `src/cli/args.rs` | Modify | Add `Pdf` variant to `OutputFormat` enum |
| 4 | `src/cli/runner.rs` | Modify | Add `Some(OutputFormat::Pdf)` dispatch arm calling `report::pdf::save_report()` |

**Type and Trait Changes:**

- `OutputFormat` enum: add `Pdf` variant (cli/args.rs)
- New function: `report::pdf::save_report(&ScanResult, &ReportConfig) -> Result<PathBuf>`
- New function: `report::pdf::render_pdf_html(&ScanResult) -> String` (pure, testable)

No new types or traits.

**Error Handling Strategy:**
- `ScorchError::ToolNotFound` if weasyprint not installed (existing variant)
- `ScorchError::ToolFailed` if weasyprint exits non-zero (existing variant)
- `ScorchError::Report` for file write failures (existing variant)
- No new error variants

**Testing Strategy:**
- Unit tests in `report/pdf.rs` (`#[cfg(test)] mod tests`):
  - `render_pdf_html()` produces valid HTML with all required sections
  - Executive summary section contains severity counts
  - Each finding rendered with evidence, remediation, OWASP/CWE
  - Risk matrix contains correct severity distribution
  - Print CSS rules present (`@page`, `@media print`)
  - Cover page contains target and date
- No integration test with weasyprint (external tool, may not be installed)
- Existing CLI tests auto-verify `Pdf` format appears in help

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 119+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_render_pdf_html_structure` | `src/report/pdf.rs` | HTML has cover, exec summary, methodology, findings, appendix |
| 4 | `test_render_pdf_html_severity_counts` | `src/report/pdf.rs` | Executive summary shows correct finding counts |
| 5 | `test_render_pdf_html_finding_details` | `src/report/pdf.rs` | Each finding has evidence, remediation, OWASP, CWE |
| 6 | `test_render_pdf_html_print_css` | `src/report/pdf.rs` | Contains @page and @media print rules |
| 7 | `test_render_pdf_html_risk_matrix` | `src/report/pdf.rs` | Risk matrix table with severity rows |
| 8 | `test_modules_list` | `tests/cli.rs` | pdf appears in --format options |

**Architectural Decisions:**
- **Separate from html.rs** — The PDF HTML template is substantially different from the screen HTML (print CSS, cover page, methodology section, risk matrix, page breaks). Not a wrapper around html.rs — it's a parallel implementation optimized for print.
- **weasyprint over typst/pandoc** — weasyprint produces the highest quality HTML-to-PDF output. typst requires learning a new markup language. pandoc requires markdown intermediate format. weasyprint accepts HTML directly — reuses our HTML templating pattern.

### Deferred Items
- DOCX generation (separate ticket — could use pandoc for HTML → DOCX)
- Custom report templates (user-provided CSS/HTML templates)
- Company logo/branding customization

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** report, cli

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
- Files created: `src/report/pdf.rs`
- Files modified: `src/report/mod.rs`, `src/cli/args.rs`, `src/cli/runner.rs`
- Quality: fmt clean, clippy clean (0 warnings), 127 default tests (+8)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
- MCP: 224 passed (was 216, +8). Semgrep clean. All regression tests passing.

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
- Phase 4→5 mcp 224→224, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS

### Self-Reflection
1. **Workarounds:** #[allow(too_many_lines)] on render_pdf_html — justified template function with 6 sections.
2. **Cleanest version:** Yes — pure HTML template function, subprocess stdin piping, professional print CSS.
3. **Senior Rust approval:** Yes — no unwrap in library (unwrap_or used for path display), proper error handling.

### CHANGELOG: v0.19.0
### Knowledge: save-generation-trace + learn recorded
