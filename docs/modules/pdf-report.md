# PDF Report Generator

**Module ID:** `pdf` | **Category:** Report | **Type:** Built-in (external tool dependency)
**Source:** `src/report/pdf.rs`

## What It Does

Generates a professional, print-optimized PDF penetration test report from scan results. The report is built by rendering a self-contained HTML template with embedded CSS, then converting it to PDF via the `weasyprint` external tool. The HTML template is a pure function (`render_pdf_html`) that is fully testable without `weasyprint` installed.

## External Dependency

| Tool | Required | Install |
|------|----------|---------|
| `weasyprint` | Yes | `pip install weasyprint` or system package manager |

The module checks for `weasyprint` on the system PATH before attempting conversion. If not found, it returns a `ScorchError::ToolNotFound` error with a clear message.

## Report Sections

The generated PDF contains 6 professional sections with page breaks between major sections:

| # | Section | Content |
|---|---------|---------|
| 1 | **Cover Page** | ScorchKit branding, target URL, scan date, scan ID, "CONFIDENTIAL" classification |
| 2 | **Executive Summary** | Total finding count, severity distribution, overall risk rating (Critical/High/Medium/Low), risk matrix table |
| 3 | **Scope & Methodology** | Target URL, scan duration, module count, profile used, tool version, PTES methodology description |
| 4 | **Risk Matrix** | Severity breakdown table (Critical through Info) with counts and descriptions |
| 5 | **Detailed Findings** | Each finding rendered as a card with severity badge, title, description, affected target, OWASP category, CWE ID, evidence, and remediation box |
| 6 | **Appendix A: Modules Executed** | Two-column list of all modules that ran during the scan |

## Risk Rating Logic

The overall risk rating is determined by the highest severity finding present:

| Condition | Rating |
|-----------|--------|
| Any critical findings | Critical |
| Any high findings (no critical) | High |
| Any medium findings (no critical/high) | Medium |
| Only low/info findings | Low |

## CLI Usage

```bash
# Generate PDF report from a scan
cargo run -- run https://example.com --format pdf

# Output is saved to the configured output directory
# Default filename: scorchkit-<scan_id>.pdf
```

The `--format pdf` flag selects the PDF reporter. The output file is written to the directory specified by `ReportConfig.output_dir`.

## How It Works

1. Checks that `weasyprint` is available on the system PATH via `which weasyprint`.
2. Creates the output directory if it does not exist.
3. Calls `render_pdf_html(result)` to produce a self-contained HTML document with embedded CSS.
4. Spawns `weasyprint - <output_path>` as a subprocess, piping the HTML into stdin.
5. Waits for completion and returns the output file path, or an error if conversion fails.

## HTML Template Details

- **Self-contained**: All CSS is embedded in a `<style>` block within the HTML -- no external stylesheets or assets.
- **Print-optimized CSS**: Uses `@page` rules for A4 page size, 2cm/2.5cm margins, and automatic page numbering in the footer.
- **Page breaks**: Major sections use `page-break-before: always` and findings use `page-break-inside: avoid`.
- **Severity color coding**: Each finding card has a colored left border matching its severity (Critical: red, High: orange-red, Medium: amber, Low: green, Info: blue).
- **HTML escaping**: All user-controlled content (target URLs, finding titles, evidence) is escaped to prevent XSS in the generated HTML.

## Error Handling

| Error | Condition |
|-------|-----------|
| `ScorchError::ToolNotFound` | `weasyprint` not found on PATH |
| `ScorchError::ToolFailed` | `weasyprint` exits with non-zero status |
| `ScorchError::Report` | Output directory cannot be created |
