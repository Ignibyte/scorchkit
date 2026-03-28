# Report System

The report module (`src/report/`) handles outputting scan results in multiple formats.

## Files

```
report/
  mod.rs         Module declarations
  terminal.rs    Colored terminal output (implemented)
  json.rs        JSON file output (implemented)
  html.rs        HTML report generation (future)
```

## Terminal Report (`terminal.rs`)

Prints a colored, human-readable report to stdout using the `colored` crate.

### Function

```rust
pub fn print_report(result: &ScanResult)
```

### Output Structure

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  6 findings across 1 modules

    1 High           ← red
    2 Medium         ← yellow
    2 Low            ← green
    1 Info           ← blue

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  #1  [HIGH] Missing HSTS Header
  Description text...
  Target: https://example.com/
  Evidence: Header value...       ← yellow (if present)
  Fix: Add header...              ← green (if present)
  A05:2021  CWE-319               ← dimmed (if present)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scan ID: uuid
  Duration: 214ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Severity Colors

| Severity | Color |
|----------|-------|
| Critical | Red bold on white background |
| High | Red bold |
| Medium | Yellow bold |
| Low | Green bold |
| Info | Blue bold |

### Sections

1. **Summary** - total findings, count by severity, modules run/skipped
2. **Findings** - each finding with severity badge, title, description, target, evidence, remediation, OWASP/CWE
3. **Footer** - scan ID and duration

Skipped modules are listed with their skip reason (e.g., "external tool 'nmap' not found").

### Duration Formatting

- < 1 second: `"214ms"`
- < 1 minute: `"5s"`
- >= 1 minute: `"2m 30s"`

## JSON Report (`json.rs`)

Saves the full `ScanResult` as a pretty-printed JSON file.

### Functions

```rust
// Save report, returns path to saved file
pub fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf>

// Load a previously saved report
pub fn load_report(path: &Path) -> Result<ScanResult>
```

### File Naming

Reports are saved as `scorchkit-{scan_id}.json` in the configured `output_dir` (default `./reports/`). The directory is created automatically if it doesn't exist.

### JSON Structure

```json
{
  "scan_id": "uuid-v4",
  "target": {
    "raw": "https://example.com",
    "url": "https://example.com/",
    "domain": "example.com",
    "port": 443,
    "is_https": true
  },
  "started_at": "2026-03-25T21:04:36Z",
  "completed_at": "2026-03-25T21:04:36Z",
  "findings": [
    {
      "module_id": "headers",
      "severity": "high",
      "title": "Missing HSTS Header",
      "description": "...",
      "affected_target": "https://example.com/",
      "remediation": "Add header: ...",
      "owasp_category": "A05:2021 Security Misconfiguration",
      "cwe_id": 319,
      "timestamp": "2026-03-25T21:04:36Z"
    }
  ],
  "modules_run": ["headers"],
  "modules_skipped": [],
  "summary": {
    "total_findings": 6,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 2,
    "info": 1
  }
}
```

Optional fields (`evidence`, `remediation`, `owasp_category`, `cwe_id`) are omitted from JSON when `None` (via `skip_serializing_if`).

## Planned: HTML Report (`html.rs`)

Will generate a self-contained HTML file with:
- Styled finding cards with severity color coding
- Summary chart (findings by severity)
- Expandable evidence sections
- Table of contents with anchor links
- Print-friendly CSS

Implementation approach: embedded HTML template string or `minijinja` templating.
