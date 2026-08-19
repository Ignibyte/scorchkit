# Report System

The report module (`src/report/`) handles outputting scan results in multiple formats.

## Files

```
report/
  mod.rs         Module declarations
  terminal.rs    Colored terminal output (implemented)
  json.rs        JSON file output (implemented)
  html.rs        Self-contained HTML report (implemented)
  pdf.rs         Print-oriented assessment report (implemented)
  sarif.rs       SARIF 2.1.0 output (implemented)
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
  Evidence: Header value...       ← yellow (if present, already redacted)
  Agent analysis [provider/model]  ← separately labeled (if attached)
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

Optional compatibility fields (`evidence`, `remediation`, `owasp_category`, `cwe_id`) are omitted
when absent. Every finding also carries its canonical `scorchkit.finding/v2` companion with typed
location, scanner provenance, stable identity, correlation keys, redacted evidence records, and
separately labeled agent analysis. Legacy report JSON without that companion is upgraded when read.

## SARIF report (`sarif.rs`)

SARIF uses typed source/runtime/package/artifact locations and writes the stable finding identity to
`partialFingerprints.scorchkitFinding/v2`. Redacted evidence, scanner provenance, correlation keys,
and labeled agent analysis are placed in namespaced result properties. Evidence content is never a
fingerprint.

## HTML and PDF reports

The human-readable reports generate:
- Styled finding cards with severity color coding
- Summary chart (findings by severity)
- Redacted evidence and separately labeled agent-analysis sections
- Print-friendly CSS
