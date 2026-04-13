use std::fmt::Write;
use std::path::PathBuf;

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::scan_result::ScanResult;

/// Save a scan result as a self-contained HTML file.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the file cannot be written.
pub fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf> {
    let output_dir = &config.output_dir;
    std::fs::create_dir_all(output_dir)?;

    let filename = format!("scorchkit-{}.html", result.scan_id);
    let path = output_dir.join(&filename);

    let html = render_html(result);
    std::fs::write(&path, html)?;

    Ok(path)
}

/// Render the findings section of the HTML report.
fn render_findings_html(result: &ScanResult) -> String {
    let mut findings_html = String::new();
    for (i, f) in result.findings.iter().enumerate() {
        let sev_class = f.severity.to_string();
        let evidence = f.evidence.as_deref().unwrap_or("");
        let remediation = f.remediation.as_deref().unwrap_or("");
        let owasp = f.owasp_category.as_deref().unwrap_or("");
        let cwe = f.cwe_id.map_or(String::new(), |c| format!("CWE-{c}"));
        // JUSTIFICATION: confidence is 0.0–1.0, well within u8 range
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let confidence_pct = (f.confidence * 100.0) as u8;

        let _ = write!(
            findings_html,
            r#"<div class="finding {sev_class}">
  <div class="finding-header">
    <span class="finding-num">#{num}</span>
    <span class="severity-badge {sev_class}">{severity}</span>
    <span class="confidence-badge">{confidence}%</span>
    <span class="finding-title">{title}</span>
  </div>
  <p class="finding-desc">{desc}</p>
  <div class="finding-meta">
    <div><strong>Target:</strong> {target}</div>
    {evidence_html}
    {remediation_html}
    <div class="tags">{owasp} {cwe}</div>
  </div>
</div>
"#,
            num = i + 1,
            severity = f.severity.to_string().to_uppercase(),
            confidence = confidence_pct,
            title = html_escape(&f.title),
            desc = html_escape(&f.description),
            target = html_escape(&f.affected_target),
            evidence_html = if evidence.is_empty() {
                String::new()
            } else {
                format!(
                    "<div><strong>Evidence:</strong> <code>{}</code></div>",
                    html_escape(evidence)
                )
            },
            remediation_html = if remediation.is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"remediation\"><strong>Fix:</strong> {}</div>",
                    html_escape(remediation)
                )
            },
        );
    }
    findings_html
}

fn render_html(result: &ScanResult) -> String {
    let s = &result.summary;
    let findings_html = render_findings_html(result);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScorchKit Report - {scan_id}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ color: #f85149; margin-bottom: 0.5rem; }}
  h2 {{ color: #c9d1d9; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1rem 0 2rem; flex-wrap: wrap; }}
  .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem 1.5rem; min-width: 100px; text-align: center; }}
  .summary-card .count {{ font-size: 2rem; font-weight: bold; }}
  .summary-card.critical .count {{ color: #f85149; }}
  .summary-card.high .count {{ color: #f85149; }}
  .summary-card.medium .count {{ color: #d29922; }}
  .summary-card.low .count {{ color: #3fb950; }}
  .summary-card.info .count {{ color: #58a6ff; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 1rem; padding: 1rem 1.5rem; }}
  .finding.critical {{ border-left: 4px solid #f85149; }}
  .finding.high {{ border-left: 4px solid #f85149; }}
  .finding.medium {{ border-left: 4px solid #d29922; }}
  .finding.low {{ border-left: 4px solid #3fb950; }}
  .finding.info {{ border-left: 4px solid #58a6ff; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }}
  .finding-num {{ color: #8b949e; font-size: 0.9rem; }}
  .severity-badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
  .severity-badge.critical {{ background: #f85149; color: #fff; }}
  .severity-badge.high {{ background: #da3633; color: #fff; }}
  .severity-badge.medium {{ background: #d29922; color: #000; }}
  .severity-badge.low {{ background: #3fb950; color: #000; }}
  .severity-badge.info {{ background: #58a6ff; color: #000; }}
  .confidence-badge {{ padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; background: #30363d; color: #8b949e; }}
  .finding-title {{ font-weight: 600; }}
  .finding-desc {{ color: #8b949e; margin-bottom: 0.5rem; }}
  .finding-meta {{ font-size: 0.9rem; }}
  .finding-meta div {{ margin-bottom: 0.25rem; }}
  .finding-meta code {{ background: #1f2937; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; word-break: break-all; }}
  .remediation {{ color: #3fb950; }}
  .tags {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.5rem; }}
  .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85rem; }}
  @media print {{ body {{ background: #fff; color: #000; }} .finding {{ border-color: #ddd; background: #fff; }} }}
</style>
</head>
<body>
<div class="container">
  <h1>ScorchKit Security Report</h1>
  <div class="meta">
    Target: {target} | Scan ID: {scan_id} | Date: {date}
  </div>

  <div class="summary">
    <div class="summary-card critical"><div class="count">{critical}</div><div>Critical</div></div>
    <div class="summary-card high"><div class="count">{high}</div><div>High</div></div>
    <div class="summary-card medium"><div class="count">{medium}</div><div>Medium</div></div>
    <div class="summary-card low"><div class="count">{low}</div><div>Low</div></div>
    <div class="summary-card info"><div class="count">{info}</div><div>Info</div></div>
  </div>

  <h2>Findings ({total})</h2>
  {findings}

  <div class="footer">
    Generated by ScorchKit v{version} | {modules} modules | {duration}
  </div>
</div>
</body>
</html>"#,
        target = html_escape(&result.target.raw),
        scan_id = &result.scan_id,
        date = result.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
        critical = s.critical,
        high = s.high,
        medium = s.medium,
        low = s.low,
        info = s.info,
        total = s.total_findings,
        findings = findings_html,
        version = env!("CARGO_PKG_VERSION"),
        modules = result.modules_run.len(),
        duration = format_duration(result.started_at, result.completed_at),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn format_duration(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> String {
    let secs = (end - start).num_seconds();
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}
