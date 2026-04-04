//! Professional PDF pentest report generation.
//!
//! Generates a print-optimized HTML report with professional sections
//! (cover page, executive summary, methodology, risk matrix, finding
//! details, appendix) and converts it to PDF via `weasyprint`.
//!
//! The HTML template is a pure function ([`render_pdf_html`]) testable
//! without `weasyprint` installed. The PDF conversion is a thin subprocess
//! wrapper that pipes HTML to `weasyprint - output.pdf`.

use std::path::PathBuf;
use std::process::Stdio;

use crate::config::ReportConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::scan_result::ScanResult;

/// Save a scan result as a professional PDF pentest report.
///
/// Renders an enhanced HTML template with print-optimized CSS, then
/// converts to PDF via `weasyprint`. Returns the path to the generated
/// PDF file.
///
/// # Errors
///
/// Returns [`ScorchError::ToolNotFound`] if `weasyprint` is not installed,
/// [`ScorchError::ToolFailed`] if PDF conversion fails, or
/// [`ScorchError::Report`] if the output file cannot be written.
pub fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf> {
    // Check weasyprint is installed
    let which = std::process::Command::new("which").arg("weasyprint").output().map_err(|e| {
        ScorchError::ToolFailed {
            tool: "weasyprint".to_string(),
            status: -1,
            stderr: e.to_string(),
        }
    })?;

    if !which.status.success() {
        return Err(ScorchError::ToolNotFound { tool: "weasyprint".to_string() });
    }

    let output_dir = &config.output_dir;
    std::fs::create_dir_all(output_dir)?;

    let filename = format!("scorchkit-{}.pdf", result.scan_id);
    let path = output_dir.join(&filename);

    let html = render_pdf_html(result);

    // Pipe HTML to weasyprint via stdin
    let mut child = std::process::Command::new("weasyprint")
        .args(["-", path.to_str().unwrap_or("report.pdf")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ScorchError::ToolFailed {
            tool: "weasyprint".to_string(),
            status: -1,
            stderr: e.to_string(),
        })?;

    // Write HTML to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(html.as_bytes());
    }

    let output = child.wait_with_output().map_err(|e| ScorchError::ToolFailed {
        tool: "weasyprint".to_string(),
        status: -1,
        stderr: e.to_string(),
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ScorchError::ToolFailed {
            tool: "weasyprint".to_string(),
            status: output.status.code().unwrap_or(-1),
            stderr: stderr.to_string(),
        });
    }

    Ok(path)
}

/// Render the professional PDF HTML template from scan results.
///
/// Produces a self-contained HTML document with print-optimized CSS,
/// professional layout sections, and page break controls. This is a
/// pure function — testable without `weasyprint`.
#[must_use]
#[allow(clippy::too_many_lines)] // Report template with 6 HTML sections — cannot meaningfully split
pub fn render_pdf_html(result: &ScanResult) -> String {
    let s = &result.summary;
    let target = html_escape(&result.target.raw);
    let scan_id = &result.scan_id;
    let date = result.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let duration = format_duration(result.started_at, result.completed_at);
    let version = env!("CARGO_PKG_VERSION");
    let module_count = result.modules_run.len();

    let risk_rating = overall_risk_rating(s.critical, s.high, s.medium);

    let findings_html = render_findings(&result.findings);
    let modules_list = result
        .modules_run
        .iter()
        .map(|m| format!("<li>{}</li>", html_escape(m)))
        .collect::<Vec<_>>()
        .join("\n            ");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report - {target}</title>
{CSS}
</head>
<body>

<!-- Cover Page -->
<div class="cover-page">
  <div class="cover-brand">SCORCHKIT</div>
  <h1 class="cover-title">Security Assessment Report</h1>
  <div class="cover-target">{target}</div>
  <div class="cover-meta">
    <div>Date: {date}</div>
    <div>Scan ID: {scan_id}</div>
    <div>Classification: CONFIDENTIAL</div>
  </div>
</div>

<!-- Executive Summary -->
<div class="section">
  <h2>1. Executive Summary</h2>
  <p>A security assessment was conducted against <strong>{target}</strong> using
  ScorchKit v{version} with {module_count} scanning modules. The assessment
  identified <strong>{total} findings</strong> across {categories} severity levels.</p>

  <div class="risk-rating {risk_class}">
    <span class="risk-label">Overall Risk Rating:</span>
    <span class="risk-value">{risk_rating}</span>
  </div>

  <table class="risk-matrix">
    <thead>
      <tr><th>Severity</th><th>Count</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr class="sev-critical"><td>Critical</td><td>{critical}</td><td>Immediate exploitation risk, full system compromise</td></tr>
      <tr class="sev-high"><td>High</td><td>{high}</td><td>Significant security impact, exploit likely</td></tr>
      <tr class="sev-medium"><td>Medium</td><td>{medium}</td><td>Moderate risk, requires specific conditions</td></tr>
      <tr class="sev-low"><td>Low</td><td>{low}</td><td>Minor impact, limited exploitability</td></tr>
      <tr class="sev-info"><td>Info</td><td>{info}</td><td>Informational, no direct security impact</td></tr>
    </tbody>
  </table>
</div>

<!-- Scope & Methodology -->
<div class="section page-break">
  <h2>2. Scope &amp; Methodology</h2>
  <table class="info-table">
    <tr><th>Target</th><td>{target}</td></tr>
    <tr><th>Scan Duration</th><td>{duration}</td></tr>
    <tr><th>Modules Executed</th><td>{module_count}</td></tr>
    <tr><th>Profile</th><td>Standard</td></tr>
    <tr><th>Tool Version</th><td>ScorchKit v{version}</td></tr>
  </table>
  <h3>Methodology</h3>
  <p>The assessment followed the PTES (Penetration Testing Execution Standard)
  framework adapted for automated scanning: reconnaissance, vulnerability
  identification, analysis, and reporting. All testing was non-destructive.</p>
</div>

<!-- Findings -->
<div class="section page-break">
  <h2>3. Detailed Findings</h2>
  {findings_html}
</div>

<!-- Appendix -->
<div class="section page-break">
  <h2>Appendix A: Modules Executed</h2>
  <ol class="module-list">
    {modules_list}
  </ol>
  <div class="footer-note">
    Generated by ScorchKit v{version} | {date}
  </div>
</div>

</body>
</html>"#,
        CSS = PDF_CSS,
        target = target,
        scan_id = scan_id,
        date = date,
        version = version,
        module_count = module_count,
        total = s.total_findings,
        categories = count_categories(s.critical, s.high, s.medium, s.low, s.info),
        risk_rating = risk_rating,
        risk_class = risk_rating.to_lowercase(),
        critical = s.critical,
        high = s.high,
        medium = s.medium,
        low = s.low,
        info = s.info,
        duration = duration,
        findings_html = findings_html,
        modules_list = modules_list,
    )
}

/// Render all findings as HTML sections.
fn render_findings(findings: &[crate::engine::finding::Finding]) -> String {
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let evidence = f.evidence.as_deref().unwrap_or("");
            let remediation = f.remediation.as_deref().unwrap_or("");
            let owasp = f.owasp_category.as_deref().unwrap_or("—");
            let cwe = f.cwe_id.map_or_else(|| "—".to_string(), |c| format!("CWE-{c}"));
            let sev = f.severity.to_string().to_uppercase();
            let sev_class = f.severity.to_string();
            // JUSTIFICATION: confidence is 0.0–1.0, result fits in u8
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let confidence_pct = (f.confidence * 100.0) as u8;

            format!(
                r#"<div class="finding {sev_class}">
    <div class="finding-header">
      <span class="finding-num">Finding #{num}</span>
      <span class="severity-badge {sev_class}">{sev}</span>
    </div>
    <h3 class="finding-title">{title}</h3>
    <p class="finding-desc">{desc}</p>
    <table class="finding-meta">
      <tr><th>Affected Target</th><td>{target}</td></tr>
      <tr><th>Confidence</th><td>{confidence}%</td></tr>
      <tr><th>OWASP Category</th><td>{owasp}</td></tr>
      <tr><th>CWE</th><td>{cwe}</td></tr>
      {evidence_row}
    </table>
    {remediation_box}
  </div>"#,
                num = i + 1,
                sev = sev,
                sev_class = sev_class,
                confidence = confidence_pct,
                title = html_escape(&f.title),
                desc = html_escape(&f.description),
                target = html_escape(&f.affected_target),
                owasp = html_escape(owasp),
                cwe = cwe,
                evidence_row = if evidence.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<tr><th>Evidence</th><td><code>{}</code></td></tr>",
                        html_escape(evidence)
                    )
                },
                remediation_box = if remediation.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<div class=\"remediation-box\"><strong>Remediation:</strong> {}</div>",
                        html_escape(remediation)
                    )
                },
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Determine overall risk rating from severity counts.
const fn overall_risk_rating(critical: usize, high: usize, medium: usize) -> &'static str {
    if critical > 0 {
        "Critical"
    } else if high > 0 {
        "High"
    } else if medium > 0 {
        "Medium"
    } else {
        "Low"
    }
}

/// Count how many non-zero severity categories exist.
fn count_categories(critical: usize, high: usize, medium: usize, low: usize, info: usize) -> usize {
    [critical, high, medium, low, info].iter().filter(|&&c| c > 0).count()
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

/// Print-optimized CSS for the PDF report.
const PDF_CSS: &str = r#"<style>
  @page {
    size: A4;
    margin: 2cm 2.5cm;
    @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 9pt; color: #888; }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 11pt; color: #1a1a1a; line-height: 1.6; }

  .cover-page { text-align: center; padding-top: 8cm; page-break-after: always; }
  .cover-brand { font-size: 14pt; letter-spacing: 4px; color: #888; margin-bottom: 1cm; }
  .cover-title { font-size: 28pt; font-weight: 700; color: #c0392b; margin-bottom: 1cm; }
  .cover-target { font-size: 16pt; color: #2c3e50; margin-bottom: 2cm; }
  .cover-meta { font-size: 11pt; color: #666; }
  .cover-meta div { margin-bottom: 0.3cm; }

  .section { margin-bottom: 1.5cm; }
  .page-break { page-break-before: always; }

  h2 { font-size: 16pt; color: #2c3e50; border-bottom: 2px solid #c0392b; padding-bottom: 4pt; margin-bottom: 12pt; }
  h3 { font-size: 13pt; color: #2c3e50; margin: 8pt 0 4pt; }
  p { margin-bottom: 8pt; }

  .risk-rating { text-align: center; padding: 12pt; margin: 16pt 0; border: 2px solid #ddd; border-radius: 4pt; }
  .risk-rating .risk-label { font-size: 12pt; color: #666; }
  .risk-rating .risk-value { font-size: 20pt; font-weight: 700; margin-left: 8pt; }
  .risk-rating.critical .risk-value { color: #c0392b; }
  .risk-rating.high .risk-value { color: #e74c3c; }
  .risk-rating.medium .risk-value { color: #f39c12; }
  .risk-rating.low .risk-value { color: #27ae60; }

  table { width: 100%; border-collapse: collapse; margin: 8pt 0; font-size: 10pt; }
  th, td { padding: 6pt 8pt; border: 1px solid #ddd; text-align: left; }
  th { background: #f5f5f5; font-weight: 600; white-space: nowrap; }
  .risk-matrix th { text-align: center; }
  .risk-matrix td:nth-child(2) { text-align: center; font-weight: 700; }
  .sev-critical td:first-child { color: #c0392b; font-weight: 700; }
  .sev-high td:first-child { color: #e74c3c; font-weight: 700; }
  .sev-medium td:first-child { color: #f39c12; font-weight: 700; }
  .sev-low td:first-child { color: #27ae60; font-weight: 700; }
  .sev-info td:first-child { color: #3498db; font-weight: 700; }

  .info-table th { width: 30%; }

  .finding { border: 1px solid #ddd; border-radius: 4pt; padding: 12pt; margin-bottom: 12pt; page-break-inside: avoid; }
  .finding.critical { border-left: 4pt solid #c0392b; }
  .finding.high { border-left: 4pt solid #e74c3c; }
  .finding.medium { border-left: 4pt solid #f39c12; }
  .finding.low { border-left: 4pt solid #27ae60; }
  .finding.info { border-left: 4pt solid #3498db; }
  .finding-header { display: flex; align-items: center; gap: 8pt; margin-bottom: 6pt; }
  .finding-num { font-size: 10pt; color: #888; }
  .severity-badge { padding: 2pt 8pt; border-radius: 3pt; font-size: 9pt; font-weight: 700; color: #fff; }
  .severity-badge.critical { background: #c0392b; }
  .severity-badge.high { background: #e74c3c; }
  .severity-badge.medium { background: #f39c12; color: #000; }
  .severity-badge.low { background: #27ae60; }
  .severity-badge.info { background: #3498db; }
  .finding-title { margin-bottom: 4pt; }
  .finding-desc { color: #555; font-size: 10pt; margin-bottom: 8pt; }
  .finding-meta { font-size: 10pt; }
  .finding-meta code { background: #f5f5f5; padding: 1pt 4pt; border-radius: 2pt; font-size: 9pt; word-break: break-all; }

  .remediation-box { background: #eafaf1; border: 1px solid #27ae60; border-radius: 3pt; padding: 8pt; margin-top: 8pt; font-size: 10pt; }

  .module-list { columns: 2; font-size: 10pt; padding-left: 20pt; }
  .module-list li { margin-bottom: 2pt; }

  .footer-note { margin-top: 2cm; text-align: center; font-size: 9pt; color: #888; border-top: 1px solid #ddd; padding-top: 8pt; }
</style>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::finding::Finding;
    use crate::engine::scan_result::{ScanResult, ScanSummary};
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    use chrono::Utc;

    /// Test suite for PDF report generation.
    ///
    /// Tests the pure HTML template function without requiring weasyprint.

    /// Create a test scan result with sample findings.
    fn test_result() -> ScanResult {
        let target = Target::parse("https://example.com").expect("valid target");
        let findings = vec![
            Finding::new(
                "test",
                Severity::Critical,
                "SQL Injection in Login",
                "The login form is vulnerable to SQL injection",
                "https://example.com/login",
            )
            .with_evidence("Parameter: username | Payload: ' OR 1=1--")
            .with_remediation("Use parameterized queries")
            .with_owasp("A03:2021 Injection")
            .with_cwe(89),
            Finding::new(
                "test",
                Severity::Medium,
                "Missing HSTS Header",
                "No Strict-Transport-Security header",
                "https://example.com",
            )
            .with_remediation("Add HSTS header"),
        ];
        let now = Utc::now();
        ScanResult {
            scan_id: "test-scan-001".to_string(),
            target,
            started_at: now,
            completed_at: now + chrono::Duration::seconds(42),
            modules_run: vec!["headers".to_string(), "injection".to_string()],
            modules_skipped: Vec::new(),
            findings,
            summary: ScanSummary {
                total_findings: 2,
                critical: 1,
                high: 0,
                medium: 1,
                low: 0,
                info: 0,
            },
        }
    }

    /// Verify the rendered HTML contains all required professional sections.
    ///
    /// Cover page, executive summary, methodology, findings, and appendix
    /// must all be present in the output.
    #[test]
    fn test_render_pdf_html_structure() {
        let html = render_pdf_html(&test_result());

        assert!(html.contains("cover-page"), "Missing cover page");
        assert!(html.contains("Executive Summary"), "Missing executive summary");
        assert!(html.contains("Scope &amp; Methodology"), "Missing methodology");
        assert!(html.contains("Detailed Findings"), "Missing findings section");
        assert!(html.contains("Appendix A"), "Missing appendix");
        assert!(html.contains("SCORCHKIT"), "Missing branding");
        assert!(html.contains("CONFIDENTIAL"), "Missing classification");
    }

    /// Verify executive summary shows correct severity counts.
    #[test]
    fn test_render_pdf_html_severity_counts() {
        let html = render_pdf_html(&test_result());

        // Risk matrix should contain counts
        assert!(html.contains("<td>1</td>"), "Missing critical count");
        assert!(html.contains("Overall Risk Rating"), "Missing risk rating");
        assert!(html.contains("Critical"), "Missing Critical rating (has critical findings)");
    }

    /// Verify each finding renders with evidence, remediation, and OWASP/CWE.
    #[test]
    fn test_render_pdf_html_finding_details() {
        let html = render_pdf_html(&test_result());

        assert!(html.contains("SQL Injection in Login"), "Missing finding title");
        assert!(html.contains("A03:2021 Injection"), "Missing OWASP category");
        assert!(html.contains("CWE-89"), "Missing CWE");
        assert!(html.contains("parameterized queries"), "Missing remediation");
        assert!(html.contains("OR 1=1"), "Missing evidence");
        assert!(html.contains("Finding #1"), "Missing finding number");
        assert!(html.contains("Finding #2"), "Missing second finding");
    }

    /// Verify print CSS rules are present for proper PDF rendering.
    #[test]
    fn test_render_pdf_html_print_css() {
        let html = render_pdf_html(&test_result());

        assert!(html.contains("@page"), "Missing @page CSS rule");
        assert!(html.contains("page-break"), "Missing page-break CSS");
        assert!(html.contains("size: A4"), "Missing A4 page size");
    }

    /// Verify the risk matrix table contains severity distribution.
    #[test]
    fn test_render_pdf_html_risk_matrix() {
        let html = render_pdf_html(&test_result());

        assert!(html.contains("risk-matrix"), "Missing risk matrix class");
        assert!(html.contains("sev-critical"), "Missing critical severity row");
        assert!(html.contains("sev-high"), "Missing high severity row");
        assert!(html.contains("sev-medium"), "Missing medium severity row");
    }

    /// Verify risk rating logic for different severity combinations.
    #[test]
    fn test_overall_risk_rating() {
        assert_eq!(overall_risk_rating(1, 0, 0), "Critical");
        assert_eq!(overall_risk_rating(0, 3, 0), "High");
        assert_eq!(overall_risk_rating(0, 0, 5), "Medium");
        assert_eq!(overall_risk_rating(0, 0, 0), "Low");
        assert_eq!(overall_risk_rating(2, 5, 3), "Critical");
    }

    /// Verify category counting for executive summary.
    #[test]
    fn test_count_categories() {
        assert_eq!(count_categories(1, 0, 1, 0, 0), 2);
        assert_eq!(count_categories(0, 0, 0, 0, 0), 0);
        assert_eq!(count_categories(1, 1, 1, 1, 1), 5);
    }

    /// Verify HTML escaping prevents XSS in generated reports.
    #[test]
    fn test_html_escape() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }
}
