//! Professional PDF pentest report generation.
//!
//! Generates a print-optimized HTML report with professional sections
//! (cover page, executive summary, methodology, risk matrix, finding
//! details, appendix) and converts it to PDF via `weasyprint`.
//!
//! The HTML template is a pure function ([`render_pdf_html`]) testable
//! without `weasyprint` installed. The PDF conversion is a thin subprocess
//! wrapper that pipes HTML to `weasyprint - output.pdf`.

use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::observation::{redact_text, redact_url};
use crate::engine::scan_result::ScanResult;
use crate::runner::subprocess::{SystemToolExecutor, ToolExecutor, ToolInvocation};

/// Save a scan result as a professional PDF pentest report.
///
/// Renders an enhanced HTML template with print-optimized CSS, then
/// converts to PDF via `weasyprint`. Returns the path to the generated
/// PDF file.
///
/// # Errors
///
/// Returns [`crate::engine::error::ScorchError::ToolNotFound`] if `weasyprint`
/// is not installed, [`crate::engine::error::ScorchError::ToolFailed`] if PDF
/// conversion fails, or [`crate::engine::error::ScorchError::Report`] if the
/// output file cannot be written.
pub async fn save_report(result: &ScanResult, config: &ReportConfig) -> Result<PathBuf> {
    let output_dir = &config.output_dir;
    std::fs::create_dir_all(output_dir)?;

    let filename = format!("scorchkit-{}.pdf", result.scan_id);
    let path = output_dir.join(&filename);

    let html = render_pdf_html(result);

    let output_path = path.to_string_lossy().into_owned();
    SystemToolExecutor
        .execute(
            ToolInvocation::strict(
                "weasyprint",
                &["-", output_path.as_str()],
                Duration::from_mins(2),
            )
            .with_stdin(html.into_bytes()),
        )
        .await?;

    Ok(path)
}

/// Render the professional PDF HTML template from scan results.
///
/// Produces a self-contained HTML document with print-optimized CSS,
/// professional layout sections, and page break controls. This is a
/// pure function — testable without `weasyprint`.
#[must_use]
#[allow(clippy::too_many_lines)] // JUSTIFICATION: one cohesive six-section HTML template.
pub fn render_pdf_html(result: &ScanResult) -> String {
    let s = &result.summary;
    let target = html_escape(&redact_url(&result.target.raw).0);
    let scan_id = &result.scan_id;
    let date = result.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let duration = format_duration(result.started_at, result.completed_at);
    let version = env!("CARGO_PKG_VERSION");
    let module_count = result.modules_run.len();
    let execution_status = match result.execution_status {
        crate::engine::scan_result::ScanExecutionStatus::Complete => "Complete",
        crate::engine::scan_result::ScanExecutionStatus::Incomplete => "Incomplete",
        crate::engine::scan_result::ScanExecutionStatus::Degraded => "Degraded",
    };
    let supply_chain_html = result.supply_chain.as_ref().map_or_else(String::new, |assessment| {
        let gaps = assessment.gaps.iter().map(|gap| {
            format!(
                "<li><code>{}/{}</code>{}: {}</li>",
                gap.phase.as_str(),
                gap.kind.as_str(),
                gap.component.as_deref().map_or_else(String::new, |component| {
                    format!(" [{}]", html_escape(component))
                }),
                html_escape(&gap.detail),
            )
        }).collect::<Vec<_>>().join("\n");
        format!(
            "<h3>Application supply-chain coverage</h3><p>Status: <strong>{}</strong></p><ul>{}</ul>",
            assessment.coverage_status.as_str(), gaps
        )
    });
    let application_dast_html = result.application_dast.as_ref().map_or_else(String::new, |assessment| {
        let personas = assessment.personas.iter().map(|persona| {
            let observed = persona.routes.iter().filter(|route| route.observed).count();
            format!(
                "<li><strong>{}</strong>: {:?}; {}/{} routes observed</li>",
                html_escape(&persona.persona), persona.authentication, observed, persona.routes.len()
            )
        }).collect::<Vec<_>>().join("\n");
        let gaps = assessment.gaps.iter().map(|gap| {
            format!(
                "<li><code>{}/{}/{}</code>: {}</li>",
                html_escape(&gap.persona), gap.phase.as_str(), gap.kind.as_str(), html_escape(&gap.detail)
            )
        }).collect::<Vec<_>>().join("\n");
        format!(
            "<h3>Application DAST coverage</h3><p>Status: <strong>{}</strong>; profile: {}; ZAP {}</p><ul>{}</ul><ul>{}</ul>",
            assessment.coverage_status.as_str(), assessment.profile.as_str(), html_escape(&assessment.zap_version), personas, gaps
        )
    });
    let application_pentest_html = render_application_pentest(result);
    let adapter_executions_html = render_adapter_executions(result);

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
    <tr><th>Execution Status</th><td>{execution_status}</td></tr>
    <tr><th>Profile</th><td>Standard</td></tr>
    <tr><th>Tool Version</th><td>ScorchKit v{version}</td></tr>
  </table>
  {supply_chain}
  {application_dast}
  {application_pentest}
  {adapter_executions}
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
        execution_status = execution_status,
        supply_chain = supply_chain_html,
        application_dast = application_dast_html,
        application_pentest = application_pentest_html,
        adapter_executions = adapter_executions_html,
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

fn render_application_pentest(result: &ScanResult) -> String {
    result.application_pentest.as_ref().map_or_else(String::new, |assessment| {
        let canonical_plan = serde_json::to_string_pretty(&assessment.plan)
            .unwrap_or_else(|_| "{}".to_string());
        let scenarios = assessment.scenarios.iter().map(|scenario| {
            let authorization = serde_json::to_string(&scenario.authorization_requirements)
                .unwrap_or_else(|_| "[]".to_string());
            let gaps = scenario.gaps.iter().map(|gap| {
                format!("<li><code>{}</code>: {}</li>", gap.kind.as_str(), html_escape(&gap.detail))
            }).collect::<Vec<_>>().join("\n");
            format!(
                "<li><code>{}</code>: <strong>{}</strong>/{} via <code>{}</code> ({})<br>authorization: <code>{}</code><br>started: {} | completed: {}<br>findings: <code>{}</code><br>evidence: <code>{}</code><ul>{}</ul></li>",
                html_escape(&scenario.scenario_identity),
                scenario.status.as_str(),
                scenario.invariant.map_or("not_applicable", |value| value.as_str()),
                html_escape(&scenario.executor_id),
                scenario.executor_kind.as_str(),
                html_escape(&authorization),
                scenario.started_at.to_rfc3339(),
                scenario.completed_at.to_rfc3339(),
                html_escape(&scenario.finding_identities.join(", ")),
                html_escape(&scenario.evidence_identities.join(", ")),
                gaps,
            )
        }).collect::<Vec<_>>().join("\n");
        format!(
            "<h3>Application pentest coverage</h3><p>Status: <strong>{}</strong>; plan: <code>{}</code>; target: <code>{}</code></p><h4>Canonical plan</h4><pre>{}</pre><h4>Scenario outcomes</h4><ol>{}</ol>",
            assessment.coverage_status.as_str(),
            html_escape(&assessment.plan_identity),
            html_escape(&redact_url(&assessment.target).0),
            html_escape(&canonical_plan),
            scenarios,
        )
    })
}

fn render_adapter_executions(result: &ScanResult) -> String {
    if result.adapter_executions.is_empty() {
        return String::new();
    }
    let assessments = result.adapter_executions.iter().fold(
        String::new(),
        |mut rendered, assessment| {
            let inputs = assessment.inputs.iter().fold(String::new(), |mut rendered, input| {
                let signer = input.signer_identity.as_deref().map_or_else(String::new, |signer| {
                    format!(" signer:{}", html_escape(signer))
                });
                let _ = write!(
                    rendered,
                    "<li><code>{}/{}</code> sha256:{}{}</li>",
                    html_escape(&input.kind),
                    html_escape(&input.id),
                    html_escape(&input.sha256),
                    signer,
                );
                rendered
            });
            let gaps = assessment.gaps.iter().fold(String::new(), |mut rendered, gap| {
                let _ = write!(
                    rendered,
                    "<li><code>{:?}/{}</code>: {}</li>",
                    gap.kind,
                    html_escape(&gap.component),
                    html_escape(&gap.detail),
                );
                rendered
            });
            let _ = write!(
                rendered,
                "<h4>{}</h4><table><tbody><tr><th>Schema</th><td>{}</td></tr><tr><th>Status</th><td>{:?}</td></tr><tr><th>Tool</th><td>{}</td></tr><tr><th>Collection</th><td>{}</td></tr><tr><th>Effect</th><td>{}</td></tr></tbody></table><p>Verified inputs</p><ul>{}</ul><p>Coverage gaps</p><ul>{}</ul>",
                html_escape(&assessment.adapter_id),
                html_escape(&assessment.schema_version),
                assessment.status,
                html_escape(assessment.tool_version.as_deref().unwrap_or("unknown")),
                html_escape(assessment.configuration_identity.as_deref().unwrap_or("unavailable")),
                html_escape(assessment.strongest_effect.as_deref().unwrap_or("unknown")),
                inputs,
                gaps,
            );
            rendered
        },
    );
    format!("<h3>External adapter execution</h3>{assessments}")
}

/// Render all findings as HTML sections.
fn render_findings(findings: &[crate::engine::finding::Finding]) -> String {
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let evidence = f.evidence.as_deref().map(redact_text).unwrap_or_default();
            let remediation = f.remediation.as_deref().map(redact_text).unwrap_or_default();
            let title = redact_text(&f.title);
            let description = redact_text(&f.description);
            let affected_target = redact_url(&f.affected_target).0;
            let owasp = f.owasp_category.as_deref().unwrap_or("—");
            let cwe = f.cwe_id.map_or_else(|| "—".to_string(), |c| format!("CWE-{c}"));
            let analysis_rows = f.canonical_appsec().agent_analysis.iter().fold(
                String::new(),
                |mut output, analysis| {
                    let _ = write!(
                        output,
                        "<tr><th>Agent analysis [{}]</th><td>{}</td></tr>",
                        html_escape(&analysis.report_label()),
                        html_escape(&analysis.summary)
                    );
                    output
                },
            );
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
      {analysis_rows}
    </table>
    {remediation_box}
  </div>"#,
                num = i + 1,
                sev = sev,
                sev_class = sev_class,
                confidence = confidence_pct,
                title = html_escape(&title),
                desc = html_escape(&description),
                target = html_escape(&affected_target),
                owasp = html_escape(owasp),
                cwe = cwe,
                evidence_row = if evidence.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<tr><th>Evidence</th><td><code>{}</code></td></tr>",
                        html_escape(&evidence)
                    )
                },
                analysis_rows = analysis_rows,
                remediation_box = if remediation.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<div class=\"remediation-box\"><strong>Remediation:</strong> {}</div>",
                        html_escape(&remediation)
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
    use crate::engine::observation::AgentAnalysisRecord;
    use crate::engine::scan_result::{ScanResult, ScanSummary};
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    use crate::{
        ModelAnalysisProvenance, ModelExecutionLocation, ModelRole, MODEL_ANALYSIS_CONTRACT_V1,
        MODEL_ANALYSIS_PROVENANCE_V1,
    };
    use chrono::Utc;

    fn model_record(now: chrono::DateTime<Utc>) -> AgentAnalysisRecord {
        AgentAnalysisRecord::from_model(
            ModelAnalysisProvenance {
                schema: MODEL_ANALYSIS_PROVENANCE_V1.to_string(),
                provider: "fixture-host".to_string(),
                model: "exact-model".to_string(),
                role: ModelRole::Remediation,
                contract_version: MODEL_ANALYSIS_CONTRACT_V1.to_string(),
                input_evidence_digests: vec!["1".repeat(64)],
                workflow_version: "workflow/v1".to_string(),
                created_at: now,
                confidence_bps: 7_500,
                execution_location: ModelExecutionLocation::Local,
            },
            "Model remediation guidance",
        )
        .expect("model record")
    }

    // Test suite for PDF report generation.
    //
    // Tests the pure HTML template function without requiring weasyprint.

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
            module_outcomes: Vec::new(),
            execution_status: crate::engine::scan_result::ScanExecutionStatus::Complete,
            supply_chain: None,
            application_dast: None,
            application_pentest: None,
            adapter_executions: Vec::new(),
            pipeline_outcomes: Vec::new(),
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

    #[test]
    fn pdf_html_preserves_canonical_application_pentest_plan_and_outcomes() {
        let assessment = crate::report::application_pentest_fixture();
        let plan_identity = assessment.plan_identity.clone();
        let result = test_result()
            .with_application_pentest(assessment)
            .expect("valid application-pentest fixture");

        let html = render_pdf_html(&result);
        assert!(html.contains("Application pentest coverage"));
        assert!(html.contains(&plan_identity));
        assert!(html.contains("manual-upload-v1"));
        assert!(html.contains("cleanup_required"));
        assert!(html.contains("codex&lt;script&gt;"));
        assert!(!html.contains("report-secret"));
        assert!(!html.contains("codex<script>"));
    }

    #[test]
    fn pdf_projects_external_adapter_identity_without_unescaped_markup() {
        let mut result = test_result();
        let mut assessment = scorchkit_core::AdapterExecutionAssessment::new("nuclei<script>");
        assessment.tool_version = Some("3.11.1<script>".to_string());
        assessment.configuration_identity = Some("collection<script>".to_string());
        assessment.inputs.push(scorchkit_core::AdapterInputIdentity::new(
            "nuclei_template",
            "probe",
            "a".repeat(64),
        ));
        result = result.with_adapter_executions(vec![assessment]);

        let html = render_pdf_html(&result);
        assert!(html.contains("External adapter execution"));
        assert!(html.contains("nuclei&lt;script&gt;"));
        assert!(html.contains("3.11.1&lt;script&gt;"));
        assert!(!html.contains("nuclei<script>"));
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

    #[test]
    fn pdf_projects_complete_model_provenance_label() {
        let mut result = test_result();
        let finding = result.findings.remove(0).with_agent_analysis(model_record(Utc::now()));
        result.findings.insert(0, finding);
        let html = render_pdf_html(&result);
        assert!(html.contains("fixture-host/exact-model remediation@local"));
        assert!(html.contains("Model remediation guidance"));
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

    #[tokio::test]
    async fn save_report_rejects_an_output_directory_that_is_a_file() {
        let temporary = tempfile::tempdir().expect("create PDF report fixture root");
        let output_file = temporary.path().join("not-a-directory");
        std::fs::write(&output_file, b"fixture").expect("write conflicting output file");
        let config = ReportConfig { output_dir: output_file, ..ReportConfig::default() };

        assert!(
            save_report(&test_result(), &config).await.is_err(),
            "PDF report creation must propagate an invalid output-directory error"
        );
    }
}
