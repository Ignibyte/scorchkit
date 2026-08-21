use std::fmt::Write;
use std::path::PathBuf;

use crate::config::ReportConfig;
use crate::engine::error::Result;
use crate::engine::observation::{redact_text, redact_url};
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
        let evidence = f.evidence.as_deref().map(redact_text).unwrap_or_default();
        let remediation = f.remediation.as_deref().map(redact_text).unwrap_or_default();
        let title = redact_text(&f.title);
        let description = redact_text(&f.description);
        let affected_target = redact_url(&f.affected_target).0;
        let owasp = f.owasp_category.as_deref().unwrap_or("");
        let cwe = f.cwe_id.map_or(String::new(), |c| format!("CWE-{c}"));
        let agent_analysis_html = f
            .canonical_appsec()
            .agent_analysis
            .iter()
            .fold(String::new(), |mut output, analysis| {
                let model = analysis
                    .model
                    .as_deref()
                    .map_or_else(String::new, |model| format!("/{model}"));
                let _ = write!(
                    output,
                    "<div class=\"agent-analysis\"><strong>Agent analysis [{}{}]:</strong> {}</div>",
                    html_escape(&analysis.provider),
                    html_escape(&model),
                    html_escape(&analysis.summary)
                );
                output
            });
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
    {agent_analysis_html}
    {remediation_html}
    <div class="tags">{owasp} {cwe}</div>
  </div>
</div>
"#,
            num = i + 1,
            severity = f.severity.to_string().to_uppercase(),
            confidence = confidence_pct,
            title = html_escape(&title),
            desc = html_escape(&description),
            target = html_escape(&affected_target),
            evidence_html = if evidence.is_empty() {
                String::new()
            } else {
                format!(
                    "<div><strong>Evidence:</strong> <code>{}</code></div>",
                    html_escape(&evidence)
                )
            },
            agent_analysis_html = agent_analysis_html,
            remediation_html = if remediation.is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"remediation\"><strong>Fix:</strong> {}</div>",
                    html_escape(&remediation)
                )
            },
        );
    }
    findings_html
}

// JUSTIFICATION: This function assembles one static HTML document whose sections share escaped
// scan projections; splitting it would obscure the single encoding boundary without simplifying it.
#[allow(clippy::too_many_lines)]
fn render_html(result: &ScanResult) -> String {
    let s = &result.summary;
    let findings_html = render_findings_html(result);
    let execution_status = match result.execution_status {
        crate::engine::scan_result::ScanExecutionStatus::Complete => "complete",
        crate::engine::scan_result::ScanExecutionStatus::Incomplete => "incomplete",
        crate::engine::scan_result::ScanExecutionStatus::Degraded => "degraded",
    };
    let supply_chain_html = result.supply_chain.as_ref().map_or_else(String::new, |assessment| {
        let gaps = assessment
            .gaps
            .iter()
            .map(|gap| {
                format!(
                    "<li><code>{}/{}</code>{}: {}</li>",
                    gap.phase.as_str(),
                    gap.kind.as_str(),
                    gap.component.as_deref().map_or_else(String::new, |component| {
                        format!(" [{}]", html_escape(component))
                    }),
                    html_escape(&gap.detail),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "<h2>Supply-chain coverage</h2><p>Status: <strong>{}</strong></p><ul>{}</ul>",
            assessment.coverage_status.as_str(),
            gaps
        )
    });
    let application_dast_html = application_dast_html(result);
    let application_pentest_html = application_pentest_html(result);
    let adapter_executions_html = adapter_executions_html(result);

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
  .agent-analysis {{ color: #d2a8ff; border-left: 2px solid #8957e5; padding-left: 0.5rem; }}
  .tags {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.5rem; }}
  pre {{ white-space: pre-wrap; word-break: break-word; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; }}
  .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85rem; }}
  @media print {{ body {{ background: #fff; color: #000; }} .finding {{ border-color: #ddd; background: #fff; }} }}
</style>
</head>
<body>
<div class="container">
  <h1>ScorchKit Security Report</h1>
  <div class="meta">
    Target: {target} | Scan ID: {scan_id} | Date: {date} | Execution: {execution_status}
  </div>

  <div class="summary">
    <div class="summary-card critical"><div class="count">{critical}</div><div>Critical</div></div>
    <div class="summary-card high"><div class="count">{high}</div><div>High</div></div>
    <div class="summary-card medium"><div class="count">{medium}</div><div>Medium</div></div>
    <div class="summary-card low"><div class="count">{low}</div><div>Low</div></div>
    <div class="summary-card info"><div class="count">{info}</div><div>Info</div></div>
  </div>

  {supply_chain}
  {application_dast}
  {application_pentest}
  {adapter_executions}

  <h2>Findings ({total})</h2>
  {findings}

  <div class="footer">
    Generated by ScorchKit v{version} | {modules} modules | {duration}
  </div>
</div>
</body>
</html>"#,
        target = html_escape(&redact_url(&result.target.raw).0),
        scan_id = &result.scan_id,
        date = result.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
        execution_status = execution_status,
        critical = s.critical,
        high = s.high,
        medium = s.medium,
        low = s.low,
        info = s.info,
        total = s.total_findings,
        findings = findings_html,
        supply_chain = supply_chain_html,
        application_dast = application_dast_html,
        application_pentest = application_pentest_html,
        adapter_executions = adapter_executions_html,
        version = env!("CARGO_PKG_VERSION"),
        modules = result.modules_run.len(),
        duration = format_duration(result.started_at, result.completed_at),
    )
}

fn adapter_executions_html(result: &ScanResult) -> String {
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
            let collection = assessment.configuration_identity.as_deref().map_or_else(
                String::new,
                |identity| format!(" | Collection: <code>{}</code>", html_escape(identity)),
            );
            let _ = write!(
                rendered,
                "<h3>{}</h3><p>Schema: <code>{}</code> | Status: <strong>{:?}</strong> | Tool: <code>{}</code> | Effect: <code>{}</code>{}</p><h4>Verified inputs</h4><ul>{}</ul><h4>Coverage gaps</h4><ul>{}</ul>",
                html_escape(&assessment.adapter_id),
                html_escape(&assessment.schema_version),
                assessment.status,
                html_escape(assessment.tool_version.as_deref().unwrap_or("unknown")),
                html_escape(assessment.strongest_effect.as_deref().unwrap_or("unknown")),
                collection,
                inputs,
                gaps,
            );
            rendered
        },
    );
    format!("<h2>External adapter execution</h2>{assessments}")
}

fn application_dast_html(result: &ScanResult) -> String {
    result.application_dast.as_ref().map_or_else(String::new, |assessment| {
        let personas = assessment
            .personas
            .iter()
            .map(|persona| {
                let observed = persona.routes.iter().filter(|route| route.observed).count();
                format!(
                    "<li><strong>{}</strong>: {:?}; {}/{} routes observed</li>",
                    html_escape(&persona.persona),
                    persona.authentication,
                    observed,
                    persona.routes.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let gaps = assessment
            .gaps
            .iter()
            .map(|gap| {
                format!(
                    "<li><code>{}/{}/{}</code>: {}</li>",
                    html_escape(&gap.persona),
                    gap.phase.as_str(),
                    gap.kind.as_str(),
                    html_escape(&gap.detail)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "<h2>Application DAST coverage</h2><p>Status: <strong>{}</strong>; profile: {}; ZAP {}</p><ul>{}</ul><ul>{}</ul>",
            assessment.coverage_status.as_str(),
            assessment.profile.as_str(),
            html_escape(&assessment.zap_version),
            personas,
            gaps
        )
    })
}

fn application_pentest_html(result: &ScanResult) -> String {
    result.application_pentest.as_ref().map_or_else(String::new, |assessment| {
        let canonical_plan = serde_json::to_string_pretty(&assessment.plan)
            .unwrap_or_else(|_| "{}".to_string());
        let outcomes = assessment
            .scenarios
            .iter()
            .map(|scenario| {
                let authorization = serde_json::to_string(&scenario.authorization_requirements)
                    .unwrap_or_else(|_| "[]".to_string());
                let gaps = scenario
                    .gaps
                    .iter()
                    .map(|gap| {
                        format!(
                            "<li><code>{}</code>: {}</li>",
                            gap.kind.as_str(),
                            html_escape(&gap.detail)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
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
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "<h2>Application pentest coverage</h2><p>Status: <strong>{}</strong>; plan: <code>{}</code>; target: <code>{}</code></p><h3>Canonical plan</h3><pre>{}</pre><h3>Scenario outcomes</h3><ol>{}</ol>",
            assessment.coverage_status.as_str(),
            html_escape(&assessment.plan_identity),
            html_escape(&redact_url(&assessment.target).0),
            html_escape(&canonical_plan),
            outcomes,
        )
    })
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::engine::finding::Finding;
    use crate::engine::observation::AgentAnalysisRecord;
    use crate::engine::severity::Severity;
    use crate::engine::target::Target;
    use crate::{
        ApplicationDastAssessment, ApplicationDastCoverageGap, ApplicationDastGapKind,
        ApplicationDastPhase, ApplicationDastProfile,
    };

    #[test]
    fn html_report_renders_findings_and_document_shell() {
        let now = Utc::now();
        let finding = Finding::new(
            "semgrep",
            Severity::High,
            "Unsafe <eval>",
            "User input reaches eval",
            "src/app.py:42",
        )
        .with_evidence("result = eval(user_input)")
        .with_agent_analysis(AgentAnalysisRecord::new(
            "codex-security",
            Some("trusted-security".to_string()),
            "Validated source-to-sink path",
            Vec::new(),
            now,
        ));
        let result = ScanResult::new(
            "html-test".to_string(),
            Target::parse("https://example.com").expect("valid target"),
            now,
            vec![finding],
            vec!["semgrep".to_string()],
            Vec::new(),
        );

        let findings = render_findings_html(&result);
        assert!(findings.contains("Unsafe &lt;eval&gt;"));
        assert!(findings.contains("result = eval(user_input)"));
        assert!(findings.contains("Agent analysis [codex-security/trusted-security]"));

        let document = render_html(&result);
        assert!(document.starts_with("<!DOCTYPE html>"));
        assert!(document.contains("ScorchKit Security Report"));
        assert!(document.contains("Unsafe &lt;eval&gt;"));
        assert!(document.contains("Scan ID: html-test"));
        assert!(document.ends_with("</html>"));
    }

    #[test]
    fn html_report_escapes_application_dast_coverage() {
        let mut assessment =
            ApplicationDastAssessment::new("https://example.com", ApplicationDastProfile::Passive);
        assessment.zap_version = "2.17.0<script>".to_string();
        assessment.record_gap(ApplicationDastCoverageGap::new(
            "user<script>",
            ApplicationDastPhase::AlertReport,
            ApplicationDastGapKind::ArtifactInvalid,
            "malformed <script>alert(1)</script>",
        ));
        let result = ScanResult::new(
            "html-dast".to_string(),
            Target::parse("https://example.com").expect("target"),
            Utc::now(),
            Vec::new(),
            vec!["application-dast".to_string()],
            Vec::new(),
        )
        .with_application_dast(assessment);

        let document = render_html(&result);
        assert!(document.contains("Application DAST coverage"));
        assert!(document.contains("user&lt;script&gt;"));
        assert!(!document.contains("2.17.0<script>"));
        assert!(!document.contains("malformed <script>"));
    }

    #[test]
    fn html_report_preserves_canonical_application_pentest_plan_and_outcomes() {
        let assessment = crate::report::application_pentest_fixture();
        let plan_identity = assessment.plan_identity.clone();
        let result = ScanResult::new(
            "html-application-pentest".to_string(),
            Target::parse("https://example.com/upload").expect("target"),
            Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_application_pentest(assessment)
        .expect("valid application-pentest fixture");

        let document = render_html(&result);
        assert!(document.contains("Application pentest coverage"));
        assert!(document.contains(&plan_identity));
        assert!(document.contains("manual-upload-v1"));
        assert!(document.contains("cleanup_required"));
        assert!(document.contains("codex&lt;script&gt;"));
        assert!(!document.contains("report-secret"));
        assert!(!document.contains("codex<script>"));
    }

    #[test]
    fn html_report_projects_and_escapes_external_adapter_evidence() {
        let mut assessment = scorchkit_core::AdapterExecutionAssessment::new("nuclei<script>");
        assessment.configuration_identity = Some("collection<script>".to_string());
        assessment.inputs.push(
            scorchkit_core::AdapterInputIdentity::new(
                "nuclei_template",
                "probe<script>",
                "a".repeat(64),
            )
            .with_signer("reviewer<script>"),
        );
        assessment = assessment.with_gap(
            scorchkit_core::AdapterExecutionStatus::Degraded,
            scorchkit_core::AdapterExecutionGap::new(
                scorchkit_core::AdapterExecutionGapKind::OutputInvalid,
                "output<script>",
                "token=html-adapter-secret",
            ),
        );
        let result = ScanResult::new(
            "html-adapter".to_string(),
            Target::parse("https://example.com").expect("target"),
            Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_adapter_executions(vec![assessment]);

        let document = render_html(&result);
        assert!(document.contains("External adapter execution"));
        assert!(document.contains("nuclei&lt;script&gt;"));
        assert!(document.contains("collection&lt;script&gt;"));
        assert!(!document.contains("html-adapter-secret"));
        assert!(!document.contains("nuclei<script>"));
    }
}
