use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Automated SQL injection detection and exploitation via sqlmap.
#[derive(Debug)]
pub struct SqlmapModule;

#[async_trait]
impl ScanModule for SqlmapModule {
    fn name(&self) -> &'static str {
        "SQLMap Injection Scanner"
    }

    fn id(&self) -> &'static str {
        "sqlmap"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Automated SQL injection detection via sqlmap"
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("sqlmap")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        // Only run sqlmap if the target URL has parameters
        if !target.contains('?') || !target.contains('=') {
            return Ok(vec![Finding::new(
                "sqlmap",
                Severity::Info,
                "SQLMap: No Parameters to Test",
                "The target URL has no query parameters. Provide a URL with \
                 parameters for sqlmap testing (e.g., https://target.com/page?id=1).",
                target,
            )]);
        }

        let output = subprocess::run_tool(
            "sqlmap",
            &[
                "-u",
                target,
                "--batch",
                "--level",
                "1",
                "--risk",
                "1",
                "--forms",
                "--crawl=2",
                "--output-dir=/tmp/scorchkit-sqlmap",
            ],
            Duration::from_secs(600),
        )
        .await?;

        parse_sqlmap_output(&output.stdout, target)
    }
}

/// Parse sqlmap console output into findings.
fn parse_sqlmap_output(output: &str, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = output.lines().collect();

    let mut current_param: Option<String> = None;
    let mut current_type: Option<String> = None;

    for line in &lines {
        let trimmed = line.trim();

        // Detect injection confirmation
        // sqlmap output: "Parameter: id (GET)" or similar
        if trimmed.starts_with("Parameter:") {
            current_param = Some(trimmed.trim_start_matches("Parameter:").trim().to_string());
        }

        // Detect injection type
        // "Type: boolean-based blind"
        if trimmed.starts_with("Type:") {
            current_type = Some(trimmed.trim_start_matches("Type:").trim().to_string());
        }

        // Confirmed injection
        if trimmed.contains("is vulnerable") || trimmed.contains("injectable") {
            let param = current_param.as_deref().unwrap_or("unknown");
            let inj_type = current_type.as_deref().unwrap_or("unknown type");

            findings.push(
                Finding::new(
                    "sqlmap",
                    Severity::Critical,
                    format!("Confirmed SQL Injection: {param}"),
                    format!(
                        "sqlmap confirmed SQL injection in parameter {param}. \
                         Injection type: {inj_type}."
                    ),
                    target_url,
                )
                .with_evidence(format!("Parameter: {param} | Type: {inj_type}"))
                .with_remediation(
                    "Use parameterized queries / prepared statements. \
                     Never concatenate user input into SQL queries.",
                )
                .with_owasp("A03:2021 Injection")
                .with_cwe(89),
            );
        }

        // Database identified
        if trimmed.contains("back-end DBMS:") {
            let dbms = trimmed.split("back-end DBMS:").nth(1).unwrap_or("unknown").trim();

            findings.push(
                Finding::new(
                    "sqlmap",
                    Severity::Info,
                    format!("Database Identified: {dbms}"),
                    format!("sqlmap identified the back-end database as {dbms}."),
                    target_url,
                )
                .with_evidence(format!("DBMS: {dbms}")),
            );
        }
    }

    // If no specific injection found but sqlmap ran, note it
    if findings.is_empty() {
        findings.push(Finding::new(
            "sqlmap",
            Severity::Info,
            "SQLMap: No Injection Points Found",
            "sqlmap did not find any SQL injection vulnerabilities at the tested level/risk.",
            target_url,
        ));
    }

    Ok(findings)
}
