//! `eyewitness` wrapper — visual recon (screenshots).
//!
//! Wraps [EyeWitness](https://github.com/RedSiege/EyeWitness) to
//! capture screenshots of the target. High-signal artifact for
//! human review — shows what the target actually *looks* like
//! (login pages, default installs, exposed admin panels) which
//! is hard to capture in finding text.

use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Visual recon screenshot capture via `EyeWitness`.
#[derive(Debug)]
pub struct EyewitnessModule;

#[async_trait]
impl ScanModule for EyewitnessModule {
    fn name(&self) -> &'static str {
        "EyeWitness Visual Recon"
    }
    fn id(&self) -> &'static str {
        "eyewitness"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }
    fn description(&self) -> &'static str {
        "Capture screenshots of the target for human-readable visual review"
    }
    fn requires_external_tool(&self) -> bool {
        true
    }
    fn required_tool(&self) -> Option<&str> {
        Some("eyewitness")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        use std::io::Write as _;
        let url = ctx.target.url.as_str();
        // Write the URL to a temp file so EyeWitness can read it.
        let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
            return Ok(Vec::new());
        };
        if writeln!(tmp, "{url}").is_err() {
            return Ok(Vec::new());
        }
        let Ok(out_dir) = tempfile::tempdir() else {
            return Ok(Vec::new());
        };
        let in_path = tmp.path().to_string_lossy().to_string();
        let out_path = out_dir.path().to_string_lossy().to_string();
        let _output = subprocess::run_tool_lenient(
            "eyewitness",
            &["-f", &in_path, "-d", &out_path, "--no-prompt", "--web"],
            Duration::from_secs(120),
        )
        .await?;
        Ok(parse_eyewitness_output(&out_path, url))
    }
}

/// Surface a single Info finding pointing at the screenshot
/// directory. We don't embed the image — just reference the path.
#[must_use]
fn parse_eyewitness_output(out_dir: &str, target_url: &str) -> Vec<Finding> {
    // EyeWitness writes a `report.html` index plus per-target PNGs.
    let report_html = format!("{out_dir}/report.html");
    if !std::path::Path::new(&report_html).exists() {
        return Vec::new();
    }
    vec![Finding::new(
        "eyewitness",
        Severity::Info,
        format!("EyeWitness: screenshot captured for {target_url}"),
        format!(
            "EyeWitness saved a screenshot of the target. Open `{report_html}` in a \
             browser for the full report. Visual review surfaces login pages, default \
             installs, and exposed admin panels that finding text can't convey."
        ),
        target_url,
    )
    .with_evidence(format!("EyeWitness output dir: {out_dir} | report.html: {report_html}"))
    .with_remediation(
        "Review the screenshot — note any default credentials prompts, error pages \
         leaking stack traces, or admin panels that shouldn't be reachable.",
    )
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_confidence(0.8)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When the report.html doesn't exist, no finding is emitted —
    /// matches the fail-soft behaviour every wrapper follows.
    #[test]
    fn parse_eyewitness_output_no_report() {
        let findings = parse_eyewitness_output("/nonexistent/dir", "https://example.com");
        assert!(findings.is_empty());
    }

    /// When report.html exists, a single Info finding is emitted
    /// pointing at the file path.
    #[test]
    fn parse_eyewitness_output_with_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = dir.path().join("report.html");
        std::fs::write(&report, "<html>fixture</html>").expect("write report");
        let findings =
            parse_eyewitness_output(&dir.path().to_string_lossy(), "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].evidence.as_ref().unwrap().contains("report.html"));
    }
}
