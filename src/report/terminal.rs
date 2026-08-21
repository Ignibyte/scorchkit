use colored::Colorize;

use crate::engine::observation::{redact_text, redact_url};
use crate::engine::scan_result::ScanResult;

/// Escape terminal control and bidirectional-format characters in untrusted text.
///
/// This operates only at presentation sinks. Secret redaction is a separate canonicalization step
/// applied before untrusted finding and diagnostic text reaches any output boundary.
#[must_use]
pub fn escape_terminal_text(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_control() || is_bidirectional_format(character) {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

const fn is_bidirectional_format(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Print a scan report to the terminal with colors.
pub fn print_report(result: &ScanResult) {
    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!("{}", " SCAN RESULTS".bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Summary
    let s = &result.summary;
    print_execution_status(result);
    println!(
        "  {} findings across {} modules",
        s.total_findings.to_string().bold(),
        result.modules_run.len()
    );
    println!();

    if s.critical > 0 {
        println!("    {} Critical", s.critical.to_string().red().bold());
    }
    if s.high > 0 {
        println!("    {} High", s.high.to_string().red());
    }
    if s.medium > 0 {
        println!("    {} Medium", s.medium.to_string().yellow());
    }
    if s.low > 0 {
        println!("    {} Low", s.low.to_string().green());
    }
    if s.info > 0 {
        println!("    {} Info", s.info.to_string().blue());
    }

    if !result.modules_skipped.is_empty() {
        println!();
        println!(
            "  {} module{} skipped",
            result.modules_skipped.len(),
            if result.modules_skipped.len() == 1 { "" } else { "s" }
        );
        for (id, reason) in &result.modules_skipped {
            println!(
                "    {} {}: {}",
                "-".dimmed(),
                escape_terminal_text(id).dimmed(),
                escape_terminal_text(reason).dimmed()
            );
        }
    }

    // Findings detail
    if !result.findings.is_empty() {
        println!();
        println!("{}", "━".repeat(60).dimmed());
        println!("{}", " FINDINGS".bold());
        println!("{}", "━".repeat(60).dimmed());

        for (i, finding) in result.findings.iter().enumerate() {
            println!();
            // JUSTIFICATION: confidence is 0.0–1.0, well within f64→u8 range
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let conf_pct = (finding.confidence * 100.0) as u8;
            println!(
                "  {}  [{}] [{}%] {}",
                format!("#{}", i + 1).dimmed(),
                finding.severity.colored_str(),
                conf_pct.to_string().dimmed(),
                escape_terminal_text(&redact_text(&finding.title)).bold()
            );
            println!("  {}", escape_terminal_text(&redact_text(&finding.description)).dimmed());
            println!(
                "  Target: {}",
                escape_terminal_text(&redact_url(&finding.affected_target).0).cyan()
            );

            if let Some(evidence) = &finding.evidence {
                println!("  Evidence: {}", escape_terminal_text(&redact_text(evidence)).yellow());
            }

            for analysis in &finding.canonical_appsec().agent_analysis {
                let model =
                    analysis.model.as_deref().map_or_else(String::new, |model| format!("/{model}"));
                println!(
                    "  Agent analysis [{}{}]: {}",
                    escape_terminal_text(&analysis.provider).magenta(),
                    escape_terminal_text(&model).magenta(),
                    escape_terminal_text(&analysis.summary).magenta()
                );
            }

            if let Some(remediation) = &finding.remediation {
                println!("  Fix: {}", escape_terminal_text(&redact_text(remediation)).green());
            }

            if let Some(owasp) = &finding.owasp_category {
                print!("  {}", escape_terminal_text(owasp).dimmed());
            }
            if let Some(cwe) = finding.cwe_id {
                print!("  CWE-{}", cwe.to_string().dimmed());
            }
            if finding.owasp_category.is_some() || finding.cwe_id.is_some() {
                println!();
            }
        }
    }

    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!("  Scan ID: {}", escape_terminal_text(&result.scan_id).dimmed());
    println!("  Duration: {}", format_duration(result.started_at, result.completed_at).dimmed());
    println!("{}", "━".repeat(60).dimmed());
    println!();
}

fn print_execution_status(result: &ScanResult) {
    use crate::engine::scan_result::ScanExecutionStatus;

    let failures = result
        .module_outcomes
        .iter()
        .filter(|outcome| outcome.status == crate::engine::scan_result::ModuleOutcomeStatus::Failed)
        .count();
    let dast_failures = result.application_dast.as_ref().map_or(0, |assessment| {
        assessment.gaps.iter().filter(|gap| gap.kind.is_degraded()).count()
    });
    match result.execution_status {
        ScanExecutionStatus::Complete => println!("  {} Complete", "Status:".bold()),
        ScanExecutionStatus::Incomplete => {
            let skipped = result
                .module_outcomes
                .iter()
                .filter(|outcome| {
                    outcome.status == crate::engine::scan_result::ModuleOutcomeStatus::Skipped
                })
                .count();
            println!(
                "  {} {} ({} coverage gap{})",
                "Status:".bold(),
                "INCOMPLETE".yellow().bold(),
                skipped,
                if skipped == 1 { "" } else { "s" }
            );
        }
        ScanExecutionStatus::Degraded => println!(
            "  {} {} ({} execution failure{})",
            "Status:".bold(),
            "DEGRADED".yellow().bold(),
            failures + dast_failures,
            if failures + dast_failures == 1 { "" } else { "s" }
        ),
    }
    if let Some(assessment) = &result.supply_chain {
        println!(
            "  {} {} ({} gap{})",
            "Supply chain:".bold(),
            assessment.coverage_status.as_str(),
            assessment.gaps.len(),
            if assessment.gaps.len() == 1 { "" } else { "s" }
        );
        for gap in &assessment.gaps {
            println!(
                "    - {}/{}{}: {}",
                gap.phase.as_str(),
                gap.kind.as_str(),
                gap.component
                    .as_deref()
                    .map_or_else(String::new, |component| format!(" [{component}]")),
                escape_terminal_text(&gap.detail)
            );
        }
    }
    if let Some(assessment) = &result.application_dast {
        println!(
            "  {} {} ({} persona{}, {} gap{})",
            "Application DAST:".bold(),
            assessment.coverage_status.as_str(),
            assessment.personas.len(),
            if assessment.personas.len() == 1 { "" } else { "s" },
            assessment.gaps.len(),
            if assessment.gaps.len() == 1 { "" } else { "s" }
        );
        for persona in &assessment.personas {
            let observed = persona.routes.iter().filter(|route| route.observed).count();
            println!(
                "    - {}: {:?}, {}/{} routes observed",
                escape_terminal_text(&persona.persona),
                persona.authentication,
                observed,
                persona.routes.len()
            );
        }
        for gap in &assessment.gaps {
            println!(
                "    - {}/{}/{}: {}",
                escape_terminal_text(&gap.persona),
                gap.phase.as_str(),
                gap.kind.as_str(),
                escape_terminal_text(&gap.detail)
            );
        }
    }
}

fn format_duration(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> String {
    let duration = end - start;
    let secs = duration.num_seconds();
    if secs < 1 {
        format!("{}ms", duration.num_milliseconds())
    } else if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_escapes_c0_c1_escape_and_bidi_controls() {
        let input = "title\u{001b}[2J\rforged\u{0007}\u{0085}\u{202e}txt\nnext";
        let rendered = escape_terminal_text(input);
        assert_eq!(rendered, "title\\u{1b}[2J\\u{d}forged\\u{7}\\u{85}\\u{202e}txt\\u{a}next");
        assert!(!rendered.chars().any(char::is_control));
        assert!(!rendered.chars().any(is_bidirectional_format));
        assert_eq!(input.as_bytes()[5], 0x1b, "the source evidence must remain unchanged");
    }

    #[test]
    fn ordinary_terminal_text_is_preserved() {
        assert_eq!(
            escape_terminal_text("SQL injection at /search?q=1"),
            "SQL injection at /search?q=1"
        );
    }

    #[test]
    fn execution_status_contract_distinguishes_failed_modules() {
        let mut result = crate::engine::scan_result::ScanResult::new(
            "terminal-status".to_string(),
            crate::engine::target::Target::parse("https://example.com").expect("target"),
            chrono::Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            result.execution_status,
            crate::engine::scan_result::ScanExecutionStatus::Complete
        );
        result.module_outcomes.push(crate::engine::scan_result::ModuleOutcome::failed(
            "codeql",
            crate::engine::scan_result::ModuleOutcomeReason::ExecutionFailed {
                message: "fixture".to_string(),
            },
        ));
        result.refresh_execution_status();
        assert_eq!(
            result.execution_status,
            crate::engine::scan_result::ScanExecutionStatus::Degraded
        );
    }

    fn one_failure_result() -> ScanResult {
        let mut result = crate::engine::scan_result::ScanResult::new(
            "terminal-status-output".to_string(),
            crate::engine::target::Target::parse("https://example.com").expect("target"),
            chrono::Utc::now(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        result.module_outcomes.push(crate::engine::scan_result::ModuleOutcome::failed(
            "codeql",
            crate::engine::scan_result::ModuleOutcomeReason::ExecutionFailed {
                message: "fixture".to_string(),
            },
        ));
        result.refresh_execution_status();
        result
    }

    #[test]
    fn execution_status_capture_helper() {
        if std::env::var_os("SCORCHKIT_TERMINAL_STATUS_CAPTURE").is_none() {
            return;
        }
        print_execution_status(&one_failure_result());
    }

    #[test]
    fn one_execution_failure_is_rendered_in_the_singular() {
        let output =
            std::process::Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "report::terminal::tests::execution_status_capture_helper",
                    "--nocapture",
                ])
                .env("SCORCHKIT_TERMINAL_STATUS_CAPTURE", "1")
                .env("NO_COLOR", "1")
                .output()
                .expect("run terminal capture helper");
        assert!(output.status.success(), "capture helper failed: {output:?}");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 test output");
        assert!(stdout.contains("(1 execution failure)"), "unexpected output: {stdout:?}");
        assert!(!stdout.contains("(1 execution failures)"), "unexpected output: {stdout:?}");
    }
}
