use colored::Colorize;

use crate::engine::scan_result::ScanResult;

/// Print a scan report to the terminal with colors.
pub fn print_report(result: &ScanResult) {
    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!("{}", " SCAN RESULTS".bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();

    // Summary
    let s = &result.summary;
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
            println!("    {} {}: {}", "-".dimmed(), id.dimmed(), reason.dimmed());
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
                finding.title.bold()
            );
            println!("  {}", finding.description.dimmed());
            println!("  Target: {}", finding.affected_target.cyan());

            if let Some(evidence) = &finding.evidence {
                println!("  Evidence: {}", evidence.yellow());
            }

            if let Some(remediation) = &finding.remediation {
                println!("  Fix: {}", remediation.green());
            }

            if let Some(owasp) = &finding.owasp_category {
                print!("  {}", owasp.dimmed());
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
    println!("  Scan ID: {}", result.scan_id.dimmed());
    println!("  Duration: {}", format_duration(result.started_at, result.completed_at).dimmed());
    println!("{}", "━".repeat(60).dimmed());
    println!();
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
