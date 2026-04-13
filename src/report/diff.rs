use colored::Colorize;

use crate::engine::scan_result::ScanResult;

/// Print a diff between two scan reports.
pub fn print_diff(baseline: &ScanResult, current: &ScanResult) {
    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!("{}", " SCAN COMPARISON".bold());
    println!("{}", "━".repeat(60).dimmed());
    println!();
    println!(
        "  Baseline: {} ({})",
        baseline.scan_id.dimmed(),
        baseline.started_at.format("%Y-%m-%d %H:%M")
    );
    println!(
        "  Current:  {} ({})",
        current.scan_id.dimmed(),
        current.started_at.format("%Y-%m-%d %H:%M")
    );
    println!();

    // Find new findings (in current but not baseline)
    let new_findings: Vec<_> = current
        .findings
        .iter()
        .filter(|cf| {
            !baseline
                .findings
                .iter()
                .any(|bf| bf.title == cf.title && bf.affected_target == cf.affected_target)
        })
        .collect();

    // Find resolved findings (in baseline but not current)
    let resolved_findings: Vec<_> = baseline
        .findings
        .iter()
        .filter(|bf| {
            !current
                .findings
                .iter()
                .any(|cf| cf.title == bf.title && cf.affected_target == bf.affected_target)
        })
        .collect();

    // Find unchanged findings
    let unchanged_count = current.findings.len() - new_findings.len();

    // Summary
    let bs = &baseline.summary;
    let cs = &current.summary;

    println!("  {} findings → {} findings", bs.total_findings, cs.total_findings);

    // JUSTIFICATION: finding counts are small, well within i64 range
    #[allow(clippy::cast_possible_wrap)]
    let delta = cs.total_findings as i64 - bs.total_findings as i64;
    match delta.cmp(&0) {
        std::cmp::Ordering::Greater => {
            println!("  Trend: {} {}", format!("+{delta}").red(), "more findings".dimmed());
        }
        std::cmp::Ordering::Less => {
            println!("  Trend: {} {}", format!("{delta}").green(), "fewer findings".dimmed());
        }
        std::cmp::Ordering::Equal => {
            println!("  Trend: {}", "unchanged".dimmed());
        }
    }

    // New findings
    if !new_findings.is_empty() {
        println!();
        println!(
            "  {} {} new finding{}",
            "+".green().bold(),
            new_findings.len(),
            if new_findings.len() == 1 { "" } else { "s" }
        );
        for f in &new_findings {
            println!("    {} [{}] {}", "+".green(), f.severity.colored_str(), f.title);
        }
    }

    // Resolved findings
    if !resolved_findings.is_empty() {
        println!();
        println!(
            "  {} {} resolved finding{}",
            "-".red().bold(),
            resolved_findings.len(),
            if resolved_findings.len() == 1 { "" } else { "s" }
        );
        for f in &resolved_findings {
            println!(
                "    {} [{}] {}",
                "-".red(),
                f.severity.to_string().dimmed(),
                f.title.dimmed()
            );
        }
    }

    // Unchanged
    if unchanged_count > 0 {
        println!();
        println!(
            "  {} {} unchanged finding{}",
            "=".dimmed(),
            unchanged_count,
            if unchanged_count == 1 { "" } else { "s" }
        );
    }

    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!();
}
