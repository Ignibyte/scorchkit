//! AI analyst that uses Claude CLI for structured security finding analysis.
//!
//! Provides [`AiAnalyst`] for running Claude-powered analysis of scan findings
//! with typed JSON responses, and [`print_analysis`] for rich terminal rendering
//! of structured results.

use colored::Colorize;

use crate::ai::prompts::{self, AnalysisFocus};
use crate::ai::response;
use crate::ai::types::{
    AiAnalysis, EffortLevel, ExploitabilityRating, FilterAnalysis, FindingClassification,
    PrioritizedAnalysis, ProjectContext, RemediationAnalysis, StructuredAnalysis, SummaryAnalysis,
};
use crate::config::AiConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::scan_result::ScanResult;

/// AI analyst that uses Claude CLI for security finding analysis.
#[derive(Debug)]
pub struct AiAnalyst {
    claude_binary: String,
    model: String,
    max_budget: f64,
}

impl AiAnalyst {
    /// Create a new analyst from config.
    #[must_use]
    pub fn from_config(config: &AiConfig) -> Self {
        Self {
            claude_binary: config.claude_binary.clone(),
            model: config.model.clone(),
            max_budget: config.max_budget_usd,
        }
    }

    /// Check if the claude CLI is available.
    #[must_use]
    pub fn is_available(&self) -> bool {
        std::process::Command::new("which")
            .arg(&self.claude_binary)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Analyze scan findings using Claude with optional project context.
    ///
    /// When `project_context` is provided, trend data and finding lifecycle
    /// statistics are injected into the prompt for more contextual analysis.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt file cannot be written, the Claude CLI
    /// fails to execute, or the subprocess exits with a non-zero status.
    pub async fn analyze(
        &self,
        result: &ScanResult,
        focus: AnalysisFocus,
        project_context: Option<&ProjectContext>,
    ) -> Result<AiAnalysis> {
        if result.findings.is_empty() {
            return Ok(AiAnalysis {
                focus,
                analysis: StructuredAnalysis::Raw {
                    content: "No findings to analyze. The scan produced no results.".to_string(),
                },
                raw_response: String::new(),
                cost_usd: None,
                model: None,
            });
        }

        let prompt = prompts::build_prompt(result, focus, project_context);

        // Write prompt to a temp file to avoid shell escaping issues with large prompts
        let prompt_file =
            std::env::temp_dir().join(format!("scorchkit-prompt-{}.txt", result.scan_id));
        std::fs::write(&prompt_file, &prompt)
            .map_err(|e| ScorchError::AiAnalysis(format!("failed to write prompt file: {e}")))?;

        let prompt_content = std::fs::read_to_string(&prompt_file)
            .map_err(|e| ScorchError::AiAnalysis(format!("failed to read prompt file: {e}")))?;

        let budget_str = self.max_budget.to_string();
        let output = tokio::process::Command::new(&self.claude_binary)
            .args([
                "-p",
                &prompt_content,
                "--output-format",
                "json",
                "--model",
                &self.model,
                "--max-turns",
                "1",
                "--max-budget-usd",
                &budget_str,
            ])
            .output()
            .await
            .map_err(|e| ScorchError::AiAnalysis(format!("failed to run claude: {e}")))?;

        // Clean up temp file
        let _ = std::fs::remove_file(&prompt_file);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScorchError::AiAnalysis(format!(
                "claude exited with status {}: {stderr}",
                output.status.code().unwrap_or(-1)
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(response::parse_claude_response(&stdout, focus))
    }
}

/// Print an AI analysis to the terminal with structured formatting.
///
/// Dispatches to mode-specific renderers for structured results, or prints
/// raw text for the fallback variant.
pub fn print_analysis(analysis: &AiAnalysis) {
    println!();
    println!("{}", "\u{2501}".repeat(60).dimmed());
    println!(" {} {}", "AI ANALYSIS".bold(), format!("({})", analysis.focus.label()).dimmed());
    println!("{}", "\u{2501}".repeat(60).dimmed());
    println!();

    match &analysis.analysis {
        StructuredAnalysis::Summary(s) => print_summary(s),
        StructuredAnalysis::Prioritized(p) => print_prioritized(p),
        StructuredAnalysis::Remediation(r) => print_remediation(r),
        StructuredAnalysis::Filter(f) => print_filter(f),
        StructuredAnalysis::Raw { content } => println!("{content}"),
    }

    println!();

    if let Some(cost) = analysis.cost_usd {
        print!("  {}", format!("Cost: ${cost:.4}").dimmed());
    }
    if let Some(ref model) = analysis.model {
        print!("  {}", format!("Model: {model}").dimmed());
    }
    if analysis.cost_usd.is_some() || analysis.model.is_some() {
        println!();
    }

    println!("{}", "\u{2501}".repeat(60).dimmed());
    println!();
}

/// Render a structured executive summary.
fn print_summary(s: &SummaryAnalysis) {
    let score_color = if s.risk_score >= 7.0 {
        format!("{:.1}/10", s.risk_score).red().bold()
    } else if s.risk_score >= 4.0 {
        format!("{:.1}/10", s.risk_score).yellow().bold()
    } else {
        format!("{:.1}/10", s.risk_score).green().bold()
    };

    println!("  {} {}", "Risk Score:".bold(), score_color);
    println!();
    println!("{}", s.executive_summary);
    println!();

    if !s.key_findings.is_empty() {
        println!("  {}", "Key Findings:".bold().underline());
        for kf in &s.key_findings {
            println!(
                "    #{} [{}] {} \u{2014} {}",
                kf.finding_index,
                colorize_severity(&kf.severity),
                kf.title,
                kf.business_impact.dimmed(),
            );
        }
        println!();
    }

    println!("  {}", "Attack Surface:".bold());
    println!("    {}", s.attack_surface);
    println!();
    println!("  {}", "Business Impact:".bold());
    println!("    {}", s.business_impact);
}

/// Render a prioritized risk assessment.
fn print_prioritized(p: &PrioritizedAnalysis) {
    println!("  {}", "Prioritized Findings:".bold().underline());
    for (rank, pf) in p.prioritized_findings.iter().enumerate() {
        println!(
            "    {}. #{} [{}] {} (impact: {:.1}, exploit: {})",
            rank + 1,
            pf.finding_index,
            colorize_severity(&pf.severity),
            pf.title,
            pf.business_impact_score,
            format_exploitability(pf.exploitability),
        );
        println!("       {}", pf.rationale.dimmed());
    }

    if !p.attack_chains.is_empty() {
        println!();
        println!("  {}", "Attack Chains:".bold().underline());
        for chain in &p.attack_chains {
            let indices: Vec<String> =
                chain.finding_indices.iter().map(|i| format!("#{i}")).collect();
            println!(
                "    {} [{}] \u{2014} {}",
                chain.name.bold(),
                indices.join(" \u{2192} "),
                chain.combined_impact,
            );
        }
    }

    if !p.recommended_fix_order.is_empty() {
        println!();
        let order: Vec<String> = p.recommended_fix_order.iter().map(|i| format!("#{i}")).collect();
        println!("  {} {}", "Fix Order:".bold(), order.join(" \u{2192} "));
    }
}

/// Render a remediation guide.
fn print_remediation(r: &RemediationAnalysis) {
    println!("  {} {}", "Total Effort:".bold(), r.total_estimated_effort);
    println!();

    if !r.quick_wins.is_empty() {
        let wins: Vec<String> = r.quick_wins.iter().map(|i| format!("#{i}")).collect();
        println!("  {} {}", "Quick Wins:".green().bold(), wins.join(", "));
        println!();
    }

    for step in &r.remediations {
        println!(
            "  {}. #{} [{}] {}",
            step.priority,
            step.finding_index,
            colorize_severity(&step.severity),
            step.title.bold(),
        );
        println!("     {}", step.fix_description);
        if let Some(ref code) = step.code_example {
            println!("     {}", "Example:".dimmed());
            for line in code.lines() {
                println!("       {}", line.cyan());
            }
        }
        println!("     {} {}", "Effort:".dimmed(), format_effort(step.effort));
        if !step.verification_steps.is_empty() {
            println!("     {}", "Verify:".dimmed());
            for vs in &step.verification_steps {
                println!("       \u{2022} {vs}");
            }
        }
        println!();
    }
}

/// Render a false positive analysis.
fn print_filter(f: &FilterAnalysis) {
    println!(
        "  {} confirmed, {} false positive{}, {} uncertain",
        f.confirmed_count.to_string().green().bold(),
        f.false_positive_count.to_string().yellow().bold(),
        if f.false_positive_count == 1 { "" } else { "s" },
        f.uncertain_count.to_string().dimmed(),
    );
    println!();

    for ff in &f.findings {
        let badge = match ff.classification {
            FindingClassification::Confirmed => "CONFIRMED".green(),
            FindingClassification::LikelyTrue => "LIKELY TRUE".green(),
            FindingClassification::Uncertain => "UNCERTAIN".yellow(),
            FindingClassification::LikelyFalsePositive => "LIKELY FP".red(),
            FindingClassification::FalsePositive => "FALSE POS".red(),
        };
        println!(
            "  #{} [{}] {} ({:.0}% confidence)",
            ff.finding_index,
            badge,
            ff.title,
            ff.confidence * 100.0,
        );
        println!("     {}", ff.rationale.dimmed());
    }
}

/// Colorize a severity string for terminal output.
fn colorize_severity(severity: &str) -> colored::ColoredString {
    match severity.to_lowercase().as_str() {
        "critical" => severity.to_uppercase().red().bold(),
        "high" => severity.to_uppercase().red(),
        "medium" => severity.to_uppercase().yellow(),
        "low" => severity.to_uppercase().blue(),
        _ => severity.to_uppercase().dimmed(),
    }
}

/// Format an exploitability rating for display.
fn format_exploitability(rating: ExploitabilityRating) -> colored::ColoredString {
    match rating {
        ExploitabilityRating::Critical => "critical".red().bold(),
        ExploitabilityRating::High => "high".red(),
        ExploitabilityRating::Medium => "medium".yellow(),
        ExploitabilityRating::Low => "low".blue(),
        ExploitabilityRating::Theoretical => "theoretical".dimmed(),
    }
}

/// Format an effort level for display.
fn format_effort(effort: EffortLevel) -> colored::ColoredString {
    match effort {
        EffortLevel::Trivial => "trivial (<1h)".green(),
        EffortLevel::Low => "low (1-4h)".green(),
        EffortLevel::Medium => "medium (1-2d)".yellow(),
        EffortLevel::High => "high (1-2w)".red(),
        EffortLevel::Major => "major (2w+)".red().bold(),
    }
}
