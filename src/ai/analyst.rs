use colored::Colorize;

use crate::ai::prompts::{self, AnalysisFocus};
use crate::ai::response::{self, AiAnalysis};
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
    pub fn from_config(config: &AiConfig) -> Self {
        Self {
            claude_binary: config.claude_binary.clone(),
            model: config.model.clone(),
            max_budget: config.max_budget_usd,
        }
    }

    /// Check if the claude CLI is available.
    pub fn is_available(&self) -> bool {
        std::process::Command::new("which")
            .arg(&self.claude_binary)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Analyze scan findings using Claude.
    pub async fn analyze(&self, result: &ScanResult, focus: AnalysisFocus) -> Result<AiAnalysis> {
        if result.findings.is_empty() {
            return Ok(AiAnalysis {
                focus: focus.label(),
                content: "No findings to analyze. The scan produced no results.".to_string(),
                cost_usd: None,
                model: None,
            });
        }

        let prompt = prompts::build_prompt(result, focus);

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

/// Print an AI analysis to the terminal.
pub fn print_analysis(analysis: &AiAnalysis) {
    println!();
    println!("{}", "━".repeat(60).dimmed());
    println!(" {} {}", "AI ANALYSIS".bold(), format!("({})", analysis.focus).dimmed());
    println!("{}", "━".repeat(60).dimmed());
    println!();
    println!("{}", analysis.content);
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

    println!("{}", "━".repeat(60).dimmed());
    println!();
}
