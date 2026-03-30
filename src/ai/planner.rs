//! AI-guided scan planner that uses Claude to build a targeted scan strategy.
//!
//! [`ScanPlanner`] implements a two-phase approach: first runs reconnaissance
//! modules to gather target intelligence, then feeds those findings plus a
//! catalog of available scan modules to Claude. Claude returns a structured
//! [`ScanPlan`] specifying which modules to run and why.

use std::sync::Arc;

use crate::ai::prompts;
use crate::ai::response;
use crate::ai::types::{validate_plan, ScanPlan};
use crate::config::{AiConfig, AppConfig};
use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ModuleCategory;
use crate::engine::scan_context::ScanContext;
use crate::engine::target::Target;
use crate::runner::orchestrator::{all_modules, Orchestrator};

/// AI-powered scan planner that analyzes recon results to build a targeted strategy.
#[derive(Debug)]
pub struct ScanPlanner {
    claude_binary: String,
    model: String,
    max_budget: f64,
}

impl ScanPlanner {
    /// Create a new planner from AI config.
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

    /// Run recon, then ask Claude to build a scan plan.
    ///
    /// 1. Runs all recon modules against the target
    /// 2. Builds a module catalog from all available modules
    /// 3. Sends recon findings + catalog to Claude
    /// 4. Parses and validates the response into a [`ScanPlan`]
    ///
    /// # Errors
    ///
    /// Returns an error if the recon phase fails or the Claude CLI
    /// cannot be executed. Parse failures are handled gracefully by
    /// returning an empty plan.
    pub async fn plan(&self, target: &Target, config: &Arc<AppConfig>) -> Result<ScanPlan> {
        // Phase A: Run recon
        let http_client = build_recon_client(config)?;
        let ctx = ScanContext::new(target.clone(), Arc::clone(config), http_client);

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_category(ModuleCategory::Recon);

        let recon_result = orchestrator.run(true).await?;

        // Phase B: Build prompt and call Claude
        let modules = all_modules();
        let catalog = prompts::build_module_catalog(&modules);
        let prompt = prompts::build_planning_prompt(
            target.url.as_str(),
            &recon_result.findings,
            &catalog,
            None, // Intelligence context passed by agent runner when project available
        );

        let plan_output = self.run_claude(&prompt, &target.raw).await?;

        // Parse and validate
        let raw_plan = response::parse_plan_response(&plan_output, target.url.as_str());
        let known_ids: Vec<&str> = modules.iter().map(|m| m.id()).collect();
        let validation = validate_plan(&raw_plan, &known_ids);

        if !validation.unknown_modules.is_empty() {
            tracing::warn!(
                unknown = ?validation.unknown_modules,
                "scan plan contained unknown module IDs — these were removed"
            );
        }

        Ok(ScanPlan {
            target: raw_plan.target,
            recommendations: validation.valid_recommendations,
            skipped_modules: raw_plan.skipped_modules,
            overall_strategy: raw_plan.overall_strategy,
            estimated_scan_time: raw_plan.estimated_scan_time,
        })
    }

    /// Run the Claude CLI with a prompt and return the raw output.
    async fn run_claude(&self, prompt: &str, scan_id: &str) -> Result<String> {
        let prompt_file = std::env::temp_dir().join(format!("scorchkit-plan-{scan_id}.txt"));
        std::fs::write(&prompt_file, prompt)
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

        let _ = std::fs::remove_file(&prompt_file);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScorchError::AiAnalysis(format!(
                "claude exited with status {}: {stderr}",
                output.status.code().unwrap_or(-1)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Build an HTTP client for recon operations.
fn build_recon_client(config: &AppConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .cookie_store(true)
        .danger_accept_invalid_certs(false);

    if config.scan.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(config.scan.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    if let Some(ref proxy_url) = config.scan.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}
