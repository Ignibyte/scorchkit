//! Structured analysis types for AI-powered security finding analysis.
//!
//! Defines typed response structs for each analysis mode (summary, prioritize,
//! remediate, filter) and a [`StructuredAnalysis`] enum wrapper with a `Raw`
//! fallback for when JSON parsing fails. Also defines [`ProjectContext`] for
//! injecting project history into AI prompts, and the updated [`AiAnalysis`]
//! struct that replaces the previous raw-text response.

use serde::{Deserialize, Serialize};

use crate::ai::prompts::AnalysisFocus;

// ── Shared enums ────────────────────────────────────────────────────────

/// How easily a vulnerability can be exploited in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitabilityRating {
    /// Trivially exploitable — public exploits or tools exist.
    Critical,
    /// Exploitable with minimal skill or custom tooling.
    High,
    /// Requires moderate effort, knowledge, or specific conditions.
    Medium,
    /// Difficult to exploit in realistic scenarios.
    Low,
    /// Requires unlikely conditions or chained prerequisites.
    Theoretical,
}

/// Estimated developer effort to remediate a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffortLevel {
    /// Less than 1 hour.
    Trivial,
    /// 1-4 hours.
    Low,
    /// 1-2 days.
    Medium,
    /// 1-2 weeks.
    High,
    /// More than 2 weeks.
    Major,
}

/// AI confidence classification for a finding's validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClassification {
    /// Confirmed true positive with high confidence.
    Confirmed,
    /// Likely a true positive based on evidence.
    LikelyTrue,
    /// Insufficient evidence to determine.
    Uncertain,
    /// Likely a false positive based on context.
    LikelyFalsePositive,
    /// Confirmed false positive with reasoning.
    FalsePositive,
}

// ── Summary mode ────────────────────────────────────────────────────────

/// Structured response for the executive summary analysis mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryAnalysis {
    /// Overall risk score from 0.0 (no risk) to 10.0 (critical).
    pub risk_score: f64,
    /// 1-2 paragraph executive summary.
    pub executive_summary: String,
    /// The most important findings with business context.
    pub key_findings: Vec<KeyFinding>,
    /// Assessment of the target's overall attack surface.
    pub attack_surface: String,
    /// Business impact summary.
    pub business_impact: String,
}

/// A key finding highlighted in the executive summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    /// References finding index (#N) from the input.
    pub finding_index: usize,
    /// Severity level as a string (e.g., "critical", "high").
    pub severity: String,
    /// Finding title.
    pub title: String,
    /// Why this finding matters to the business.
    pub business_impact: String,
    /// How easily this can be exploited.
    pub exploitability: ExploitabilityRating,
}

// ── Prioritize mode ─────────────────────────────────────────────────────

/// Structured response for the prioritized risk assessment mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedAnalysis {
    /// Findings ranked by real-world exploitability.
    pub prioritized_findings: Vec<PrioritizedFinding>,
    /// Groups of findings that form attack chains.
    pub attack_chains: Vec<AttackChain>,
    /// Recommended fix order as finding indices.
    pub recommended_fix_order: Vec<usize>,
}

/// A finding ranked by exploitability and business impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedFinding {
    /// References finding index (#N) from the input.
    pub finding_index: usize,
    /// Finding title.
    pub title: String,
    /// Severity level as a string.
    pub severity: String,
    /// How easily this can be exploited.
    pub exploitability: ExploitabilityRating,
    /// Business impact score from 0.0 to 10.0.
    pub business_impact_score: f64,
    /// Effort an attacker needs to exploit this.
    pub effort_to_exploit: EffortLevel,
    /// Reasoning for the ranking.
    pub rationale: String,
}

/// A chain of findings that combine for greater impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Descriptive name for the attack chain.
    pub name: String,
    /// Finding indices involved in this chain.
    pub finding_indices: Vec<usize>,
    /// What an attacker achieves via the combined chain.
    pub combined_impact: String,
    /// Likelihood assessment (e.g., "high", "medium", "low").
    pub likelihood: String,
}

// ── Remediate mode ──────────────────────────────────────────────────────

/// Structured response for the remediation guide mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAnalysis {
    /// Ordered remediation steps for each finding.
    pub remediations: Vec<RemediationStep>,
    /// Finding indices that are quick wins (low effort, high impact).
    pub quick_wins: Vec<usize>,
    /// Estimated total effort across all remediations.
    pub total_estimated_effort: String,
}

/// A specific remediation step for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    /// References finding index (#N) from the input.
    pub finding_index: usize,
    /// Finding title.
    pub title: String,
    /// Severity level as a string.
    pub severity: String,
    /// Detailed description of the fix.
    pub fix_description: String,
    /// Optional code or configuration example.
    pub code_example: Option<String>,
    /// Estimated developer effort.
    pub effort: EffortLevel,
    /// Priority rank (1 = fix first).
    pub priority: u32,
    /// Steps to verify the fix worked.
    pub verification_steps: Vec<String>,
}

// ── Filter mode ─────────────────────────────────────────────────────────

/// Structured response for the false positive analysis mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAnalysis {
    /// Classification for each finding.
    pub findings: Vec<FilteredFinding>,
    /// Count of findings classified as false positives.
    pub false_positive_count: usize,
    /// Count of confirmed true positives.
    pub confirmed_count: usize,
    /// Count of findings that could not be determined.
    pub uncertain_count: usize,
}

/// A finding with its false-positive classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredFinding {
    /// References finding index (#N) from the input.
    pub finding_index: usize,
    /// Finding title.
    pub title: String,
    /// AI classification of this finding's validity.
    pub classification: FindingClassification,
    /// Confidence in the classification from 0.0 to 1.0.
    pub confidence: f64,
    /// Reasoning for the classification.
    pub rationale: String,
}

// ── Wrapper enum ────────────────────────────────────────────────────────

/// Structured analysis result, one variant per analysis mode.
///
/// The `Raw` variant serves as a graceful fallback when the AI response
/// cannot be parsed into a typed struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredAnalysis {
    /// Executive summary with risk score and key findings.
    Summary(SummaryAnalysis),
    /// Findings ranked by exploitability with attack chains.
    Prioritized(PrioritizedAnalysis),
    /// Detailed remediation steps with effort estimates.
    Remediation(RemediationAnalysis),
    /// False positive classification for each finding.
    Filter(FilterAnalysis),
    /// Unparsed raw text — fallback when JSON extraction fails.
    Raw {
        /// The raw analysis text from Claude.
        content: String,
    },
}

// ── Project context ─────────────────────────────────────────────────────

/// Project history context injected into AI prompts for trend-aware analysis.
///
/// This type is always available (no feature gate). The builder function
/// that populates it from the database lives in `storage::context` and is
/// gated behind the `storage` feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectContext {
    /// Project name.
    pub project_name: String,
    /// Total number of scans run against this project.
    pub total_scans: usize,
    /// Date of the most recent scan, if any.
    pub latest_scan_date: Option<String>,
    /// Finding trend data across scans.
    pub finding_trends: FindingTrends,
}

/// Finding trends across a project's scan history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingTrends {
    /// Total tracked findings in the project.
    pub total_tracked: usize,
    /// Breakdown by vulnerability lifecycle status.
    pub by_status: StatusBreakdown,
}

/// Count of findings in each vulnerability lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusBreakdown {
    /// Newly discovered, not yet triaged.
    pub new: usize,
    /// Acknowledged by the team.
    pub acknowledged: usize,
    /// Determined to be a false positive.
    pub false_positive: usize,
    /// Fix has been applied.
    pub remediated: usize,
    /// Fix has been verified by re-scan.
    pub verified: usize,
}

// ── Scan planning types ────────────────────────────────────────────────

/// AI-generated scan plan based on recon analysis.
///
/// Produced by [`crate::ai::planner::ScanPlanner`] after Claude analyzes
/// reconnaissance results and the available module catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    /// The target being scanned.
    pub target: String,
    /// Modules Claude recommends running, ordered by priority.
    pub recommendations: Vec<ModuleRecommendation>,
    /// Modules Claude recommends skipping, with justification.
    pub skipped_modules: Vec<SkippedModule>,
    /// Claude's high-level strategy description.
    pub overall_strategy: String,
    /// Rough time estimate for executing the plan.
    pub estimated_scan_time: Option<String>,
}

/// A recommended scan module with priority and rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecommendation {
    /// Module ID — must match a registered module.
    pub module_id: String,
    /// Execution priority (1 = first).
    pub priority: u32,
    /// Why this module should run against this target.
    pub rationale: String,
    /// Module category (recon, scanner).
    pub category: String,
}

/// A module Claude recommends skipping, with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedModule {
    /// Module ID.
    pub module_id: String,
    /// Why Claude recommends skipping this module.
    pub reason: String,
}

/// Result of validating a scan plan against registered modules.
#[derive(Debug, Clone)]
pub struct PlanValidation {
    /// Recommendations with valid (registered) module IDs.
    pub valid_recommendations: Vec<ModuleRecommendation>,
    /// Module IDs that were in the plan but don't match any registered module.
    pub unknown_modules: Vec<String>,
}

/// Validate a scan plan's module recommendations against a list of known module IDs.
///
/// Moves recommendations with unrecognized `module_id` values into the
/// `unknown_modules` list, preserving only valid ones.
#[must_use]
pub fn validate_plan(plan: &ScanPlan, known_ids: &[&str]) -> PlanValidation {
    let mut valid = Vec::new();
    let mut unknown = Vec::new();

    for rec in &plan.recommendations {
        if known_ids.contains(&rec.module_id.as_str()) {
            valid.push(rec.clone());
        } else {
            unknown.push(rec.module_id.clone());
        }
    }

    PlanValidation { valid_recommendations: valid, unknown_modules: unknown }
}

// ── Updated AiAnalysis ──────────────────────────────────────────────────

/// Complete result from an AI analysis session.
///
/// Contains the structured (or raw fallback) analysis, metadata about
/// the analysis run, and the original Claude response for debugging.
#[derive(Debug, Clone)]
pub struct AiAnalysis {
    /// Which analysis mode was used.
    pub focus: AnalysisFocus,
    /// Parsed structured analysis or raw fallback.
    pub analysis: StructuredAnalysis,
    /// The unmodified response text from Claude.
    pub raw_response: String,
    /// Cost of the analysis in USD, if reported.
    pub cost_usd: Option<f64>,
    /// Model used for the analysis.
    pub model: Option<String>,
}
