//! Parameter types for MCP tool inputs.
//!
//! Each struct represents the input schema for one or more MCP tools.
//! They derive `Deserialize` for JSON-RPC parameter parsing and
//! `JsonSchema` for automatic schema generation by the `rmcp` macros.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for the `scan` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Target URL, domain, or IP address to scan.
    pub target: String,
    /// Scan profile: "quick", "standard", or "thorough".
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Comma-separated list of specific module IDs to run.
    pub modules: Option<String>,
    /// Comma-separated list of module IDs to skip.
    pub skip: Option<String>,
}

fn default_profile() -> String {
    "standard".to_string()
}

/// Parameters for creating a new project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectCreateParams {
    /// Project name (must be unique).
    pub name: String,
    /// Optional project description.
    pub description: Option<String>,
}

/// Parameters that reference a project by name or UUID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectRefParams {
    /// Project name or UUID.
    pub project: String,
}

/// Parameters for deleting a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectDeleteParams {
    /// Project name or UUID.
    pub project: String,
    /// If true, delete without confirmation. Defaults to false.
    #[serde(default)]
    pub force: bool,
}

/// Parameters for scanning within a project context.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectScanParams {
    /// Project name or UUID.
    pub project: String,
    /// Target URL to scan.
    pub target: String,
    /// Scan profile: "quick", "standard", or "thorough".
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// Parameters for adding a target to a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetAddParams {
    /// Project name or UUID.
    pub project: String,
    /// Target URL to add.
    pub url: String,
    /// Optional human-readable label for the target.
    pub label: Option<String>,
}

/// Parameters for removing a target from a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetRemoveParams {
    /// Project name or UUID.
    pub project: String,
    /// Target UUID to remove.
    pub id: String,
}

/// Parameters for listing findings with optional filters.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingListParams {
    /// Project name or UUID.
    pub project: String,
    /// Filter by severity (critical, high, medium, low, info).
    pub severity: Option<String>,
    /// Filter by status (new, acknowledged, `false_positive`, remediated, verified).
    pub status: Option<String>,
}

/// Parameters that reference a single finding by UUID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingRefParams {
    /// Finding UUID.
    pub id: String,
}

/// Parameters for updating a finding's lifecycle status.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingUpdateStatusParams {
    /// Finding UUID.
    pub id: String,
    /// New status: new, acknowledged, `false_positive`, remediated, or verified.
    pub status: String,
}

/// Parameters for retrieving project security posture metrics.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectStatusParams {
    /// Project name or UUID.
    pub project: String,
}

/// Parameters for AI-powered analysis of project findings.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFindingsParams {
    /// Project name or UUID containing the findings to analyze.
    pub project: String,
    /// Analysis focus: "summary", "prioritize", "remediate", or "filter".
    #[serde(default = "default_focus")]
    pub focus: String,
    /// Optional scan UUID to analyze findings from a specific scan.
    /// If omitted, analyzes all findings for the project.
    pub scan_id: Option<String>,
}

fn default_focus() -> String {
    "summary".to_string()
}
