//! Parameter types for MCP tool inputs.
//!
//! Each struct represents the input schema for one or more MCP tools.
//! They derive `Deserialize` for JSON-RPC parameter parsing and
//! `JsonSchema` for automatic schema generation by the `rmcp` macros.
//! Field `///` doc comments become `description` fields in the generated
//! JSON Schema, helping Claude understand each parameter's purpose.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for the `scan` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Target URL, domain, or IP address to scan. Examples: "<https://example.com>",
    /// "example.com" (defaults to HTTPS), "192.168.1.1". Must be a host the user
    /// has authorized for testing.
    pub target: String,
    /// Scan profile controlling which modules run. "quick" = 4 recon modules
    /// (headers, tech, ssl, misconfig) for fast initial assessment. "standard" =
    /// all 20 built-in modules covering OWASP Top 10. "thorough" = all 41
    /// modules including external tools (requires tools installed). Defaults to
    /// "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Comma-separated list of specific module IDs to run, ignoring the profile.
    /// Example: "headers,ssl,xss". Get valid IDs from `list_modules`. Use when you
    /// want to run only specific checks based on `plan_scan` recommendations.
    pub modules: Option<String>,
    /// Comma-separated list of module IDs to exclude from the profile. Example:
    /// "nmap,nuclei" to skip slow external tools. Takes effect after profile
    /// filtering.
    pub skip: Option<String>,
}

fn default_profile() -> String {
    "standard".to_string()
}

/// Parameters for creating a new project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectCreateParams {
    /// Unique project name. Use descriptive names like "example-com-assessment"
    /// or "client-webapp-2024". Referenced by name in all other project tools.
    pub name: String,
    /// Optional description of the project scope and purpose. Helps identify
    /// the project later.
    pub description: Option<String>,
}

/// Parameters that reference a project by name or UUID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectRefParams {
    /// Project name or UUID. Use the human-readable name (e.g., "my-project")
    /// rather than the UUID for convenience.
    pub project: String,
}

/// Parameters for deleting a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectDeleteParams {
    /// Project name or UUID to delete.
    pub project: String,
    /// Must be set to true to confirm deletion. Without force=true, returns a
    /// warning instead of deleting. This prevents accidental data loss.
    #[serde(default)]
    pub force: bool,
}

/// Parameters for scanning within a project context.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectScanParams {
    /// Project name or UUID. Results will be persisted under this project with
    /// automatic finding deduplication.
    pub project: String,
    /// Target URL to scan. Must be a URL the user has authorized for testing.
    pub target: String,
    /// Scan profile: "quick" for fast recon (4 modules), "standard" for full
    /// built-in assessment (20 modules), "thorough" for all modules including
    /// external tools (41 modules). Defaults to "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// Parameters for adding a target to a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetAddParams {
    /// Project name or UUID to add the target to.
    pub project: String,
    /// Target URL to register. Example: "<https://example.com>". This URL will
    /// be available for `project_scan` operations.
    pub url: String,
    /// Optional human-readable label for the target, such as "production API"
    /// or "staging frontend".
    pub label: Option<String>,
}

/// Parameters for removing a target from a project.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetRemoveParams {
    /// Project name or UUID containing the target.
    pub project: String,
    /// Target UUID to remove. Get target UUIDs from `target_list`.
    pub id: String,
}

/// Parameters for listing findings with optional filters.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingListParams {
    /// Project name or UUID to list findings for.
    pub project: String,
    /// Filter findings by severity level. Valid values: "critical", "high",
    /// "medium", "low", "info". Omit to return all severities.
    pub severity: Option<String>,
    /// Filter findings by lifecycle status. Valid values: "new",
    /// "acknowledged", "`false_positive`", "remediated", "verified". Omit to
    /// return all statuses.
    pub status: Option<String>,
}

/// Parameters that reference a single finding by UUID.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingRefParams {
    /// Finding UUID. Get finding UUIDs from `project_findings` results.
    pub id: String,
}

/// Parameters for updating a finding's lifecycle status.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindingUpdateStatusParams {
    /// Finding UUID to update. Get from `project_findings` results.
    pub id: String,
    /// New lifecycle status. Valid transitions: "new" -> "acknowledged" ->
    /// "remediated" -> "verified", or "new"/"acknowledged" -> "`false_positive`".
    pub status: String,
}

/// Parameters for creating a recurring scan schedule.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScheduleScanParams {
    /// Project name or UUID to create the schedule for.
    pub project: String,
    /// Target URL to scan on the recurring schedule.
    pub target: String,
    /// Standard 5-field cron expression defining the recurrence pattern. Examples:
    /// "0 0 * * *" (daily at midnight), "0 */6 * * *" (every 6 hours),
    /// "0 9 * * 1" (Mondays at 9am).
    pub cron: String,
    /// Scan profile for scheduled runs. "quick", "standard", or "thorough".
    /// Defaults to "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// Parameters for AI-guided scan planning.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanScanParams {
    /// Target URL, domain, or IP address to plan a scan for. The planner will
    /// run recon modules first, then recommend which scanner modules to use
    /// based on the target's tech stack and attack surface.
    pub target: String,
}

/// Parameters for retrieving project security posture metrics.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProjectStatusParams {
    /// Project name or UUID to get posture metrics for. The project should have
    /// at least one completed scan for meaningful metrics.
    pub project: String,
}

/// Parameters for AI-powered analysis of project findings.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFindingsParams {
    /// Project name or UUID containing the findings to analyze.
    pub project: String,
    /// Analysis focus mode. "summary" = executive overview with 0-10 risk score.
    /// "prioritize" = findings ranked by exploitability with attack chains.
    /// "remediate" = fix steps with effort estimates and code examples.
    /// "filter" = false positive classification with confidence scores.
    /// Defaults to "summary".
    #[serde(default = "default_focus")]
    pub focus: String,
    /// Optional scan UUID to analyze findings from a specific scan only. If
    /// omitted, analyzes all findings across all scans for the project. Get
    /// scan UUIDs from `project_show`.
    pub scan_id: Option<String>,
}

fn default_focus() -> String {
    "summary".to_string()
}

/// Parameters for the `auto_scan` composite tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AutoScanParams {
    /// Target URL to scan. Examples: "<https://example.com>", "example.com".
    /// Must be a host the user has authorized for testing.
    pub target: String,
    /// Scan profile: "quick" (recon only), "standard" (all built-in modules),
    /// "thorough" (all modules including external tools). Defaults to "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Optional project name to persist results to. If provided, findings are
    /// deduplicated and stored in the project database. If omitted, results
    /// are returned without persistence.
    pub project: Option<String>,
}

/// Parameters for the `target_intelligence` recon-only tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TargetIntelligenceParams {
    /// Target URL to gather intelligence on. Runs only recon-category modules
    /// (headers, tech detection, discovery, subdomain enumeration, crawling,
    /// DNS security) without any active vulnerability scanning.
    pub target: String,
}

/// Parameters for the `scan_progress` status check tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanProgressParams {
    /// Project name or UUID to check scan status for. Returns the most recent
    /// scan record with metadata, finding counts, and timing.
    pub project: String,
}

/// Parameters for the `correlate_findings` attack chain analysis tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CorrelateFindingsParams {
    /// Project name or UUID to analyze findings for. Loads all findings and
    /// applies rule-based correlation to identify attack chains where
    /// multiple findings combine into compound vulnerabilities.
    pub project: String,
}
