//! Parameter types for MCP tool inputs.
//!
//! Each struct represents the input schema for one or more MCP tools.
//! They derive `Deserialize` for JSON-RPC parameter parsing and
//! `JsonSchema` for automatic schema generation by the `rmcp` macros.
//! Field `///` doc comments become `description` fields in the generated
//! JSON Schema, helping any MCP agent understand each parameter's purpose.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for the `scan` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Target URL, domain, or IP address to scan. Examples: "<https://example.com>",
    /// "example.com" (defaults to HTTPS), "192.168.1.1". Must be a host the user
    /// has authorized for testing.
    pub target: String,
    /// Scan profile controlling which modules run. "quick" = 4 safe recon
    /// modules. "standard" = built-in modules only. "thorough" adds
    /// non-restricted external tools. "pentest" adds credential/exploit modules
    /// and requires explicit engagement grants. Defaults to "standard".
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

/// Parameters for a scan-job lookup, cancellation, or resume.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanJobRefParams {
    /// Scan job UUID returned by `scan_job_start` or `scan_job_resume`.
    pub job_id: String,
}

fn default_profile() -> String {
    "standard".to_string()
}

const fn default_true() -> bool {
    true
}

/// One digest-pinned local schema for `application_dast`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationDastSchemaParams {
    /// `open_api` or `graph_ql`.
    pub kind: String,
    /// Existing local schema file.
    pub path: String,
    /// Expected lowercase SHA-256 of the exact file bytes.
    pub sha256: String,
    /// Credential-free same-origin GraphQL endpoint; required only for `graph_ql`.
    pub endpoint: Option<String>,
}

/// Parameters for the isolated authenticated OWASP ZAP application DAST service.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationDastParams {
    /// Authorized credential-free HTTP(S) base URL.
    pub target: String,
    /// `passive`, `standard`, or `active` ordered ZAP phase profile.
    pub profile: String,
    /// Include an isolated anonymous run before named personas.
    #[serde(default = "default_true")]
    pub include_anonymous: bool,
    /// Stable persona IDs from `[dast.personas]`; values never contain credentials.
    #[serde(default)]
    pub personas: Vec<String>,
    /// Local digest-pinned `OpenAPI` or GraphQL schemas.
    #[serde(default)]
    pub schemas: Vec<ApplicationDastSchemaParams>,
}

/// One immutable Git change set declared to the application workflow planner.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationChangeSetParams {
    /// Immutable lowercase 40- or 64-hex base object ID. Branch names are rejected.
    pub base_revision: String,
    /// Immutable lowercase 40- or 64-hex head object ID. Branch names are rejected.
    pub head_revision: String,
    /// Root-relative changed paths for exactly this change set.
    pub changed_paths: Vec<String>,
}

/// Inputs for bounded application context discovery.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationContextParams {
    /// Existing authorized local application source directory.
    pub path: String,
    /// Optional project name or UUID used only to load registered target inventory.
    pub project: Option<String>,
    /// Optional immutable host-declared Git change set. `ScorchKit` records but does not execute
    /// Git to verify the declaration.
    pub change_set: Option<ApplicationChangeSetParams>,
    /// Normalized application routes declared by the host without query values.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Root-relative local application artifacts declared by the host.
    #[serde(default)]
    pub artifacts: Vec<String>,
}

/// Exact static or runtime scanner selector in a focused verification request.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FocusedScannerSelectorParams {
    /// Scanner or module identifier.
    pub scanner_id: String,
    /// Exact rule, query, check, or template identifier.
    pub rule_id: String,
    /// Exact rule or template digest when supplied by correlation.
    pub rule_digest: Option<String>,
    /// Exact rule pack, template collection, or configuration identity.
    pub config_identity: Option<String>,
}

/// Parameter identity for a focused request without a value.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FocusedRequestParameterParams {
    /// Parameter name.
    pub name: String,
    /// Parameter carrier such as `query` or `json`.
    pub location: String,
}

/// Redacted focused runtime request selector.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FocusedRequestSelectorParams {
    /// Exact HTTP method.
    pub method: String,
    /// Normalized route without query values.
    pub route: String,
    /// Optional parameter identity without a value.
    pub parameter: Option<FocusedRequestParameterParams>,
    /// Optional persona label without a credential.
    pub authentication_persona: Option<String>,
}

/// Complete canonical focused selection returned by attack-path correlation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FocusedVerificationSelectionParams {
    /// Must be `scorchkit.focused-verification/v1`.
    pub schema: String,
    /// Deterministic selection identity returned by correlation.
    pub identity: String,
    /// Parent attack-path identity.
    pub path_identity: String,
    /// Exact static-analysis selectors.
    #[serde(default)]
    pub static_rules: Vec<FocusedScannerSelectorParams>,
    /// Exact runtime scanner or template selectors.
    #[serde(default)]
    pub runtime_probes: Vec<FocusedScannerSelectorParams>,
    /// Redacted runtime requests.
    #[serde(default)]
    pub requests: Vec<FocusedRequestSelectorParams>,
    /// Exact test identities.
    #[serde(default)]
    pub tests: Vec<String>,
}

/// Parameters for compiling an inert application-security workflow.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationSecurityWorkflowParams {
    /// `commit`, `pull_request`, `staging`, `release`, or `deep`.
    pub profile: String,
    /// Inputs used to rebuild the canonical application context.
    pub context: ApplicationContextParams,
    /// Optional exact focused selection. When present, broad profile steps are not compiled.
    pub focused_selection: Option<FocusedVerificationSelectionParams>,
}

/// One expected access result for an application-pentest persona.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationPentestPersonaParams {
    /// `anonymous` or a stable persona ID configured under `[dast.personas]`.
    pub persona: String,
    /// `allow` or `deny`.
    pub expected: String,
}

/// One inert application-pentest proposal. It contains no payload or credential values.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationPentestScenarioParams {
    /// Human-readable scenario name.
    pub name: String,
    /// Untrusted proposal attribution: `human`, `agent`, or `tool`.
    pub proposal_kind: String,
    /// Stable source label such as `operator`, `codex`, or a scanner ID.
    pub proposal_label: String,
    /// Reviewed scenario class: `authorization_invariant`, `business_logic_invariant`,
    /// `injection`, `ssrf`, `path_traversal`, `api_object_binding`, `command_injection`, or
    /// `file_upload`.
    pub scenario_class: String,
    /// Reviewed payload class: `persona_comparison`, `syntax_boundary`,
    /// `internal_destination`, `path_normalization`, `field_boundary`, `command_proof`, or
    /// `inert_upload`. This is a class label, never an executable payload.
    pub payload_class: String,
    /// Exact HTTP method. Version 1 accepts `GET`, `HEAD`, or the reviewed `POST` scenario classes.
    pub method: String,
    /// Exact normalized route, including its leading slash.
    pub route: String,
    /// Optional parameter name without a value.
    pub parameter_name: Option<String>,
    /// Optional parameter carrier: `query` or `json`.
    pub parameter_location: Option<String>,
    /// Persona expectations for authorization and business-logic comparisons.
    #[serde(default)]
    pub personas: Vec<ApplicationPentestPersonaParams>,
    /// Scenario deadline ceiling in seconds.
    pub max_seconds: u64,
    /// Scenario concurrency ceiling from 1 through 4.
    pub max_concurrency: usize,
    /// `not_required` or `manual_required`.
    pub cleanup: String,
    /// Explicit conditions that must already hold.
    #[serde(default)]
    pub preconditions: Vec<String>,
    /// Required evidence classes such as `status_code`, `response_difference`,
    /// `error_signature`, `out_of_band_callback`, `file_marker`, or `cleanup_proof`.
    #[serde(default)]
    pub evidence_requirements: Vec<String>,
    /// Stable finding identities that motivated the proposal.
    #[serde(default)]
    pub source_finding_identities: Vec<String>,
    /// Stable attack-path identities that motivated the proposal.
    #[serde(default)]
    pub source_path_identities: Vec<String>,
}

/// Parameters for compiling an inert application-pentest plan without effects.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationPentestPlanParams {
    /// Exact credential-free authorized application URL. The scenario route must match its path.
    pub target: String,
    /// One or more inert scenarios compiled through `ScorchKit`'s closed executor inventory.
    pub scenarios: Vec<ApplicationPentestScenarioParams>,
}

/// Parameters for executing an exact previously reviewed application-pentest plan.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationPentestExecuteParams {
    /// Project name or UUID. The exact target must already be registered to this project.
    pub project: String,
    /// Exact credential-free authorized application URL.
    pub target: String,
    /// Exact plan identity returned by `plan_application_pentest`.
    pub approved_plan_identity: String,
    /// The same inert scenarios used to produce the approved identity.
    pub scenarios: Vec<ApplicationPentestScenarioParams>,
}

/// Metadata for a new explicitly manual finding created during evidence import.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ManualApplicationFindingParams {
    /// `critical`, `high`, `medium`, `low`, or `info`.
    pub severity: String,
    pub title: String,
    pub description: String,
    pub remediation: Option<String>,
    pub cwe_id: Option<u32>,
}

/// Parameters for importing digest-pinned local HAR or HTTP-exchange evidence.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplicationEvidenceImportParams {
    /// Project name or UUID. The exact target must already be registered to this project.
    pub project: String,
    /// Exact credential-free registered application base URL and path scope.
    pub target: String,
    /// Existing local regular file. Symbolic links are rejected.
    pub path: String,
    /// Expected lowercase SHA-256 of the exact file bytes.
    pub sha256: String,
    /// `har` or `http_exchange`.
    pub format: String,
    /// `human`, `proxy`, or `tool`.
    pub source_kind: String,
    /// Redacted source name used in evidence provenance.
    pub source_label: String,
    /// Existing finding UUID to append evidence to. Mutually exclusive with `new_finding`.
    pub finding_id: Option<String>,
    /// New explicitly manual finding. Mutually exclusive with `finding_id`.
    pub new_finding: Option<ManualApplicationFindingParams>,
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
    /// Scan profile: "quick" for safe recon, "standard" for built-ins,
    /// "thorough" for non-restricted external tools, or "pentest" for explicitly
    /// authorized credential/exploit modules. Defaults to "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Comma-separated module IDs to run within the authorized profile. Omit to run the complete
    /// profile. Use validated IDs returned by `plan_scan` or `list_modules`.
    pub modules: Option<String>,
    /// Comma-separated module IDs to exclude after profile and include filtering.
    pub skip: Option<String>,
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
    /// Scan profile for scheduled runs: "quick", "standard", "thorough", or "pentest".
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
    /// Scan profile: "quick" (safe recon), "standard" (built-ins), "thorough"
    /// (non-restricted external tools), or "pentest" (credential/exploit modules
    /// with explicit grants). Defaults to "standard".
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

/// Parameters for the `scan_code` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CodeScanParams {
    /// Filesystem path to the source code directory to scan. Must be an absolute
    /// path or relative to the server's working directory. The scanner auto-detects
    /// the project language from manifest files (Cargo.toml, package.json, go.mod, etc.).
    pub path: String,
    /// Filter to a specific language. Only modules supporting this language will run.
    /// Language-agnostic modules (dependency auditor, Checkov) always run regardless.
    /// Valid values: "rust", "python", "javascript", "go", "php", "java", "ruby".
    /// If omitted, auto-detected from manifest files.
    pub language: Option<String>,
    /// Code scan profile: "quick" for secrets/dependencies, "standard" for fast application
    /// analysis, or "thorough"/"pentest" to add deep analyzers. Defaults to "standard".
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Comma-separated list of specific code module IDs to run, ignoring defaults.
    /// Get valid IDs from `list_code_modules`. Example: "semgrep,dep-audit".
    pub modules: Option<String>,
    /// Comma-separated list of code module IDs to skip.
    pub skip: Option<String>,
}

/// Parameters for an explicit local application supply-chain scan.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupplyChainScanParams {
    /// Existing local directory, archive, artifact, OCI layout, or `CycloneDX` document.
    pub path: String,
    /// Exact target kind: `source_directory`, `directory_artifact`, `file_artifact`, `oci_archive`,
    /// `oci_layout`, or `cyclonedx_sbom`.
    pub kind: String,
    /// quick, standard, thorough, or pentest.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Optional immutable source or artifact revision supplied by the caller.
    pub revision: Option<String>,
}

/// One exact provider object to download during an explicit cache refresh.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupplyChainProviderDownloadParams {
    pub url: String,
    pub relative_path: String,
    pub sha256: String,
}

/// Parameters for a policy-owned supply-chain provider refresh.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupplyChainCacheRefreshParams {
    /// osv, grype, or trivy. Trivy refresh currently fails closed.
    pub provider: String,
    pub snapshot_id: String,
    pub schema_version: String,
    pub downloads: Vec<SupplyChainProviderDownloadParams>,
    /// Optional RFC 3339 upstream build time.
    pub upstream_built_at: Option<String>,
    pub maximum_age_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::ApplicationDastParams;

    #[test]
    fn application_dast_defaults_to_anonymous_without_personas_or_schemas() {
        let params: ApplicationDastParams =
            serde_json::from_str(r#"{"target":"https://example.com","profile":"passive"}"#)
                .expect("deserialize application DAST parameters");

        assert!(params.include_anonymous);
        assert!(params.personas.is_empty());
        assert!(params.schemas.is_empty());
    }
}
