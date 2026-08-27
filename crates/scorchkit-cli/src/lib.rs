use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};

/// `ScorchKit` - Web Application Security Testing Toolkit
#[derive(Parser, Debug)]
#[command(
    name = "scorchkit",
    version,
    about = "Web application security testing toolkit",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress all output except findings
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output format override
    #[arg(short, long, global = true)]
    pub output: Option<OutputFormat>,
}

// JUSTIFICATION: Run variant has many CLI flags — this is inherent to a feature-rich CLI;
// boxing would add indirection for the most common code path
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run all default scans against a target
    Run {
        /// Target URL, domain, or IP
        #[arg(required_unless_present_any = ["targets_file", "resume"])]
        target: Option<String>,

        /// File with one target per line (replaces positional target)
        #[arg(long, conflicts_with = "target")]
        targets_file: Option<PathBuf>,

        /// Resume an interrupted scan from a checkpoint file
        #[arg(long, conflicts_with_all = ["target", "targets_file"])]
        resume: Option<PathBuf>,

        /// Specific modules to run (comma-separated)
        #[arg(short, long)]
        modules: Option<String>,

        /// Modules to skip (comma-separated)
        #[arg(long)]
        skip: Option<String>,

        /// Run AI analysis after scan completes
        #[arg(long)]
        analyze: bool,

        /// Use AI-guided scan planning with the configured provider
        #[arg(long)]
        plan: bool,

        /// Scan profile: quick, standard, thorough, pentest
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Scan template: web-app, api, graphql, wordpress, spa, network, compatibility, full
        #[arg(long)]
        template: Option<String>,

        /// HTTP proxy URL (e.g., `http://127.0.0.1:8080` for Burp Suite)
        #[arg(long)]
        proxy: Option<String>,

        /// Minimum confidence threshold (0.0–1.0) — hide findings below this level
        #[arg(long)]
        min_confidence: Option<f64>,

        /// Restrict scope to URLs matching pattern (e.g., "*.example.com")
        #[arg(long)]
        scope: Option<String>,

        /// Skip TLS certificate verification (for self-signed certs, local dev)
        #[arg(long, short = 'k')]
        insecure: bool,

        /// Exclude URLs matching pattern from scanning
        #[arg(long)]
        exclude: Option<String>,

        /// Also run SAST code scanning on the given path (DAST+SAST combined)
        #[arg(long)]
        code: Option<std::path::PathBuf>,

        /// Associate scan with a project and persist results to the database
        #[arg(long)]
        project: Option<String>,

        /// Database URL override (takes precedence over config and `DATABASE_URL` env)
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Run reconnaissance modules only
    Recon {
        /// Target URL, domain, or IP
        target: String,

        /// Specific recon modules to run
        #[arg(short, long)]
        modules: Option<String>,
    },

    /// Run vulnerability scanner modules only
    Scan {
        /// Target URL, domain, or IP
        target: String,

        /// Specific scanner modules to run
        #[arg(short, long)]
        modules: Option<String>,
    },

    /// Run AI analysis on a previous scan report
    Analyze {
        /// Path to a JSON report file from a previous scan
        report: PathBuf,

        /// Analysis focus: summary, prioritize, remediate, filter
        #[arg(short, long, default_value = "summary")]
        focus: String,

        /// Enrich analysis with project history context (requires storage feature)
        #[arg(long)]
        project: Option<String>,

        /// Database URL override for project context (takes precedence over config)
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Compare two scan reports
    Diff {
        /// Path to the baseline (older) scan report
        baseline: PathBuf,
        /// Path to the current (newer) scan report
        current: PathBuf,
    },

    /// List available modules and their status
    Modules {
        /// Check which external tools are installed
        #[arg(long)]
        check_tools: bool,

        /// Include the explicit network, enterprise, and cloud compatibility catalog
        #[arg(long)]
        include_compatibility: bool,
    },

    /// Inspect and operate the local signed extension catalog lifecycle
    Catalog {
        #[command(subcommand)]
        command: CatalogCommands,
    },

    /// Initialize a config file, optionally binding a safe engagement to a target
    Init {
        /// Target URL to resolve and pin without sending an HTTP request
        target: Option<String>,

        /// Create a named project and add the target (requires storage feature)
        #[arg(long)]
        project: Option<String>,

        /// Database URL override for project creation
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Check external tool installation status
    Doctor {
        /// Run deep validation: pinned versions, configuration, and health checks
        #[arg(long)]
        deep: bool,
    },

    /// Run autonomous scan agent (recon→plan→scan→analyze loop)
    Agent {
        /// Target URL to scan
        target: String,

        /// Scan depth: quick, standard, thorough
        #[arg(long, default_value = "standard")]
        depth: String,

        /// Associate with a project for persistence and intelligence tracking
        #[arg(long)]
        project: Option<String>,

        /// Database URL override for project persistence
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Run static analysis on source code
    Code {
        /// Path to source code directory or file
        path: std::path::PathBuf,

        /// Primary language (auto-detected if not specified)
        #[arg(long)]
        language: Option<String>,

        /// Specific modules to run (comma-separated)
        #[arg(short, long)]
        modules: Option<String>,

        /// Modules to skip (comma-separated)
        #[arg(long)]
        skip: Option<String>,

        /// Code scan profile: quick, standard, thorough
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Run AI analysis after scan completes
        #[arg(long)]
        analyze: bool,

        /// Associate with a project (requires storage feature)
        #[arg(long)]
        project: Option<String>,

        /// Database URL override
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Scan local application dependencies and artifacts with the ordered offline SBOM pipeline.
    SupplyChain {
        #[command(subcommand)]
        command: SupplyChainCommands,
    },

    /// Run an authenticated, schema-driven OWASP ZAP application assessment.
    Dast {
        /// Bounded JSON file matching the `ApplicationDastRequest` contract.
        request: PathBuf,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Manage the database schema
    #[cfg(feature = "storage")]
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },

    /// Manage security assessment projects
    #[cfg(feature = "storage")]
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },

    /// Query and manage tracked vulnerability findings
    #[cfg(feature = "storage")]
    Finding {
        #[command(subcommand)]
        command: FindingCommands,
    },

    /// Manage recurring scan schedules
    #[cfg(feature = "storage")]
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommands,
    },

    /// Run and manage durable scan jobs.
    #[cfg(feature = "storage")]
    Job {
        #[command(subcommand)]
        command: JobCommands,
    },

    /// Inspect and run the durable webhook delivery queue.
    #[cfg(feature = "storage")]
    Webhook {
        #[command(subcommand)]
        command: WebhookCommands,
    },

    /// Start the MCP server on local stdio or authenticated remote HTTP.
    #[cfg(feature = "mcp")]
    Serve {
        /// Use the authenticated `[mcp.remote]` Streamable HTTP transport.
        #[arg(long)]
        remote: bool,
    },

    /// Start the bearer-authenticated loopback control API.
    #[cfg(feature = "control-api")]
    ControlApi {
        /// Database URL override (takes precedence over config and `DATABASE_URL`).
        #[arg(long)]
        database_url: Option<String>,
    },

    /// Start the authenticated multi-user team service behind a trusted TLS proxy.
    #[cfg(feature = "team")]
    TeamApi,

    /// Run a unified assessment: DAST + SAST + Infra + Cloud combined.
    ///
    /// At least one of `--url`, `--code`, `--infra`, or `--cloud` is
    /// required. The orchestrators run concurrently and results are
    /// merged into a single report. `--cloud` requires the `cloud`
    /// feature; without it, passing `--cloud` errors at runtime.
    #[cfg(feature = "infra")]
    Assess {
        /// DAST target URL (optional).
        #[arg(long)]
        url: Option<String>,

        /// SAST code path (optional).
        #[arg(long)]
        code: Option<std::path::PathBuf>,

        /// Infrastructure target — IP, CIDR, host, or `host:port` (optional).
        #[arg(long)]
        infra: Option<String>,

        /// Cloud target — `aws:<account>`, `gcp:<project>`, `azure:<sub>`, `k8s:<ctx>`, or `all` (optional). Requires `cloud` feature.
        #[arg(long)]
        cloud: Option<String>,

        /// Scan profile applied to each applicable orchestrator.
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Suppress progress output.
        #[arg(long)]
        quiet: bool,
    },

    /// Run an infrastructure scan (host, IP, or CIDR target)
    #[cfg(feature = "infra")]
    Infra {
        /// Target: IP (`192.0.2.1`), CIDR (`10.0.0.0/24`), host (`example.com`), or endpoint (`host:port`)
        target: String,

        /// Scan profile: `quick` (port scan only) or `standard` (default: all registered modules)
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Comma-separated module IDs to run (overrides the profile).
        #[arg(long)]
        modules: Option<String>,

        /// Comma-separated module IDs to skip.
        #[arg(long)]
        skip: Option<String>,

        /// Suppress progress output.
        #[arg(long)]
        quiet: bool,
    },

    /// Run a cloud-posture scan against an AWS account, GCP project,
    /// Azure subscription, or Kubernetes cluster context (WORK-150).
    #[cfg(feature = "cloud")]
    Cloud {
        /// Target: `aws:<account-id>`, `gcp:<project-id>`, `azure:<subscription>`, `k8s:<context>`, or `all`.
        target: String,

        /// Scan profile: `quick` (IAM only) or `standard` (default: all registered cloud modules).
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Comma-separated module IDs to run (overrides the profile).
        #[arg(long)]
        modules: Option<String>,

        /// Comma-separated module IDs to skip.
        #[arg(long)]
        skip: Option<String>,

        /// Suppress progress output.
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
    Sarif,
    Pdf,
}

/// Explicit local target shapes accepted by the supply-chain scanner.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SupplyChainTargetKindArg {
    SourceDirectory,
    DirectoryArtifact,
    FileArtifact,
    OciArchive,
    OciLayout,
    CycloneDxSbom,
}

/// Application supply-chain scan and provider-cache operations.
#[derive(Subcommand, Debug)]
pub enum SupplyChainCommands {
    /// Run the ordered offline pipeline against one explicit local target.
    Scan {
        /// Existing local target path.
        path: PathBuf,
        /// Exact target shape; never inferred as an image, registry, or daemon target.
        #[arg(long, value_enum)]
        kind: SupplyChainTargetKindArg,
        /// Supply-chain profile: quick, standard, thorough, or pentest.
        #[arg(long, default_value = "standard")]
        profile: String,
        /// Optional source revision or immutable artifact revision supplied by the caller.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Show missing, stale, invalid, or ready state for every provider snapshot.
    CacheStatus,
    /// Refresh one provider from a complete, explicit JSON request file.
    CacheRefresh {
        /// JSON file matching the versioned provider refresh request contract.
        request: PathBuf,
    },
}

/// Local-only signed extension catalog operations.
#[derive(Subcommand, Debug)]
pub enum CatalogCommands {
    /// Verify a signed release and print its exact permission difference.
    Inspect {
        /// Exact configured local catalog path.
        catalog: PathBuf,
        /// Signed immutable release identity.
        release: String,
    },
    /// Record an explicit immutable approval for a verified release.
    Approve {
        /// Exact configured local catalog path.
        catalog: PathBuf,
        /// Signed immutable release identity.
        release: String,
        /// Exact payload digest returned by `catalog inspect`.
        #[arg(long)]
        payload_sha256: String,
        /// Exact normalized permission-difference digest returned by `catalog inspect`.
        #[arg(long)]
        permission_diff_sha256: String,
    },
    /// Activate one exact approval after artifact and startup revalidation.
    Activate {
        /// Content-addressed approval identity.
        approval: String,
    },
    /// Reactivate one exact prior approval.
    Rollback {
        /// Extension identity whose pointer may change.
        extension: String,
        /// Prior content-addressed approval identity.
        approval: String,
    },
    /// Print current active pointers and append-preserved transitions.
    Status,
}

/// Database management subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum DbCommands {
    /// Run pending database migrations
    Migrate,
}

/// Project management subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum ProjectCommands {
    /// Create a new project
    Create {
        /// Project name (must be unique)
        name: String,

        /// Optional project description
        #[arg(short, long)]
        description: Option<String>,
    },

    /// List all projects
    List,

    /// Show project details
    Show {
        /// Project name or UUID
        project: String,
    },

    /// Delete a project and all associated data
    Delete {
        /// Project name or UUID
        project: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Show security posture metrics and trend analysis
    Status {
        /// Project name or UUID
        project: String,
    },

    /// Show module effectiveness intelligence
    Intelligence {
        /// Project name or UUID
        project: String,
    },

    /// List scan history for a project
    Scans {
        /// Project name or UUID
        project: String,
    },

    /// Show details for a specific scan
    ScanShow {
        /// Scan UUID
        id: String,
    },

    /// Manage project targets
    Target {
        #[command(subcommand)]
        command: TargetCommands,
    },
}

/// Target management subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum TargetCommands {
    /// Add a target URL to a project
    Add {
        /// Project name
        project: String,

        /// Target URL
        url: String,

        /// Optional human-readable label
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Remove a target from a project
    Remove {
        /// Project name
        project: String,

        /// Target UUID to remove
        id: String,
    },

    /// List all targets for a project
    List {
        /// Project name
        project: String,
    },
}

/// Finding management subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum FindingCommands {
    /// List findings for a project
    List {
        /// Project name
        project: String,

        /// Filter by severity (critical, high, medium, low, info)
        #[arg(short, long)]
        severity: Option<String>,

        /// Filter by status (new, acknowledged, `false_positive`, remediated, verified)
        #[arg(long)]
        status: Option<String>,
    },

    /// Show details for a single finding
    Show {
        /// Finding UUID
        id: String,
    },

    /// Update the lifecycle status of a finding
    Status {
        /// Finding UUID
        id: String,

        /// New status (`new`, `acknowledged`, `false_positive`, `wont_fix`, `accepted_risk`, `remediated`, `verified`)
        status: String,

        /// Rationale for the status change (e.g., why it's a false positive)
        #[arg(short, long)]
        note: Option<String>,
    },
}

/// Schedule management subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum ScheduleCommands {
    /// Create a recurring scan schedule
    Create {
        /// Project name
        project: String,

        /// Target URL to scan
        target: String,

        /// Cron expression (e.g., "0 0 * * *" for daily at midnight)
        cron: String,

        /// Scan profile (quick, standard, thorough, pentest)
        #[arg(long, default_value = "standard")]
        profile: String,
    },

    /// List schedules for a project
    List {
        /// Project name
        project: String,
    },

    /// Show details for a single schedule
    Show {
        /// Schedule UUID
        id: String,
    },

    /// Enable a disabled schedule
    Enable {
        /// Schedule UUID
        id: String,
    },

    /// Disable an active schedule
    Disable {
        /// Schedule UUID
        id: String,
    },

    /// Delete a schedule
    Delete {
        /// Schedule UUID
        id: String,
    },

    /// Execute all schedules that are due
    RunDue,
}

/// Durable scan job subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum JobCommands {
    /// Submit and run a DAST job in the foreground.
    Run {
        /// Authorized target URL.
        target: String,
        /// Scan profile: quick, standard, thorough, or pentest.
        #[arg(long, default_value = "standard")]
        profile: String,
        /// Comma-separated module allow-list.
        #[arg(long)]
        modules: Option<String>,
        /// Comma-separated module deny-list.
        #[arg(long)]
        skip: Option<String>,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// List at most 1,000 stored jobs in creation order.
    List {
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Show one job and its progress.
    Status {
        /// Scan job UUID.
        id: String,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Cancel a queued or running job.
    Cancel {
        /// Scan job UUID.
        id: String,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Mark jobs with expired ownership leases as interrupted.
    Recover {
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Create a successor for an interrupted job and run it in the foreground.
    Resume {
        /// Interrupted scan job UUID.
        id: String,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
}

/// Durable webhook queue subcommands.
#[cfg(feature = "storage")]
#[derive(Subcommand, Debug)]
pub enum WebhookCommands {
    /// List at most 1,000 deliveries in creation order.
    List {
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Show one delivery record.
    Status {
        /// Delivery UUID.
        id: String,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Show immutable audit history for one delivery.
    Audit {
        /// Delivery UUID.
        id: String,
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Recover expired claims and process one bounded due batch.
    RunDue {
        /// Database URL override.
        #[arg(long)]
        database_url: Option<String>,
    },
}

/// Print shell completions to stdout.
pub fn print_completions(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "scorchkit", &mut std::io::stdout());
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn catalog_lifecycle_commands_require_explicit_subjects() {
        let inspect = Cli::try_parse_from([
            "scorchkit",
            "catalog",
            "inspect",
            "/approved/catalog.json",
            "publisher.release-1",
        ])
        .expect("catalog inspect arguments");
        assert!(matches!(
            inspect.command,
            Commands::Catalog {
                command: CatalogCommands::Inspect { catalog, release }
            } if catalog.as_path() == std::path::Path::new("/approved/catalog.json")
                && release == "publisher.release-1"
        ));
        assert!(Cli::try_parse_from(["scorchkit", "catalog", "approve"]).is_err());
        assert!(Cli::try_parse_from([
            "scorchkit",
            "catalog",
            "approve",
            "/approved/catalog.json",
            "publisher.release-1",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["scorchkit", "catalog", "rollback", "fixture.extension"]).is_err()
        );
    }
}

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::*;

    #[test]
    fn serve_transport_selection_is_explicit_and_local_by_default() {
        let local = Cli::try_parse_from(["scorchkit", "serve"]).expect("local serve arguments");
        assert!(matches!(local.command, Commands::Serve { remote: false }));

        let remote = Cli::try_parse_from(["scorchkit", "serve", "--remote"])
            .expect("remote serve arguments");
        assert!(matches!(remote.command, Commands::Serve { remote: true }));
    }
}

#[cfg(all(test, feature = "control-api"))]
mod control_api_tests {
    use super::*;

    #[test]
    fn control_api_listener_is_an_explicit_subcommand() {
        let cli = Cli::try_parse_from(["scorchkit", "control-api"]).expect("control API arguments");
        assert!(matches!(cli.command, Commands::ControlApi { database_url: None }));
    }
}

#[cfg(all(test, feature = "team"))]
mod team_api_tests {
    use super::*;

    #[test]
    fn team_listener_is_an_explicit_subcommand_without_secret_flags() {
        let cli = Cli::try_parse_from(["scorchkit", "team-api"]).expect("team API arguments");
        assert!(matches!(cli.command, Commands::TeamApi));
        assert!(Cli::try_parse_from(["scorchkit", "team-api", "--token", "secret"]).is_err());
    }
}
