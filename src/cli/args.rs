use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};

/// `ScorchKit` - Web Application Security Testing Toolkit
#[derive(Parser, Debug)]
#[command(name = "scorchkit", version, about, long_about = None)]
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

        /// Use AI-guided scan planning (recon first, then Claude decides modules)
        #[arg(long)]
        plan: bool,

        /// Scan profile: quick, standard, thorough
        #[arg(long, default_value = "standard")]
        profile: String,

        /// Scan template: web-app, api, graphql, wordpress, spa, network, full
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
    },

    /// Initialize a config file, optionally probing a target for fingerprinting
    Init {
        /// Target URL to probe and generate a tailored config for
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
        /// Run deep validation: version checks, template freshness, health checks
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

    /// Start the MCP server on stdio transport
    #[cfg(feature = "mcp")]
    Serve,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
    Sarif,
    Pdf,
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

        /// Scan profile (quick, standard, thorough)
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

/// Print shell completions to stdout.
pub fn print_completions(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "scorchkit", &mut std::io::stdout());
}
