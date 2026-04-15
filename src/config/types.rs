use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    pub scan: ScanConfig,
    pub auth: AuthConfig,
    pub tools: ToolsConfig,
    pub ai: AiConfig,
    pub report: ReportConfig,
    pub database: DatabaseConfig,
    /// Custom wordlist paths for brute-force and enumeration modules.
    #[serde(default)]
    pub wordlists: WordlistConfig,
    /// Lifecycle hooks for scan extensibility.
    #[serde(default)]
    pub hooks: HookConfig,
    /// Webhook endpoints for scan lifecycle notifications.
    #[serde(default)]
    pub webhooks: Vec<crate::runner::hooks::WebhookConfig>,
    /// JSONL audit-log sink for scan-lifecycle events.
    #[serde(default)]
    pub audit_log: AuditLogConfig,
    /// CVE backend configuration (NVD or mock).
    #[serde(default)]
    pub cve: super::cve::CveConfig,
    /// Credentials for authenticated network scanning (SSH, SMB, SNMP,
    /// Kerberos). Defaults to all-`None` so scans run unauthenticated
    /// unless opted in. See
    /// [`crate::engine::network_credentials::NetworkCredentials`] for
    /// the env-var precedence contract.
    #[serde(default)]
    pub network_credentials: crate::engine::network_credentials::NetworkCredentials,
    /// Cloud-API credentials — AWS profile / role / region, GCP
    /// service-account path and project, Azure subscription and
    /// tenant, Kubernetes context. Defaults to all-`None` so cloud
    /// scans use the underlying SDK / tool defaults (AWS CLI profile,
    /// `gcloud` ADC, `kubectl` current context) unless explicitly
    /// configured. See
    /// [`crate::engine::cloud_credentials::CloudCredentials`] for the
    /// env-var precedence contract. Shipped in WORK-150.
    #[cfg(feature = "cloud")]
    #[serde(default)]
    pub cloud: crate::engine::cloud_credentials::CloudCredentials,
}

/// Configuration for the built-in JSONL audit-log event subscriber.
///
/// Disabled by default. When `enabled` is true and `path` is `Some`, the
/// orchestrator wires an [`crate::engine::audit_log::AuditLogHandler`] that
/// appends every published [`crate::engine::events::ScanEvent`] to the file
/// as one JSON record per line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuditLogConfig {
    /// Turn the audit-log sink on. Defaults to `false`.
    pub enabled: bool,
    /// Destination file. Opened in append+create mode. Parent directory must exist.
    pub path: Option<PathBuf>,
}

/// Database connection configuration for persistent storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// `PostgreSQL` connection URL (e.g., `postgresql://user:pass@localhost/scorchkit`).
    /// If `None`, storage features are disabled.
    pub url: Option<String>,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Run migrations automatically on startup.
    pub migrate_on_startup: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { url: None, max_connections: 5, migrate_on_startup: true }
    }
}

/// Scan behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Global scan timeout in seconds.
    pub timeout_seconds: u64,
    /// Max modules to run concurrently.
    pub max_concurrent_modules: usize,
    /// HTTP User-Agent string.
    pub user_agent: String,
    /// Follow HTTP redirects.
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow.
    pub max_redirects: usize,
    /// Additional headers to send with every request.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Max requests per second (0 = unlimited).
    pub rate_limit: u32,
    /// Scan profile: quick, standard, thorough.
    pub profile: String,
    /// HTTP/HTTPS proxy URL (e.g., <http://127.0.0.1:8080> for Burp).
    pub proxy: Option<String>,
    /// Scope: only scan URLs matching these patterns (glob). Empty = target domain only.
    #[serde(default)]
    pub scope_include: Vec<String>,
    /// Exclude URLs matching these patterns from scanning.
    #[serde(default)]
    pub scope_exclude: Vec<String>,
    /// Directory containing plugin definition files (.toml).
    pub plugins_dir: Option<PathBuf>,
    /// Directory containing YAML rule definition files (.yaml/.yml).
    pub rules_dir: Option<PathBuf>,
    /// Skip TLS certificate verification (for self-signed certs in local dev).
    #[serde(default)]
    pub insecure: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 300,
            max_concurrent_modules: 4,
            user_agent: format!("ScorchKit/{}", env!("CARGO_PKG_VERSION")),
            follow_redirects: true,
            max_redirects: 10,
            headers: HashMap::new(),
            rate_limit: 0,
            profile: "standard".to_string(),
            proxy: None,
            scope_include: Vec::new(),
            scope_exclude: Vec::new(),
            plugins_dir: None,
            rules_dir: None,
            insecure: false,
        }
    }
}

/// Authentication configuration for scanning behind login.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AuthConfig {
    /// Bearer token for Authorization header.
    pub bearer_token: Option<String>,
    /// Raw cookie string to send with requests.
    pub cookies: Option<String>,
    /// Basic auth username.
    pub username: Option<String>,
    /// Basic auth password.
    pub password: Option<String>,
    /// Custom auth header name and value.
    pub custom_header: Option<String>,
    /// Custom auth header value.
    pub custom_header_value: Option<String>,
}

/// External tool path overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ToolsConfig {
    // Network
    pub nmap: Option<String>,
    // Web scanners
    pub nikto: Option<String>,
    pub nuclei: Option<String>,
    pub zap: Option<String>,
    pub wpscan: Option<String>,
    pub droopescan: Option<String>,
    // Injection
    pub sqlmap: Option<String>,
    pub dalfox: Option<String>,
    // Discovery
    pub feroxbuster: Option<String>,
    pub ffuf: Option<String>,
    pub arjun: Option<String>,
    pub cewl: Option<String>,
    // TLS
    pub sslyze: Option<String>,
    pub testssl: Option<String>,
    // Subdomain
    pub amass: Option<String>,
    pub subfinder: Option<String>,
    // HTTP
    pub httpx: Option<String>,
    // OSINT
    pub theharvester: Option<String>,
    // WAF
    pub wafw00f: Option<String>,
    // Credentials
    pub hydra: Option<String>,
    // Exploit
    pub msfconsole: Option<String>,
}

impl ToolsConfig {
    /// Get the binary path for a tool, falling back to the tool name (PATH lookup).
    #[must_use]
    pub fn get_path(&self, tool: &str) -> String {
        let override_path = match tool {
            "nmap" => &self.nmap,
            "nikto" => &self.nikto,
            "nuclei" => &self.nuclei,
            "zap-cli" | "zap.sh" => &self.zap,
            "wpscan" => &self.wpscan,
            "droopescan" => &self.droopescan,
            "sqlmap" => &self.sqlmap,
            "dalfox" => &self.dalfox,
            "feroxbuster" => &self.feroxbuster,
            "ffuf" => &self.ffuf,
            "arjun" => &self.arjun,
            "cewl" => &self.cewl,
            "sslyze" => &self.sslyze,
            "testssl.sh" | "testssl" => &self.testssl,
            "amass" => &self.amass,
            "subfinder" => &self.subfinder,
            "httpx" => &self.httpx,
            "theHarvester" | "theharvester" => &self.theharvester,
            "wafw00f" => &self.wafw00f,
            "hydra" => &self.hydra,
            "msfconsole" => &self.msfconsole,
            _ => &None,
        };
        override_path.as_deref().unwrap_or(tool).to_string()
    }
}

/// AI analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub claude_binary: String,
    pub model: String,
    pub max_budget_usd: f64,
    pub auto_analyze: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            claude_binary: "claude".to_string(),
            model: "sonnet".to_string(),
            max_budget_usd: 0.50,
            auto_analyze: false,
        }
    }
}

/// Report output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportConfig {
    pub output_dir: PathBuf,
    pub include_evidence: bool,
    pub include_remediation: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("./reports"),
            include_evidence: true,
            include_remediation: true,
        }
    }
}

/// Configuration for scan lifecycle hooks.
///
/// Hooks are external scripts/binaries that fire at scan lifecycle points.
/// They receive JSON on stdin and can optionally return modified JSON on stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HookConfig {
    /// Scripts to run before scanning begins. Can modify scan configuration.
    #[serde(default)]
    pub pre_scan: Vec<PathBuf>,
    /// Scripts to run after each module completes. Can filter/enrich findings.
    #[serde(default)]
    pub post_module: Vec<PathBuf>,
    /// Scripts to run after all modules complete. Fire-and-forget (output ignored).
    #[serde(default)]
    pub post_scan: Vec<PathBuf>,
    /// Maximum time in seconds to wait for each hook script. Default: 30.
    pub timeout_seconds: u64,
    /// If true, hook failures log a warning but don't block the scan. Default: true.
    pub fail_open: bool,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            pre_scan: Vec::new(),
            post_module: Vec::new(),
            post_scan: Vec::new(),
            timeout_seconds: 30,
            fail_open: true,
        }
    }
}

/// Custom wordlist paths for brute-force and enumeration modules.
///
/// When a path is set, the corresponding module reads lines from that file
/// instead of using its built-in default wordlist. Paths that don't exist
/// cause a warning and fall back to built-in defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WordlistConfig {
    /// Wordlist for directory brute-force (used by discovery, feroxbuster, ffuf, gobuster).
    pub directory: Option<PathBuf>,
    /// Wordlist for subdomain enumeration (one prefix per line).
    pub subdomain: Option<PathBuf>,
    /// Wordlist for virtual host discovery (one prefix per line).
    pub vhost: Option<PathBuf>,
    /// Wordlist for parameter fuzzing (one parameter name per line).
    pub params: Option<PathBuf>,
}

/// Load a wordlist from a file, returning one entry per non-empty, non-comment line.
///
/// Lines starting with `#` are treated as comments and skipped.
/// Leading/trailing whitespace is trimmed from each line.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn load_wordlist(path: &std::path::Path) -> crate::engine::error::Result<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::engine::error::ScorchError::Config(format!(
            "failed to read wordlist {}: {e}",
            path.display()
        ))
    })?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect())
}

impl AppConfig {
    /// Load application configuration from an optional TOML file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file cannot be read or contains invalid TOML.
    pub fn load(path: Option<&std::path::Path>) -> crate::engine::error::Result<Self> {
        if let Some(path) = path {
            if path.exists() {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    crate::engine::error::ScorchError::Config(format!(
                        "failed to read config file {}: {e}",
                        path.display()
                    ))
                })?;
                let config: Self = toml::from_str(&content).map_err(|e| {
                    crate::engine::error::ScorchError::Config(format!(
                        "failed to parse config file {}: {e}",
                        path.display()
                    ))
                })?;
                return Ok(config);
            }
        }
        Ok(Self::default())
    }

    /// Serialize the default configuration as a TOML string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization to TOML fails.
    pub fn default_toml() -> crate::engine::error::Result<String> {
        toml::to_string_pretty(&Self::default()).map_err(|e| {
            crate::engine::error::ScorchError::Config(format!("failed to serialize config: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify all wordlist paths default to None.
    #[test]
    fn wordlist_config_defaults_to_none() {
        let wl = WordlistConfig::default();
        assert!(wl.directory.is_none());
        assert!(wl.subdomain.is_none());
        assert!(wl.vhost.is_none());
        assert!(wl.params.is_none());
    }

    /// Verify `load_wordlist` skips comment lines and blank lines.
    #[test]
    fn load_wordlist_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "# comment\nadmin\n\n  api  \n# another comment\nstaging\n")
            .expect("write test file");
        let words = load_wordlist(&path).expect("load wordlist");
        assert_eq!(words, vec!["admin", "api", "staging"]);
    }

    /// Verify `load_wordlist` returns an error for a missing file.
    #[test]
    fn load_wordlist_returns_error_for_missing() {
        let result = load_wordlist(std::path::Path::new("/nonexistent/wordlist.txt"));
        assert!(result.is_err());
    }

    /// Verify TOML deserialization of `[wordlists]` section.
    #[test]
    fn wordlist_config_deserialize() {
        let toml_str = r#"
[wordlists]
directory = "/opt/SecLists/Discovery/Web-Content/common.txt"
subdomain = "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
"#;
        let config: AppConfig = toml::from_str(toml_str).expect("parse TOML");
        assert_eq!(
            config.wordlists.directory.as_deref(),
            Some(std::path::Path::new("/opt/SecLists/Discovery/Web-Content/common.txt"))
        );
        assert_eq!(
            config.wordlists.subdomain.as_deref(),
            Some(std::path::Path::new(
                "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
            ))
        );
        assert!(config.wordlists.vhost.is_none());
        assert!(config.wordlists.params.is_none());
    }
}
