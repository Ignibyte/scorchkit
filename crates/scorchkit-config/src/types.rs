use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    /// Authorization context for every scan effect started from this configuration.
    ///
    /// Scans fail closed when this is absent. Callers embedding `ScorchKit` may
    /// instead supply an engagement explicitly through
    /// the `ScorchKit` `Engine::for_engagement` composition facade.
    #[serde(default)]
    pub engagement: Option<crate::engine::policy::Engagement>,
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
    /// [`crate::network_credentials::NetworkCredentials`] for
    /// the env-var precedence contract.
    #[serde(default)]
    pub network_credentials: crate::engine::network_credentials::NetworkCredentials,
    /// Cloud-API credentials — AWS profile / role / region, GCP
    /// service-account path and project, Azure subscription and
    /// tenant, Kubernetes context. Defaults to all-`None` so cloud
    /// scans use the underlying SDK / tool defaults (AWS CLI profile,
    /// `gcloud` ADC, `kubectl` current context) unless explicitly
    /// configured. See
    /// [`crate::cloud_credentials::CloudCredentials`] for the
    /// env-var precedence contract. Shipped in WORK-150.
    #[cfg(feature = "cloud")]
    #[serde(default)]
    pub cloud: crate::engine::cloud_credentials::CloudCredentials,
}

/// Configuration for the built-in JSONL audit-log event subscriber.
///
/// Disabled by default. When `enabled` is true and `path` is `Some`, the
/// orchestrator wires an audit-log handler that appends every published
/// [`scorchkit_core::events::ScanEvent`] to the file
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
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("url", &self.url.as_ref().map(|_| "<configured>"))
            .field("max_connections", &self.max_connections)
            .field("migrate_on_startup", &self.migrate_on_startup)
            .finish()
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { url: None, max_connections: 5, migrate_on_startup: true }
    }
}

/// Scan behavior configuration.
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for ScanConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut header_names: Vec<_> = self.headers.keys().collect();
        header_names.sort_unstable();
        formatter
            .debug_struct("ScanConfig")
            .field("timeout_seconds", &self.timeout_seconds)
            .field("max_concurrent_modules", &self.max_concurrent_modules)
            .field("user_agent", &self.user_agent)
            .field("follow_redirects", &self.follow_redirects)
            .field("max_redirects", &self.max_redirects)
            .field("header_names", &header_names)
            .field("rate_limit", &self.rate_limit)
            .field("profile", &self.profile)
            .field("proxy", &self.proxy.as_ref().map(|_| "<configured>"))
            .field("scope_include", &self.scope_include)
            .field("scope_exclude", &self.scope_exclude)
            .field("plugins_dir", &self.plugins_dir)
            .field("rules_dir", &self.rules_dir)
            .field("insecure", &self.insecure)
            .finish()
    }
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
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "***"))
            .field("cookies", &self.cookies.as_ref().map(|_| "***"))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("custom_header", &self.custom_header)
            .field("custom_header_value", &self.custom_header_value.as_ref().map(|_| "***"))
            .finish()
    }
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

/// Supported AI host adapters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    /// `OpenAI` Codex CLI, run non-interactively in its read-only sandbox.
    #[default]
    Codex,
    /// Compatibility adapter for the Claude CLI.
    Claude,
}

impl AiProviderKind {
    /// Default executable name for this adapter.
    #[must_use]
    pub const fn default_binary(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

/// AI analysis configuration.
#[derive(Debug, Clone, Serialize)]
pub struct AiConfig {
    pub enabled: bool,
    pub provider: AiProviderKind,
    /// Optional executable override. Defaults to the selected provider's CLI.
    pub binary: Option<String>,
    /// Optional provider model override. `None` uses the CLI's configured default.
    pub model: Option<String>,
    /// Optional Claude CLI cost ceiling. Ignored by other adapters.
    pub max_budget_usd: Option<f64>,
    pub auto_analyze: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: AiProviderKind::Codex,
            binary: None,
            model: None,
            max_budget_usd: None,
            auto_analyze: false,
        }
    }
}

impl AiConfig {
    /// Executable selected for the configured provider.
    #[must_use]
    pub fn resolved_binary(&self) -> &str {
        self.binary.as_deref().unwrap_or_else(|| self.provider.default_binary())
    }
}

impl<'de> Deserialize<'de> for AiConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(default)]
        struct WireConfig {
            enabled: bool,
            provider: Option<AiProviderKind>,
            binary: Option<String>,
            model: Option<String>,
            max_budget_usd: Option<f64>,
            auto_analyze: bool,
            claude_binary: Option<String>,
        }

        impl Default for WireConfig {
            fn default() -> Self {
                let defaults = AiConfig::default();
                Self {
                    enabled: defaults.enabled,
                    provider: None,
                    binary: defaults.binary,
                    model: defaults.model,
                    max_budget_usd: defaults.max_budget_usd,
                    auto_analyze: defaults.auto_analyze,
                    claude_binary: None,
                }
            }
        }

        let wire = WireConfig::deserialize(deserializer)?;
        let legacy_claude = wire.claude_binary.is_some();
        let provider = wire.provider.unwrap_or(if legacy_claude {
            AiProviderKind::Claude
        } else {
            AiProviderKind::Codex
        });

        Ok(Self {
            enabled: wire.enabled,
            provider,
            binary: wire.binary.or(wire.claude_binary),
            model: wire.model,
            max_budget_usd: wire.max_budget_usd,
            auto_analyze: wire.auto_analyze,
        })
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
    /// Scripts to run after all modules complete. Output is ignored, but completion is awaited.
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

impl HookConfig {
    /// Whether no lifecycle script is configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pre_scan.is_empty() && self.post_module.is_empty() && self.post_scan.is_empty()
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
        let current_dir = std::env::current_dir().map_err(|error| {
            crate::engine::error::ScorchError::Config(format!(
                "failed to resolve current directory for config discovery: {error}"
            ))
        })?;
        let Some(path) = select_config_path(path, &current_dir)? else {
            return Ok(Self::default());
        };
        let content = std::fs::read_to_string(&path).map_err(|e| {
            crate::engine::error::ScorchError::Config(format!(
                "failed to read config file {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&content).map_err(|e| {
            crate::engine::error::ScorchError::Config(format!(
                "failed to parse config file {}: {e}",
                path.display()
            ))
        })
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

fn select_config_path(
    explicit: Option<&std::path::Path>,
    current_dir: &std::path::Path,
) -> crate::engine::error::Result<Option<std::path::PathBuf>> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(crate::engine::error::ScorchError::Config(format!(
                "config file '{}' does not exist or is not a regular file",
                path.display()
            )));
        }
        return Ok(Some(path.to_path_buf()));
    }

    for filename in ["scorchkit.toml", "config.toml"] {
        let candidate = current_dir.join(filename);
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_discovery_prefers_safe_init_output_and_rejects_missing_explicit_path() {
        let directory = tempfile::tempdir().unwrap();
        let legacy = directory.path().join("config.toml");
        std::fs::write(&legacy, "").unwrap();
        assert_eq!(select_config_path(None, directory.path()).unwrap(), Some(legacy));

        let initialized = directory.path().join("scorchkit.toml");
        std::fs::write(&initialized, "").unwrap();
        assert_eq!(select_config_path(None, directory.path()).unwrap(), Some(initialized));

        let missing = directory.path().join("missing.toml");
        assert!(select_config_path(Some(&missing), directory.path()).is_err());
    }

    #[test]
    fn app_config_load_reads_the_explicit_file_instead_of_returning_defaults() {
        let directory = tempfile::tempdir().expect("create config fixture directory");
        let path = directory.path().join("explicit.toml");
        std::fs::write(
            &path,
            r#"
[scan]
profile = "thorough"
rate_limit = 17
"#,
        )
        .expect("write explicit config");

        let config = AppConfig::load(Some(&path)).expect("load explicit config");
        assert_eq!(config.scan.profile, "thorough");
        assert_eq!(config.scan.rate_limit, 17);
    }

    #[test]
    fn app_config_debug_redacts_every_direct_secret_channel() {
        let mut config = AppConfig::default();
        config.auth.bearer_token = Some("bearer-secret".to_string());
        config.auth.cookies = Some("session=cookie-secret".to_string());
        config.auth.password = Some("basic-password".to_string());
        config.auth.custom_header = Some("X-Api-Key".to_string());
        config.auth.custom_header_value = Some("header-secret".to_string());
        config.scan.headers.insert("Authorization".to_string(), "scan-header-secret".to_string());
        config.scan.proxy = Some("https://proxy-user:proxy-secret@proxy.example".to_string());
        config.database.url =
            Some("postgresql://db-user:db-secret@localhost/scorchkit".to_string());
        config.cve.nvd.api_key = Some("nvd-secret".to_string());
        config.webhooks.push(crate::runner::hooks::WebhookConfig {
            url: "https://webhook-secret@hooks.example/path".to_string(),
            events: Vec::new(),
        });

        let rendered = format!("{config:?}");
        for secret in [
            "bearer-secret",
            "cookie-secret",
            "basic-password",
            "header-secret",
            "scan-header-secret",
            "proxy-secret",
            "db-secret",
            "nvd-secret",
            "webhook-secret",
        ] {
            assert!(!rendered.contains(secret), "debug output leaked {secret}: {rendered}");
        }
        assert!(rendered.contains("***"));
        assert!(rendered.contains("<configured>"));
        assert!(rendered.contains("Authorization"), "header names remain diagnosable");
    }

    #[test]
    fn nested_config_debug_views_are_complete_and_secret_safe() {
        let database = DatabaseConfig {
            url: Some("postgresql://user:database-secret@localhost/scorchkit".to_string()),
            max_connections: 7,
            migrate_on_startup: false,
        };
        assert_eq!(
            format!("{database:?}"),
            "DatabaseConfig { url: Some(\"<configured>\"), max_connections: 7, migrate_on_startup: false }"
        );

        let auth = AuthConfig {
            bearer_token: Some("bearer-secret".to_string()),
            cookies: Some("cookie-secret".to_string()),
            username: Some("fixture-user".to_string()),
            password: Some("password-secret".to_string()),
            custom_header: Some("X-Fixture-Key".to_string()),
            custom_header_value: Some("header-secret".to_string()),
        };
        assert_eq!(
            format!("{auth:?}"),
            "AuthConfig { bearer_token: Some(\"***\"), cookies: Some(\"***\"), username: Some(\"fixture-user\"), password: Some(\"***\"), custom_header: Some(\"X-Fixture-Key\"), custom_header_value: Some(\"***\") }"
        );
    }

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

    #[test]
    fn engagement_configuration_round_trips_and_defaults_to_absent() {
        assert!(AppConfig::default().engagement.is_none());

        let policy = crate::engine::policy::EngagementPolicy::default()
            .allow_scope(crate::engine::scope::ScopeRule::parse("example.com").unwrap())
            .allow_capability(crate::engine::policy::Capability::DastScan)
            .allow_effect(crate::engine::policy::EffectClass::ActiveSafe);
        let config = AppConfig {
            engagement: Some(crate::engine::policy::Engagement::new("round-trip", policy)),
            ..AppConfig::default()
        };
        let encoded = toml::to_string(&config).expect("serialize engagement config");
        let decoded: AppConfig = toml::from_str(&encoded).expect("deserialize engagement config");

        assert_eq!(decoded.engagement, config.engagement);
    }

    #[test]
    fn ai_config_defaults_to_codex_and_round_trips() {
        let config = AiConfig::default();
        assert_eq!(config.provider, AiProviderKind::Codex);
        assert_eq!(config.resolved_binary(), "codex");

        let encoded = toml::to_string(&config).expect("serialize AI config");
        assert!(!encoded.contains("claude_binary"));
        let decoded: AiConfig = toml::from_str(&encoded).expect("deserialize AI config");
        assert_eq!(decoded.provider, AiProviderKind::Codex);
        assert_eq!(decoded.resolved_binary(), "codex");
        assert!(decoded.enabled);
    }

    #[test]
    fn legacy_claude_binary_selects_compatibility_adapter() {
        let config: AiConfig = toml::from_str(
            r#"
enabled = true
claude_binary = "/opt/claude"
model = "sonnet"
max_budget_usd = 0.5
"#,
        )
        .expect("deserialize legacy AI config");

        assert_eq!(config.provider, AiProviderKind::Claude);
        assert_eq!(config.resolved_binary(), "/opt/claude");
        assert_eq!(config.model.as_deref(), Some("sonnet"));
        assert_eq!(config.max_budget_usd, Some(0.5));
    }
}
