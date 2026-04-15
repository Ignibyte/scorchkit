//! High-level facade for using `ScorchKit` as a library.
//!
//! The [`Engine`] struct provides a simple entry point for running DAST
//! and SAST scans without manually constructing orchestrators, contexts,
//! or HTTP clients.
//!
//! ```no_run
//! use std::sync::Arc;
//! use scorchkit::facade::Engine;
//! use scorchkit::config::AppConfig;
//!
//! # async fn example() -> scorchkit::engine::error::Result<()> {
//! let config = Arc::new(AppConfig::default());
//! let engine = Engine::new(config);
//! let result = engine.scan("https://example.com").await?;
//! println!("Found {} findings", result.findings.len());
//! # Ok(())
//! # }
//! ```

use std::path::Path;
use std::sync::Arc;

use crate::config::AppConfig;
use crate::engine::code_context::CodeContext;
use crate::engine::error::{Result, ScorchError};
use crate::engine::scan_context::ScanContext;
use crate::engine::scan_result::ScanResult;
use crate::engine::target::Target;
use crate::runner::code_orchestrator::CodeOrchestrator;
use crate::runner::orchestrator::Orchestrator;

/// High-level scanning engine for library consumers.
///
/// Wraps the DAST [`Orchestrator`] and SAST [`CodeOrchestrator`] with
/// simple methods that handle context setup, module registration, and
/// execution in a single call.
///
/// For fine-grained control over module selection, profiles, or hooks,
/// use [`Orchestrator`] or [`CodeOrchestrator`] directly.
#[derive(Debug, Clone)]
pub struct Engine {
    config: Arc<AppConfig>,
}

impl Engine {
    /// Create a new engine with the given configuration.
    #[must_use]
    pub const fn new(config: Arc<AppConfig>) -> Self {
        Self { config }
    }

    /// Run a DAST scan against a URL target.
    ///
    /// Creates an HTTP client, scan context, and orchestrator, registers all
    /// default modules, and runs the scan. Returns the complete scan result
    /// with findings.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid, the HTTP client cannot be
    /// built, or the scan encounters a fatal error.
    pub async fn scan(&self, url: &str) -> Result<ScanResult> {
        let target = Target::parse(url)?;
        let http_client = build_http_client(&self.config)?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.run(true).await
    }

    /// Run a DAST scan with a specific profile.
    ///
    /// Profiles control which modules run:
    /// - `"quick"` — fast built-in modules only (headers, tech, ssl, misconfig)
    /// - `"standard"` — all built-in modules
    /// - `"thorough"` — all modules including external tool wrappers
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or the scan fails.
    pub async fn scan_with_profile(&self, url: &str, profile: &str) -> Result<ScanResult> {
        let target = Target::parse(url)?;
        let http_client = build_http_client(&self.config)?;
        let ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let mut orchestrator = Orchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.apply_profile(profile);
        orchestrator.run(true).await
    }

    /// Run a SAST code scan against a filesystem path.
    ///
    /// Creates a code context with auto-detected language and manifests,
    /// registers all default code modules (built-in + tool wrappers), and
    /// runs the scan.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or the scan fails.
    pub async fn code_scan(&self, path: &Path) -> Result<ScanResult> {
        let ctx = CodeContext::new(path.to_path_buf(), None, Arc::clone(&self.config));

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.run().await
    }

    /// Run a SAST code scan for a specific language.
    ///
    /// Only modules supporting the given language will run. Language-agnostic
    /// modules (like the dependency auditor) always run regardless.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails.
    pub async fn code_scan_language(&self, path: &Path, language: &str) -> Result<ScanResult> {
        let ctx = CodeContext::new(
            path.to_path_buf(),
            Some(language.to_string()),
            Arc::clone(&self.config),
        );

        let mut orchestrator = CodeOrchestrator::new(ctx);
        orchestrator.register_default_modules();
        orchestrator.filter_by_language(language);
        orchestrator.run().await
    }

    /// Run a combined DAST+SAST scan: web target and source code path.
    ///
    /// Runs DAST and SAST concurrently, then merges findings into a single
    /// `ScanResult`. The DAST target is the primary — SAST findings are
    /// appended. If SAST fails, only DAST results are returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the DAST scan fails. SAST failures are non-fatal.
    pub async fn full_scan(&self, url: &str, code_path: &Path) -> Result<ScanResult> {
        let target = Target::parse(url)?;
        let http_client = build_http_client(&self.config)?;
        let dast_ctx = ScanContext::new(target, Arc::clone(&self.config), http_client);

        let mut dast_orchestrator = Orchestrator::new(dast_ctx);
        dast_orchestrator.register_default_modules();

        let code_ctx = CodeContext::new(code_path.to_path_buf(), None, Arc::clone(&self.config));
        let mut sast_orchestrator = CodeOrchestrator::new(code_ctx);
        sast_orchestrator.register_default_modules();

        let (dast_result, sast_result) =
            tokio::join!(dast_orchestrator.run(true), sast_orchestrator.run());

        let mut result = dast_result?;

        if let Ok(code_result) = sast_result {
            result.merge(code_result);
        }

        Ok(result)
    }

    /// Get a reference to the engine's configuration.
    #[must_use]
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Run an infrastructure scan against a host, IP, or CIDR range.
    ///
    /// Parses `target` as an [`crate::engine::infra_target::InfraTarget`]
    /// (IP, CIDR, host, or `host:port`), builds a fresh
    /// [`crate::engine::infra_context::InfraContext`], registers every
    /// built-in [`crate::engine::infra_module::InfraModule`], and runs the
    /// orchestrator. Returns the resulting [`ScanResult`] with findings.
    ///
    /// For fine-grained control, use
    /// [`crate::runner::infra_orchestrator::InfraOrchestrator`] directly.
    ///
    /// # Errors
    ///
    /// Returns an error if the target cannot be parsed, the HTTP client
    /// cannot be built, or the scan encounters a fatal failure.
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use scorchkit::config::AppConfig;
    /// use scorchkit::facade::Engine;
    ///
    /// # async fn example() -> scorchkit::engine::error::Result<()> {
    /// let engine = Engine::new(Arc::new(AppConfig::default()));
    /// let result = engine.infra_scan("127.0.0.1").await?;
    /// println!("infra findings: {}", result.findings.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "infra")]
    pub async fn infra_scan(&self, target: &str) -> Result<ScanResult> {
        use crate::engine::infra_context::InfraContext;
        use crate::engine::infra_target::InfraTarget;
        use crate::infra::cve_lookup::build_cve_lookup;
        use crate::infra::cve_match::CveMatchModule;
        use crate::runner::infra_orchestrator::InfraOrchestrator;

        let infra_target = InfraTarget::parse(target)?;
        let http_client = build_http_client(&self.config)?;
        let ctx = InfraContext::new(infra_target, Arc::clone(&self.config), http_client);

        let mut orchestrator = InfraOrchestrator::new(ctx);
        orchestrator.register_default_modules();

        // Layer the CVE matcher on top of the defaults when [cve] is
        // configured. `build_cve_lookup` returns Ok(None) for the
        // default `disabled` backend, leaving the orchestrator
        // unchanged.
        if let Some(lookup) = build_cve_lookup(&self.config)? {
            orchestrator.add_module(Box::new(CveMatchModule::new(lookup)));
        }

        orchestrator.run(true).await
    }

    /// Run a unified DAST + SAST + Infra assessment.
    ///
    /// At least one of `url`, `code_path`, or `infra_target` must be
    /// `Some`. The three orchestrators run concurrently via
    /// `tokio::join!`; failures in any domain are logged and skipped so
    /// partial results still come back. Results merge via
    /// [`ScanResult::merge`], with DAST → SAST → Infra priority for the
    /// receiving base (mirroring [`Engine::full_scan`]).
    ///
    /// # Errors
    ///
    /// Returns [`crate::engine::error::ScorchError::Config`] when every
    /// input is `None`. Returns the first available error only when every
    /// provided domain failed.
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use std::sync::Arc;
    /// use scorchkit::config::AppConfig;
    /// use scorchkit::facade::Engine;
    ///
    /// # async fn example() -> scorchkit::engine::error::Result<()> {
    /// let engine = Engine::new(Arc::new(AppConfig::default()));
    /// let result = engine
    ///     .full_assessment(
    ///         Some("https://example.com"),
    ///         Some(Path::new("./src")),
    ///         Some("127.0.0.1"),
    ///     )
    ///     .await?;
    /// println!("unified findings: {}", result.findings.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "infra")]
    pub async fn full_assessment(
        &self,
        url: Option<&str>,
        code_path: Option<&Path>,
        infra_target: Option<&str>,
    ) -> Result<ScanResult> {
        use crate::engine::error::ScorchError;

        if url.is_none() && code_path.is_none() && infra_target.is_none() {
            return Err(ScorchError::Config(
                "full_assessment requires at least one of url, code_path, or infra_target".into(),
            ));
        }

        let dast_future = async {
            match url {
                Some(u) => Some(self.scan(u).await),
                None => None,
            }
        };
        let sast_future = async {
            match code_path {
                Some(p) => Some(self.code_scan(p).await),
                None => None,
            }
        };
        let infra_future = async {
            match infra_target {
                Some(t) => Some(self.infra_scan(t).await),
                None => None,
            }
        };

        let (dast, sast, infra) = tokio::join!(dast_future, sast_future, infra_future);

        // Pick the first available Ok as the base, merge the others into it.
        // Priority: DAST > SAST > Infra (matches full_scan precedent).
        let mut base: Option<ScanResult> = None;
        let mut first_err: Option<ScorchError> = None;

        absorb_outcome(dast, &mut base, &mut first_err);
        absorb_outcome(sast, &mut base, &mut first_err);
        absorb_outcome(infra, &mut base, &mut first_err);

        base.ok_or_else(|| {
            first_err.unwrap_or_else(|| ScorchError::Config("assess: no results".into()))
        })
    }
}

/// Fold one orchestrator outcome into the assembling base result.
///
/// `None` means the domain wasn't requested and is a no-op. An `Ok`
/// result either becomes the base (if none yet) or is merged into the
/// existing base. An `Err` is logged at `warn` and retained as
/// `first_err` for the fallback error path.
#[cfg(feature = "infra")]
fn absorb_outcome(
    outcome: Option<Result<ScanResult>>,
    base: &mut Option<ScanResult>,
    first_err: &mut Option<crate::engine::error::ScorchError>,
) {
    let Some(result) = outcome else {
        return;
    };
    match result {
        Ok(r) => match base.as_mut() {
            Some(b) => b.merge(r),
            None => *base = Some(r),
        },
        Err(e) => {
            tracing::warn!("assess: domain failed: {e}");
            if first_err.is_none() {
                *first_err = Some(e);
            }
        }
    }
}

/// Build an HTTP client from application configuration.
///
/// Configures: auth headers (bearer, basic, cookies, custom), custom scan
/// headers, user agent, timeouts, TLS settings, redirect policy, cookie
/// jar, and proxy support.
///
/// # Errors
///
/// Returns an error if the proxy URL is invalid or the client cannot be built.
pub fn build_http_client(config: &AppConfig) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();

    // Auth headers
    if let Some(ref token) = config.auth.bearer_token {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref username) = config.auth.username {
        let password = config.auth.password.as_deref().unwrap_or("");
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Basic {encoded}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
    if let Some(ref cookies) = config.auth.cookies {
        if let Ok(val) = reqwest::header::HeaderValue::from_str(cookies) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }
    if let (Some(ref name), Some(ref value)) =
        (&config.auth.custom_header, &config.auth.custom_header_value)
    {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    // Custom scan headers
    for (name, value) in &config.scan.headers {
        if let (Ok(header_name), Ok(header_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_val);
        }
    }

    let mut builder = reqwest::Client::builder()
        .user_agent(&config.scan.user_agent)
        .timeout(std::time::Duration::from_secs(config.scan.timeout_seconds))
        .default_headers(headers)
        .cookie_store(true)
        .danger_accept_invalid_certs(config.scan.insecure);

    if config.scan.follow_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::limited(config.scan.max_redirects));
    } else {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    // Proxy support
    if let Some(ref proxy_url) = config.scan.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScorchError::Config(format!("invalid proxy URL '{proxy_url}': {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| ScorchError::Config(format!("failed to build HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify `Engine` can be constructed with a default config.
    #[test]
    fn test_engine_new() {
        let config = Arc::new(AppConfig::default());
        let engine = Engine::new(config);
        // Verify engine holds a valid config reference
        assert!(!engine.config().scan.user_agent.is_empty());
    }

    /// Verify `code_scan` on an empty temporary directory produces
    /// an empty scan result with no findings.
    #[tokio::test]
    async fn test_engine_code_scan() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| ScorchError::Config(e.to_string()))?;
        let config = Arc::new(AppConfig::default());
        let engine = Engine::new(config);
        let result = engine.code_scan(dir.path()).await?;
        assert!(result.findings.is_empty());
        Ok(())
    }
}
