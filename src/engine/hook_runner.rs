//! Scan lifecycle hook system.
//!
//! Executes user-configured scripts at key points in the scan lifecycle:
//! pre-scan (modify config), post-module (filter/enrich findings), and
//! post-scan (export/notify). Scripts receive JSON on stdin and optionally
//! return modified JSON on stdout.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use crate::config::HookConfig;
use crate::runner::subprocess::ToolOutput;

use super::error::{Result, ScorchError};

/// A point in the scan lifecycle where hooks can fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookPoint {
    /// Before scanning begins. Can modify scan configuration.
    PreScan,
    /// After each module completes. Can filter/enrich findings.
    PostModule,
    /// After all modules complete. Output is ignored, but completion is awaited.
    PostScan,
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreScan => write!(f, "pre_scan"),
            Self::PostModule => write!(f, "post_module"),
            Self::PostScan => write!(f, "post_scan"),
        }
    }
}

/// Policy-sealed process boundary used by lifecycle hooks.
#[async_trait]
pub(crate) trait HookExecutor: Sync {
    async fn run_hook_script(
        &self,
        script: &std::path::Path,
        json_input: &str,
        timeout: Duration,
    ) -> Result<ToolOutput>;
}

#[async_trait]
impl HookExecutor for super::scan_context::ScanContext {
    async fn run_hook_script(
        &self,
        script: &std::path::Path,
        json_input: &str,
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.run_tool_with_stdin(script.to_string_lossy().as_ref(), json_input.as_bytes(), timeout)
            .await
    }
}

#[async_trait]
impl HookExecutor for super::code_context::CodeContext {
    async fn run_hook_script(
        &self,
        script: &std::path::Path,
        json_input: &str,
        timeout: Duration,
    ) -> Result<ToolOutput> {
        self.run_tool_with_stdin(script.to_string_lossy().as_ref(), json_input.as_bytes(), timeout)
            .await
    }
}

/// Executes lifecycle hook scripts at configured scan points.
///
/// Hook scripts receive JSON on stdin and can optionally return modified
/// JSON on stdout. Scripts are executed sequentially within each hook point,
/// with the output of one becoming the input for the next.
pub(crate) struct HookRunner {
    /// The hook configuration specifying scripts for each lifecycle point.
    config: HookConfig,
}

impl HookRunner {
    /// Create a new hook runner from the given configuration.
    #[must_use]
    pub fn new(config: &HookConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Check whether any hooks are configured for the given lifecycle point.
    #[must_use]
    pub fn has_hooks(&self, point: HookPoint) -> bool {
        !self.scripts_for(point).is_empty()
    }

    /// Execute all hook scripts for the given lifecycle point.
    ///
    /// Each script receives `input` as JSON on stdin. If a script produces
    /// valid JSON on stdout, that becomes the input for the next script.
    /// If no script modifies the data, returns `None`.
    ///
    /// Hook failures follow [`HookConfig::fail_open`]. Fail-open logs and
    /// continues; fail-closed returns a typed error and aborts the scan.
    pub async fn execute<E: HookExecutor>(
        &self,
        point: HookPoint,
        input: &serde_json::Value,
        executor: &E,
    ) -> Result<Option<serde_json::Value>> {
        let scripts = self.scripts_for(point);
        if scripts.is_empty() {
            return Ok(None);
        }

        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        let mut current = input.clone();
        let mut modified = false;

        for script in scripts {
            let json_input = match serde_json::to_string(&current) {
                Ok(s) => s,
                Err(e) => {
                    self.handle_failure(format!(
                        "{point}: failed to serialize input for {}: {e}",
                        script.display()
                    ))?;
                    continue;
                }
            };

            match Self::run_script(executor, script, &json_input, timeout_duration).await {
                Ok(Some(output)) => {
                    current = output;
                    modified = true;
                }
                Ok(None) => {
                    // Script produced no output — passthrough
                }
                Err(e) => {
                    self.handle_failure(format!(
                        "{point}: script {} failed: {e}",
                        script.display()
                    ))?;
                }
            }
        }

        if modified {
            Ok(Some(current))
        } else {
            Ok(None)
        }
    }

    fn handle_failure(&self, message: String) -> Result<()> {
        if self.config.fail_open {
            warn!("{}", crate::report::terminal::escape_terminal_text(&message));
            Ok(())
        } else {
            Err(ScorchError::Hook(message))
        }
    }

    /// Get the list of scripts configured for a given hook point.
    fn scripts_for(&self, point: HookPoint) -> &[PathBuf] {
        match point {
            HookPoint::PreScan => &self.config.pre_scan,
            HookPoint::PostModule => &self.config.post_module,
            HookPoint::PostScan => &self.config.post_scan,
        }
    }

    /// Run a single hook script, piping JSON to stdin and capturing stdout.
    ///
    /// Returns `Ok(Some(value))` if the script produced valid JSON,
    /// `Ok(None)` if stdout was empty, or `Err` on failure.
    async fn run_script<E: HookExecutor>(
        executor: &E,
        script: &std::path::Path,
        json_input: &str,
        timeout: Duration,
    ) -> std::result::Result<Option<serde_json::Value>, String> {
        let output = executor
            .run_hook_script(script, json_input, timeout)
            .await
            .map_err(|error| error.to_string())?;

        let trimmed = output.stdout.trim();

        if trimmed.is_empty() {
            return Ok(None);
        }

        serde_json::from_str(trimmed)
            .map(Some)
            .map_err(|error| format!("script {} produced invalid JSON: {error}", script.display()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[derive(Debug)]
    struct StubExecutor {
        result: std::result::Result<String, String>,
    }

    #[async_trait]
    impl HookExecutor for StubExecutor {
        async fn run_hook_script(
            &self,
            _script: &std::path::Path,
            _json_input: &str,
            _timeout: Duration,
        ) -> Result<ToolOutput> {
            match &self.result {
                Ok(stdout) => Ok(ToolOutput {
                    stdout: stdout.clone(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration: Duration::ZERO,
                    resolved_program: PathBuf::from("/stub/hook"),
                }),
                Err(error) => Err(ScorchError::Hook(error.clone())),
            }
        }
    }

    /// Verify `HookRunner` with empty config has no hooks.
    #[test]
    fn test_empty_hooks() {
        let config = HookConfig::default();
        let runner = HookRunner::new(&config);
        assert!(!runner.has_hooks(HookPoint::PreScan));
        assert!(!runner.has_hooks(HookPoint::PostModule));
        assert!(!runner.has_hooks(HookPoint::PostScan));
    }

    /// Verify hook point selection returns correct scripts.
    #[test]
    fn test_hook_point_selection() {
        let config = HookConfig {
            pre_scan: vec![PathBuf::from("./hooks/auth.sh")],
            post_module: vec![],
            post_scan: vec![PathBuf::from("./hooks/notify.sh")],
            ..HookConfig::default()
        };
        let runner = HookRunner::new(&config);
        assert!(runner.has_hooks(HookPoint::PreScan));
        assert!(!runner.has_hooks(HookPoint::PostModule));
        assert!(runner.has_hooks(HookPoint::PostScan));
    }

    /// Verify `HookPoint` Display formatting.
    #[test]
    fn test_hook_point_display() {
        assert_eq!(HookPoint::PreScan.to_string(), "pre_scan");
        assert_eq!(HookPoint::PostModule.to_string(), "post_module");
        assert_eq!(HookPoint::PostScan.to_string(), "post_scan");
    }

    #[tokio::test]
    async fn hook_output_can_modify_json() {
        let config =
            HookConfig { post_module: vec![PathBuf::from("/stub/hook")], ..HookConfig::default() };
        let runner = HookRunner::new(&config);
        let executor = StubExecutor { result: Ok("{\"kept\":true}".to_string()) };
        let output = runner
            .execute(HookPoint::PostModule, &serde_json::json!({}), &executor)
            .await
            .expect("hook succeeds")
            .expect("hook modifies input");
        assert_eq!(output["kept"], true);
    }

    #[tokio::test]
    async fn fail_closed_hook_errors_abort() {
        let config = HookConfig {
            pre_scan: vec![PathBuf::from("/stub/hook")],
            fail_open: false,
            ..HookConfig::default()
        };
        let runner = HookRunner::new(&config);
        let executor = StubExecutor { result: Err("boom".to_string()) };
        let error = runner
            .execute(HookPoint::PreScan, &serde_json::json!({}), &executor)
            .await
            .expect_err("fail-closed hook must abort");
        assert!(matches!(error, ScorchError::Hook(_)));
    }

    #[tokio::test]
    async fn fail_open_hook_errors_continue() {
        let config = HookConfig {
            pre_scan: vec![PathBuf::from("/stub/hook")],
            fail_open: true,
            ..HookConfig::default()
        };
        let runner = HookRunner::new(&config);
        let executor = StubExecutor { result: Err("boom".to_string()) };
        let output = runner
            .execute(HookPoint::PreScan, &serde_json::json!({}), &executor)
            .await
            .expect("fail-open hook continues");
        assert!(output.is_none());
    }
}
