//! Scan lifecycle hook system.
//!
//! Executes user-configured scripts at key points in the scan lifecycle:
//! pre-scan (modify config), post-module (filter/enrich findings), and
//! post-scan (export/notify). Scripts receive JSON on stdin and optionally
//! return modified JSON on stdout.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::warn;

use crate::config::HookConfig;

/// A point in the scan lifecycle where hooks can fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPoint {
    /// Before scanning begins. Can modify scan configuration.
    PreScan,
    /// After each module completes. Can filter/enrich findings.
    PostModule,
    /// After all modules complete. Fire-and-forget (output ignored).
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

/// Executes lifecycle hook scripts at configured scan points.
///
/// Hook scripts receive JSON on stdin and can optionally return modified
/// JSON on stdout. Scripts are executed sequentially within each hook point,
/// with the output of one becoming the input for the next.
pub struct HookRunner {
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
    /// Hook failures are fail-open: errors are logged as warnings but
    /// execution continues with the unmodified input.
    pub async fn execute(
        &self,
        point: HookPoint,
        input: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        let scripts = self.scripts_for(point);
        if scripts.is_empty() {
            return None;
        }

        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        let mut current = input.clone();
        let mut modified = false;

        for script in scripts {
            let json_input = match serde_json::to_string(&current) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Hook {point}: failed to serialize input for {}: {e}", script.display());
                    continue;
                }
            };

            match self.run_script(script, &json_input, timeout_duration).await {
                Ok(Some(output)) => {
                    current = output;
                    modified = true;
                }
                Ok(None) => {
                    // Script produced no output — passthrough
                }
                Err(e) => {
                    warn!("Hook {point}: script {} failed: {e}", script.display());
                }
            }
        }

        if modified {
            Some(current)
        } else {
            None
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
    async fn run_script(
        &self,
        script: &std::path::Path,
        json_input: &str,
        timeout: Duration,
    ) -> std::result::Result<Option<serde_json::Value>, String> {
        let mut child = tokio::process::Command::new(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn error: {e}"))?;

        // Write JSON to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(json_input.as_bytes())
                .await
                .map_err(|e| format!("stdin write error: {e}"))?;
            // Drop stdin to close the pipe and signal EOF
            drop(stdin);
        }

        // Wait with timeout
        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| format!("timed out after {}s", timeout.as_secs()))?
            .map_err(|e| format!("wait error: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("exited with status {}: {}", output.status, stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        if trimmed.is_empty() {
            return Ok(None);
        }

        match serde_json::from_str(trimmed) {
            Ok(value) => Ok(Some(value)),
            Err(e) => {
                warn!("Hook script {} produced invalid JSON (ignored): {e}", script.display());
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify HookRunner with empty config has no hooks.
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

    /// Verify HookPoint Display formatting.
    #[test]
    fn test_hook_point_display() {
        assert_eq!(HookPoint::PreScan.to_string(), "pre_scan");
        assert_eq!(HookPoint::PostModule.to_string(), "post_module");
        assert_eq!(HookPoint::PostScan.to_string(), "post_scan");
    }
}
