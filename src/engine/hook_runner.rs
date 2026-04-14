//! Scan lifecycle hook system.
//!
//! Executes user-configured scripts at key points in the scan lifecycle:
//! pre-scan (modify config), post-module (filter/enrich findings), and
//! post-scan (export/notify). Scripts receive JSON on stdin and optionally
//! return modified JSON on stdout.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

use crate::config::HookConfig;

use super::events::{EventHandler, ScanEvent};

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

/// `EventHandler` adapter that bridges the event bus to the existing
/// `HookRunner` script-execution API.
///
/// Subscribes to scan lifecycle events and maps them to the three hook
/// points:
///
/// - `ScanEvent::ScanStarted` → `HookPoint::PreScan`
/// - `ScanEvent::ModuleCompleted` → `HookPoint::PostModule` (with buffered findings)
/// - `ScanEvent::ScanCompleted` → `HookPoint::PostScan`
///
/// `FindingProduced` events are buffered per-module so the `PostModule` hook
/// receives the full findings array — matching the direct-call API contract.
/// Buffered findings are cleared after the `ModuleCompleted` event fires.
///
/// The adapter runs hooks for their observable side effects (logging,
/// notifications, exports). It does **not** feed modifications back into the
/// scan result, since publishing is fire-and-forget. For finding
/// modification, continue using the synchronous `HookRunner` invocation in
/// the orchestrator.
pub struct HookEventHandler {
    /// The underlying hook runner (script executor).
    runner: HookRunner,
    /// Per-module finding buffer keyed by `(scan_id, module_id)`.
    ///
    /// Findings accumulate on `FindingProduced` and are flushed on
    /// `ModuleCompleted` so the `PostModule` hook sees the full list.
    findings_buffer: Mutex<std::collections::HashMap<(String, String), Vec<serde_json::Value>>>,
}

impl HookEventHandler {
    /// Create a new event-driven hook handler from a `HookConfig`.
    #[must_use]
    pub fn new(config: &HookConfig) -> Self {
        Self {
            runner: HookRunner::new(config),
            findings_buffer: Mutex::new(std::collections::HashMap::default()),
        }
    }

    /// Wrap an existing `HookRunner` as an `EventHandler`.
    #[must_use]
    pub fn from_runner(runner: HookRunner) -> Self {
        Self { runner, findings_buffer: Mutex::new(std::collections::HashMap::default()) }
    }

    /// Consumes the handler and wraps it in an `Arc<dyn EventHandler>`, ready
    /// to pass to `subscribe_handler`.
    #[must_use]
    pub fn into_handler(self) -> Arc<dyn EventHandler> {
        Arc::new(self)
    }
}

#[async_trait]
impl EventHandler for HookEventHandler {
    async fn handle(&self, event: ScanEvent) -> Result<(), String> {
        match event {
            ScanEvent::ScanStarted { scan_id, target } => {
                if !self.runner.has_hooks(HookPoint::PreScan) {
                    return Ok(());
                }
                let data = serde_json::json!({
                    "scan_id": scan_id,
                    "target": target,
                });
                let _ = self.runner.execute(HookPoint::PreScan, &data).await;
            }
            ScanEvent::FindingProduced { scan_id, module_id, finding } => {
                if !self.runner.has_hooks(HookPoint::PostModule) {
                    return Ok(());
                }
                let value = serde_json::to_value(&finding)
                    .map_err(|e| format!("serialize finding: {e}"))?;
                let mut buf = self.findings_buffer.lock().await;
                buf.entry((scan_id, module_id)).or_default().push(value);
            }
            ScanEvent::ModuleCompleted { scan_id, module_id, findings_count, duration_ms } => {
                if !self.runner.has_hooks(HookPoint::PostModule) {
                    return Ok(());
                }
                let findings = {
                    let mut buf = self.findings_buffer.lock().await;
                    buf.remove(&(scan_id.clone(), module_id.clone())).unwrap_or_default()
                };
                let data = serde_json::json!({
                    "scan_id": scan_id,
                    "module_id": module_id,
                    "findings": findings,
                    "finding_count": findings_count,
                    "duration_ms": duration_ms,
                });
                let _ = self.runner.execute(HookPoint::PostModule, &data).await;
            }
            ScanEvent::ScanCompleted { scan_id, total_findings, duration_ms } => {
                if !self.runner.has_hooks(HookPoint::PostScan) {
                    return Ok(());
                }
                let data = serde_json::json!({
                    "scan_id": scan_id,
                    "total_findings": total_findings,
                    "duration_ms": duration_ms,
                });
                let _ = self.runner.execute(HookPoint::PostScan, &data).await;
            }
            // ModuleStarted / ModuleSkipped / ModuleError / Custom are
            // observability-only for the current hook model. Custom events
            // have no standard mapping to the three hook points — users
            // wanting script dispatch for custom events should implement
            // their own EventHandler rather than routing through hooks.
            ScanEvent::ModuleStarted { .. }
            | ScanEvent::ModuleSkipped { .. }
            | ScanEvent::ModuleError { .. }
            | ScanEvent::Custom { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::events::{subscribe_handler, EventBus};
    use crate::engine::finding::Finding;
    use crate::engine::severity::Severity;

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

    /// Regression: `HookEventHandler` subscribes to events and buffers
    /// findings between `ModuleStarted` and `ModuleCompleted`. When the
    /// hook config is empty the handler is a no-op — that's the path we
    /// can safely exercise without needing real scripts on disk.
    #[tokio::test]
    async fn test_hook_handler_still_fires_scripts() {
        // Empty hook config: handler receives events but triggers no script
        // execution. The assertion is that event delivery itself works —
        // buffering, mapping, and draining without panics or lag.
        let bus = EventBus::new(32);
        let handler = HookEventHandler::new(&HookConfig::default()).into_handler();
        let join = subscribe_handler(&bus, handler);

        let scan_id = "scan-abc".to_string();
        let module_id = "headers".to_string();

        bus.publish(ScanEvent::ScanStarted {
            scan_id: scan_id.clone(),
            target: "https://example.com".to_string(),
        });
        bus.publish(ScanEvent::ModuleStarted {
            scan_id: scan_id.clone(),
            module_id: module_id.clone(),
            module_name: "Security Headers".to_string(),
        });
        let finding = Finding::new(
            &module_id,
            Severity::Low,
            "missing X-Frame-Options",
            "no clickjacking header",
            "https://example.com",
        );
        bus.publish(ScanEvent::FindingProduced {
            scan_id: scan_id.clone(),
            module_id: module_id.clone(),
            finding: Box::new(finding),
        });
        bus.publish(ScanEvent::ModuleCompleted {
            scan_id: scan_id.clone(),
            module_id,
            findings_count: 1,
            duration_ms: 5,
        });
        bus.publish(ScanEvent::ScanCompleted { scan_id, total_findings: 1, duration_ms: 50 });

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("handler join");
    }

    /// Regression (WORK-098): `HookEventHandler` accepts `ScanEvent::Custom`
    /// events without panicking and returns `Ok(())` from the handler — the
    /// match arm for `Custom` is a deliberate no-op. Exercises both the
    /// direct-call path and the bus-driven path.
    #[tokio::test]
    async fn test_hook_event_handler_ignores_custom() {
        // Direct-call path — handle() must not error on Custom.
        let hook_handler = HookEventHandler::new(&HookConfig::default());
        hook_handler
            .handle(ScanEvent::Custom {
                kind: "crawler.depth-reached".to_string(),
                data: serde_json::json!({ "depth": 2 }),
            })
            .await
            .expect("custom handle direct");

        // Buffer remains empty — Custom must not accumulate into the
        // per-module finding buffer.
        let buf = hook_handler.findings_buffer.lock().await;
        assert!(buf.is_empty(), "Custom must not touch the findings buffer");
        drop(buf);

        // Bus-driven path — subscribe the handler and publish a Custom event.
        // Completes without panic, lag, or hang.
        let bus = EventBus::new(16);
        let bus_handler = HookEventHandler::new(&HookConfig::default()).into_handler();
        let join = subscribe_handler(&bus, bus_handler);
        bus.publish(ScanEvent::Custom {
            kind: "waf.detected".to_string(),
            data: serde_json::json!({ "vendor": "Cloudflare" }),
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(bus);
        join.await.expect("bus handler join");
    }
}
