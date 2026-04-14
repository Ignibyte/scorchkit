//! Built-in JSONL audit-log subscriber for scan-lifecycle events.
//!
//! [`AuditLogHandler`] implements [`EventHandler`] and appends each received
//! [`ScanEvent`] to a file as a single JSON record followed by `\n`. The
//! sink is best-effort observability — I/O errors are logged at `warn` and
//! the scan continues uninterrupted.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> scorchkit::engine::error::Result<()> {
//! use std::path::Path;
//! use std::sync::Arc;
//! use scorchkit::engine::audit_log::AuditLogHandler;
//! use scorchkit::engine::events::{subscribe_handler, EventBus};
//!
//! let bus = EventBus::default();
//! let handler = Arc::new(AuditLogHandler::new(Path::new("./audit.jsonl"))?);
//! let _join = subscribe_handler(&bus, handler);
//! # Ok(())
//! # }
//! ```

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::config::AuditLogConfig;

use super::error::{Result, ScorchError};
use super::events::{subscribe_handler, EventBus, EventHandler, ScanEvent};

/// Appends [`ScanEvent`]s to a file as JSON Lines.
///
/// Uses a buffered writer protected by an async mutex so concurrent handler
/// invocations serialize their writes. Every event flushes the buffer so a
/// process crash loses at most the in-flight line.
pub struct AuditLogHandler {
    writer: Mutex<BufWriter<File>>,
}

impl AuditLogHandler {
    /// Open the audit log at `path` in append+create mode.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::Io`] if the file cannot be opened — parent
    /// directory missing, insufficient permissions, etc.
    pub fn new(path: &Path) -> Result<Self> {
        let file =
            OpenOptions::new().create(true).append(true).open(path).map_err(ScorchError::from)?;
        Ok(Self { writer: Mutex::new(BufWriter::new(file)) })
    }
}

/// Construct and subscribe an [`AuditLogHandler`] if the configuration
/// enables audit logging.
///
/// Returns the subscriber's [`JoinHandle`] so the caller can decide whether
/// to await it (typically not — the task exits when the bus is dropped).
/// Returns `None` when the config is disabled, the path is missing, or the
/// file cannot be opened. File-open failures are logged at `warn` and do
/// not abort the scan.
#[must_use]
pub fn subscribe_audit_log_if_enabled(
    config: &AuditLogConfig,
    bus: &EventBus,
) -> Option<JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    let path = config.path.as_ref()?;
    match AuditLogHandler::new(path) {
        Ok(handler) => {
            let handler: Arc<dyn EventHandler> = Arc::new(handler);
            Some(subscribe_handler(bus, handler))
        }
        Err(e) => {
            warn!("audit log: failed to open {}: {e}", path.display());
            None
        }
    }
}

#[async_trait]
impl EventHandler for AuditLogHandler {
    async fn handle(&self, event: ScanEvent) -> std::result::Result<(), String> {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                warn!("audit log: serialize failed: {e}");
                return Ok(());
            }
        };

        // Hold the lock only for the duration of the write + flush; drop
        // explicitly so clippy::significant_drop_tightening is satisfied.
        {
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(line.as_bytes()) {
                warn!("audit log: write failed: {e}");
                return Ok(());
            }
            if let Err(e) = writer.write_all(b"\n") {
                warn!("audit log: newline write failed: {e}");
                return Ok(());
            }
            if let Err(e) = writer.flush() {
                warn!("audit log: flush failed: {e}");
            }
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
    use std::io::Read;
    use std::sync::Arc;
    use std::time::Duration;

    fn read_file(path: &Path) -> String {
        let mut buf = String::new();
        File::open(path).expect("open").read_to_string(&mut buf).expect("read");
        buf
    }

    /// Construction succeeds with a valid path and creates the file.
    #[tokio::test]
    async fn test_new_opens_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let handler = AuditLogHandler::new(&path).expect("new");
        assert!(path.exists(), "file should be created");
        drop(handler);
    }

    /// Invalid path (parent dir missing) returns an error.
    #[tokio::test]
    async fn test_new_rejects_invalid_path() {
        let bogus = Path::new("/nonexistent-dir-12345/audit.jsonl");
        let err = AuditLogHandler::new(bogus);
        assert!(err.is_err(), "opening in missing dir must fail");
    }

    /// A single event produces one JSON line ending in `\n`.
    #[tokio::test]
    async fn test_handle_writes_jsonl_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let handler = AuditLogHandler::new(&path).expect("new");

        handler
            .handle(ScanEvent::ScanStarted {
                scan_id: "scan-1".to_string(),
                target: "https://example.com".to_string(),
            })
            .await
            .expect("handle");

        // Drop handler to release the BufWriter.
        drop(handler);

        let contents = read_file(&path);
        let trimmed = contents.trim_end_matches('\n');
        assert_eq!(contents.lines().count(), 1);
        let parsed: serde_json::Value = serde_json::from_str(trimmed).expect("parse json");
        assert!(parsed.get("ScanStarted").is_some(), "expected externally tagged variant");
    }

    /// Multiple events are appended in order, each on its own line.
    #[tokio::test]
    async fn test_handle_appends_multiple_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let handler = AuditLogHandler::new(&path).expect("new");

        handler
            .handle(ScanEvent::ScanStarted {
                scan_id: "scan-1".to_string(),
                target: "https://example.com".to_string(),
            })
            .await
            .expect("scan-started");
        handler
            .handle(ScanEvent::ModuleStarted {
                scan_id: "scan-1".to_string(),
                module_id: "headers".to_string(),
                module_name: "Security Headers".to_string(),
            })
            .await
            .expect("module-started");
        handler
            .handle(ScanEvent::ScanCompleted {
                scan_id: "scan-1".to_string(),
                total_findings: 0,
                duration_ms: 5,
            })
            .await
            .expect("scan-completed");

        drop(handler);

        let contents = read_file(&path);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("ScanStarted"));
        assert!(lines[1].contains("ModuleStarted"));
        assert!(lines[2].contains("ScanCompleted"));

        // Every line must be valid JSON.
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).expect("valid json");
        }
    }

    /// Every `ScanEvent` variant serializes without panicking.
    #[tokio::test]
    async fn test_all_scan_event_variants_serialize() {
        let finding = Finding::new(
            "headers",
            Severity::Low,
            "missing HSTS",
            "example",
            "https://example.com",
        );

        let events = vec![
            ScanEvent::ScanStarted {
                scan_id: "s".to_string(),
                target: "https://example.com".to_string(),
            },
            ScanEvent::ModuleStarted {
                scan_id: "s".to_string(),
                module_id: "headers".to_string(),
                module_name: "Security Headers".to_string(),
            },
            ScanEvent::ModuleCompleted {
                scan_id: "s".to_string(),
                module_id: "headers".to_string(),
                findings_count: 1,
                duration_ms: 10,
            },
            ScanEvent::ModuleSkipped {
                scan_id: "s".to_string(),
                module_id: "nuclei".to_string(),
                reason: "tool missing".to_string(),
            },
            ScanEvent::ModuleError {
                scan_id: "s".to_string(),
                module_id: "ssl".to_string(),
                error: "connect timeout".to_string(),
            },
            ScanEvent::FindingProduced {
                scan_id: "s".to_string(),
                module_id: "headers".to_string(),
                finding: Box::new(finding),
            },
            ScanEvent::ScanCompleted {
                scan_id: "s".to_string(),
                total_findings: 1,
                duration_ms: 100,
            },
            ScanEvent::Custom {
                kind: "crawler.depth-reached".to_string(),
                data: serde_json::json!({ "depth": 2 }),
            },
        ];

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let handler = AuditLogHandler::new(&path).expect("new");

        for event in events {
            handler.handle(event).await.expect("handle");
        }
        drop(handler);

        let contents = read_file(&path);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 8, "all 8 variants must produce a line");
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).expect("valid json");
        }
    }

    /// End-to-end: handler subscribed via the bus receives published events.
    #[tokio::test]
    async fn test_handle_via_event_bus() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let handler: Arc<dyn EventHandler> = Arc::new(AuditLogHandler::new(&path).expect("new"));

        let bus = EventBus::new(16);
        let join = subscribe_handler(&bus, handler);

        bus.publish(ScanEvent::ScanStarted {
            scan_id: "scan-bus".to_string(),
            target: "https://example.com".to_string(),
        });
        bus.publish(ScanEvent::ScanCompleted {
            scan_id: "scan-bus".to_string(),
            total_findings: 0,
            duration_ms: 1,
        });

        tokio::time::sleep(Duration::from_millis(40)).await;
        drop(bus);
        join.await.expect("join");

        let contents = read_file(&path);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ScanStarted"));
        assert!(lines[1].contains("ScanCompleted"));
    }
}
