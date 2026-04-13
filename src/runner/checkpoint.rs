//! Scan checkpoint system for resume-on-interrupt.
//!
//! After each module completes, the orchestrator saves a checkpoint file
//! containing the scan state (completed modules, accumulated findings,
//! config hash). If a scan is interrupted, `--resume <file>` reloads the
//! checkpoint and skips already-completed modules.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;

/// Persistent scan state for resume-on-interrupt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    /// Unique scan identifier (preserved across resume).
    pub scan_id: String,
    /// The target being scanned.
    pub target: String,
    /// Scan profile used.
    pub profile: String,
    /// Hash of the scan configuration (detects config changes).
    pub config_hash: u64,
    /// Module IDs that have completed successfully.
    pub completed_modules: Vec<String>,
    /// Findings accumulated from completed modules.
    pub findings: Vec<Finding>,
    /// When the scan was originally started.
    pub started_at: DateTime<Utc>,
    /// When this checkpoint was last updated.
    pub updated_at: DateTime<Utc>,
}

impl ScanCheckpoint {
    /// Create a new checkpoint for a fresh scan.
    #[must_use]
    pub fn new(scan_id: &str, target: &str, profile: &str, config_hash: u64) -> Self {
        let now = Utc::now();
        Self {
            scan_id: scan_id.to_string(),
            target: target.to_string(),
            profile: profile.to_string(),
            config_hash,
            completed_modules: Vec::new(),
            findings: Vec::new(),
            started_at: now,
            updated_at: now,
        }
    }

    /// Record a module as completed with its findings.
    pub fn record_module(&mut self, module_id: &str, findings: &[Finding]) {
        self.completed_modules.push(module_id.to_string());
        self.findings.extend_from_slice(findings);
        self.updated_at = Utc::now();
    }

    /// Check if a module has already been completed.
    #[must_use]
    pub fn is_completed(&self, module_id: &str) -> bool {
        self.completed_modules.iter().any(|id| id == module_id)
    }
}

/// Compute a deterministic hash of the scan configuration for change detection.
#[must_use]
pub fn hash_config(profile: &str, modules: &[String], target: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    profile.hash(&mut hasher);
    target.hash(&mut hasher);
    for m in modules {
        m.hash(&mut hasher);
    }
    hasher.finish()
}

/// Build the checkpoint file path for a given scan ID and output directory.
#[must_use]
pub fn checkpoint_path(output_dir: &Path, scan_id: &str) -> PathBuf {
    output_dir.join(format!(".scorchkit-checkpoint-{scan_id}.json"))
}

/// Save a checkpoint to disk.
///
/// # Errors
///
/// Returns an error if the file cannot be written or serialization fails.
pub fn save_checkpoint(checkpoint: &ScanCheckpoint, path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let json = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| ScorchError::Report(format!("serialize checkpoint: {e}")))?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load a checkpoint from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read or deserialization fails.
pub fn load_checkpoint(path: &Path) -> Result<ScanCheckpoint> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ScorchError::Config(format!("failed to read checkpoint {}: {e}", path.display()))
    })?;
    serde_json::from_str(&content)
        .map_err(|e| ScorchError::Config(format!("invalid checkpoint {}: {e}", path.display())))
}

/// Delete a checkpoint file (called on successful scan completion).
pub fn remove_checkpoint(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::severity::Severity;

    /// Verify a new checkpoint starts with empty completed modules and findings.
    #[test]
    fn checkpoint_new_is_empty() {
        let cp = ScanCheckpoint::new("scan-1", "https://example.com", "standard", 12345);
        assert!(cp.completed_modules.is_empty());
        assert!(cp.findings.is_empty());
        assert_eq!(cp.scan_id, "scan-1");
        assert_eq!(cp.target, "https://example.com");
    }

    /// Verify `record_module` adds module ID and findings.
    #[test]
    fn checkpoint_record_module() {
        let mut cp = ScanCheckpoint::new("scan-1", "url", "standard", 0);
        let findings = vec![Finding::new("headers", Severity::Low, "T", "D", "url")];
        cp.record_module("headers", &findings);
        assert!(cp.is_completed("headers"));
        assert!(!cp.is_completed("ssl"));
        assert_eq!(cp.findings.len(), 1);
    }

    /// Verify save and load round-trip preserves all data.
    #[test]
    fn checkpoint_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("checkpoint.json");

        let mut cp = ScanCheckpoint::new("scan-1", "https://example.com", "quick", 99);
        cp.record_module("headers", &[Finding::new("headers", Severity::Info, "T", "D", "url")]);

        save_checkpoint(&cp, &path).expect("save");
        let loaded = load_checkpoint(&path).expect("load");

        assert_eq!(loaded.scan_id, "scan-1");
        assert_eq!(loaded.target, "https://example.com");
        assert_eq!(loaded.profile, "quick");
        assert_eq!(loaded.config_hash, 99);
        assert!(loaded.is_completed("headers"));
        assert_eq!(loaded.findings.len(), 1);
    }

    /// Verify `remove_checkpoint` deletes the file without error.
    #[test]
    fn checkpoint_remove_deletes_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("checkpoint.json");
        std::fs::write(&path, "{}").expect("write");
        assert!(path.exists());
        remove_checkpoint(&path);
        assert!(!path.exists());
    }

    /// Verify `hash_config` is deterministic.
    #[test]
    fn config_hash_deterministic() {
        let modules = vec!["a".to_string(), "b".to_string()];
        let h1 = hash_config("standard", &modules, "https://example.com");
        let h2 = hash_config("standard", &modules, "https://example.com");
        assert_eq!(h1, h2);
    }

    /// Verify `hash_config` changes with different inputs.
    #[test]
    fn config_hash_differs() {
        let modules = vec!["a".to_string()];
        let h1 = hash_config("standard", &modules, "https://a.com");
        let h2 = hash_config("quick", &modules, "https://a.com");
        assert_ne!(h1, h2);
    }
}
