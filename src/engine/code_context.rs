//! Code scanning context — path-based alternative to `ScanContext`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::AppConfig;

use super::events::EventBus;
use super::shared_data::SharedData;

/// Known manifest filenames and their associated languages.
const MANIFEST_MAP: &[(&str, &str)] = &[
    ("Cargo.toml", "rust"),
    ("Cargo.lock", "rust"),
    ("package.json", "javascript"),
    ("package-lock.json", "javascript"),
    ("yarn.lock", "javascript"),
    ("pnpm-lock.yaml", "javascript"),
    ("go.mod", "go"),
    ("go.sum", "go"),
    ("requirements.txt", "python"),
    ("poetry.lock", "python"),
    ("Pipfile.lock", "python"),
    ("pyproject.toml", "python"),
    ("pom.xml", "java"),
    ("build.gradle", "java"),
    ("Gemfile.lock", "ruby"),
    ("composer.lock", "php"),
];

/// Shared context passed to every code scanning module.
#[derive(Clone, Debug)]
pub struct CodeContext {
    /// Root directory or file to scan.
    pub path: PathBuf,
    /// Detected or user-specified primary language.
    pub language: Option<String>,
    /// Discovered manifest files in the scan root.
    pub manifests: Vec<PathBuf>,
    /// Application configuration.
    pub config: Arc<AppConfig>,
    /// Shared data store for inter-module communication.
    pub shared_data: Arc<SharedData>,
    /// In-process event bus for scan lifecycle events.
    pub events: EventBus,
}

impl CodeContext {
    /// Create a new code context, auto-detecting language and manifests.
    #[must_use]
    pub fn new(path: PathBuf, language: Option<String>, config: Arc<AppConfig>) -> Self {
        let manifests = discover_manifests(&path);
        let detected_language = language.or_else(|| detect_language(&path));
        Self {
            path,
            language: detected_language,
            manifests,
            config,
            shared_data: Arc::new(SharedData::new()),
            events: EventBus::default(),
        }
    }
}

/// Detect the primary language by checking for manifest files at the root.
///
/// Returns the language associated with the first matching manifest file.
#[must_use]
pub fn detect_language(path: &Path) -> Option<String> {
    if !path.is_dir() {
        return None;
    }
    for &(manifest, language) in MANIFEST_MAP {
        if path.join(manifest).exists() {
            return Some(language.to_string());
        }
    }
    None
}

/// Discover manifest files in the scan root directory.
///
/// Checks for known manifest filenames (non-recursive, root only).
#[must_use]
pub fn discover_manifests(path: &Path) -> Vec<PathBuf> {
    if !path.is_dir() {
        return Vec::new();
    }
    MANIFEST_MAP.iter().map(|&(name, _)| path.join(name)).filter(|p| p.exists()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Verify `Cargo.toml` is detected as Rust.
    #[test]
    fn test_detect_language_rust() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("Cargo.toml"), "[package]")?;
        assert_eq!(detect_language(dir.path()), Some("rust".to_string()));
        Ok(())
    }

    /// Verify `package.json` is detected as JavaScript.
    #[test]
    fn test_detect_language_javascript() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("package.json"), "{}")?;
        assert_eq!(detect_language(dir.path()), Some("javascript".to_string()));
        Ok(())
    }

    /// Verify empty directory returns `None`.
    #[test]
    fn test_detect_language_none() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        assert_eq!(detect_language(dir.path()), None);
        Ok(())
    }

    /// Verify manifest discovery finds expected files.
    #[test]
    fn test_discover_manifests() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("Cargo.toml"), "[package]")?;
        fs::write(dir.path().join("Cargo.lock"), "")?;
        let manifests = discover_manifests(dir.path());
        assert_eq!(manifests.len(), 2);
        Ok(())
    }
}
