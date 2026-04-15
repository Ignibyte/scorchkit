//! Example third-party ScorchKit SAST code module.
//!
//! This crate demonstrates how to implement a custom [`CodeModule`] for
//! static code analysis. A plugin author:
//!
//! 1. Adds `scorchkit = "1.0"` and `async-trait = "0.1"` to `Cargo.toml`.
//! 2. Imports types from [`scorchkit::prelude`].
//! 3. Defines a struct implementing [`CodeModule`].
//! 4. Registers it by building a custom binary around ScorchKit's
//!    `CodeOrchestrator`.
//!
//! # The CodeModule Contract
//!
//! Mirrors [`ScanModule`] but operates on filesystem paths instead of URLs:
//! - Receives a [`CodeContext`] with a path, auto-detected language, and config
//! - The `languages()` method controls language-based filtering
//! - Returns `Result<Vec<Finding>>` like any scan module
//!
//! # When to Use CodeModule vs ScanModule
//!
//! - **`ScanModule`** — web scanning, network probing, anything that runs
//!   against a live URL target
//! - **`CodeModule`** — static analysis of source code, lockfile parsing,
//!   secret detection, dependency auditing

use async_trait::async_trait;
use scorchkit::prelude::*;

/// Example custom code scanner — flags files containing TODO comments.
///
/// Demonstrates a minimal `CodeModule` implementation. Walks the scan
/// path, reads Rust/Go/Python/JS files, and produces a finding per
/// TODO comment found.
#[derive(Debug, Default)]
pub struct TodoScanner;

#[async_trait]
impl CodeModule for TodoScanner {
    fn name(&self) -> &'static str {
        "TODO Comment Scanner"
    }

    fn id(&self) -> &'static str {
        "todo-scanner"
    }

    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }

    fn description(&self) -> &'static str {
        "Example plugin: flags TODO comments in source files"
    }

    fn languages(&self) -> &[&str] {
        // Empty slice = language-agnostic (runs on any codebase).
        // Return a specific list to restrict which projects this runs on.
        &[]
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Walk the scan path looking for source files.
        if let Ok(entries) = std::fs::read_dir(&ctx.path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !is_source_file(&path) {
                    continue;
                }

                let Ok(content) = std::fs::read_to_string(&path) else {
                    continue;
                };

                for (line_idx, line) in content.lines().enumerate() {
                    if line.contains("TODO") {
                        let line_num = line_idx + 1;
                        let affected = format!("{}:{}", path.display(), line_num);
                        findings.push(
                            Finding::new(
                                self.id(),
                                Severity::Info,
                                "TODO comment found",
                                format!("TODO comment in {}:{line_num}", path.display()),
                                &affected,
                            )
                            .with_evidence(line.trim())
                            .with_remediation(
                                "Resolve the TODO or convert it to a tracked issue.",
                            )
                            .with_confidence(1.0),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Check if a file path has a source-code extension.
fn is_source_file(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "go" | "py" | "js" | "ts" | "java" | "rb" | "php" | "c" | "cpp" | "h")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify module metadata.
    #[test]
    fn test_module_metadata() {
        let module = TodoScanner;
        assert_eq!(module.id(), "todo-scanner");
        assert_eq!(module.category(), CodeCategory::Sast);
        assert!(module.languages().is_empty());
        assert!(!module.requires_external_tool());
    }

    /// Verify source file detection.
    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(std::path::Path::new("foo.rs")));
        assert!(is_source_file(std::path::Path::new("bar.py")));
        assert!(is_source_file(std::path::Path::new("nested/baz.js")));
        assert!(!is_source_file(std::path::Path::new("README.md")));
        assert!(!is_source_file(std::path::Path::new("data.json")));
        assert!(!is_source_file(std::path::Path::new("no-extension")));
    }
}
