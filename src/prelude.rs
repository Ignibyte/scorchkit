//! Convenience re-exports for library consumers.
//!
//! Import the prelude to get all core types in scope:
//!
//! ```no_run
//! use scorchkit::prelude::*;
//! ```

// Core types
pub use crate::engine::error::{Result, ScorchError};
pub use crate::engine::finding::Finding;
pub use crate::engine::scan_result::ScanResult;
pub use crate::engine::severity::Severity;
pub use crate::engine::target::Target;

// Module traits
pub use crate::engine::code_module::{CodeCategory, CodeModule};
pub use crate::engine::module_trait::{ModuleCategory, ScanModule};

// Contexts
pub use crate::engine::code_context::CodeContext;
pub use crate::engine::scan_context::ScanContext;

// Configuration
pub use crate::config::AppConfig;

// Facade
pub use crate::facade::Engine;

#[cfg(test)]
mod tests {
    /// Verify all prelude re-exports are accessible via wildcard import.
    #[test]
    fn test_prelude_imports() {
        use super::*;

        // Verify types are in scope by referencing them
        let _severity = Severity::High;
        let _category = ModuleCategory::Recon;
        let _code_category = CodeCategory::Sast;

        // Verify Result alias works
        fn _example() -> Result<()> {
            Ok(())
        }
    }
}
