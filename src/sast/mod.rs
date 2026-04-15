//! Built-in SAST analysis modules.
//!
//! Contains Rust-native static analysis checks that work without
//! external tools. Currently includes dependency auditing via
//! lockfile parsing. All SAST tool wrappers are in `sast_tools/`.

pub mod dep_audit;

use crate::engine::code_module::CodeModule;

/// Register all built-in SAST modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CodeModule>> {
    vec![Box::new(dep_audit::DepAuditModule)]
}
