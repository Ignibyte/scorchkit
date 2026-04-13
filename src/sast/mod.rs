//! Built-in SAST analysis modules.
//!
//! This module will contain Rust-native static analysis checks
//! (dependency auditing, secret detection, configuration scanning).
//! Currently empty — all SAST functionality is provided by external
//! tool wrappers in `sast_tools/`.

use crate::engine::code_module::CodeModule;

/// Register all built-in SAST modules.
///
/// Currently returns an empty list. Built-in analyzers will be added
/// in future releases.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CodeModule>> {
    Vec::new()
}
