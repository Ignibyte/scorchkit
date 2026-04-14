//! External SAST tool wrappers.
//!
//! Each module wraps an external security tool for static code analysis,
//! following the same pattern as `tools/` for DAST.

pub mod bandit;
pub mod checkov;
pub mod gitleaks;
pub mod gosec;
pub mod grype;
pub mod osv_scanner;
pub mod semgrep;

use crate::engine::code_module::CodeModule;

/// Register all external SAST tool wrapper modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn CodeModule>> {
    vec![
        Box::new(semgrep::SemgrepModule),
        Box::new(osv_scanner::OsvScannerModule),
        Box::new(gitleaks::GitleaksModule),
        Box::new(bandit::BanditModule),
        Box::new(gosec::GosecModule),
        Box::new(checkov::CheckovModule),
        Box::new(grype::GrypeModule),
    ]
}
