//! External SAST tool wrappers.
//!
//! Each module wraps an external security tool for static code analysis,
//! following the same pattern as `tools/` for DAST.

pub mod bandit;
pub mod brakeman;
pub mod cargo_audit;
pub mod cargo_deny;
pub mod checkov;
pub mod dockle;
pub mod eslint_security;
pub mod gitleaks;
pub mod gosec;
pub mod grype;
pub mod hadolint;
pub mod kics;
pub mod kubescape;
pub mod osv_scanner;
pub mod phpstan;
pub mod scoutsuite;
pub mod semgrep;
pub mod slither;
pub mod snyk_code;
pub mod snyk_test;
pub mod tflint;

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
        Box::new(hadolint::HadolintModule),
        Box::new(eslint_security::EslintSecurityModule),
        Box::new(phpstan::PhpstanModule),
        Box::new(snyk_test::SnykTestModule),
        Box::new(snyk_code::SnykCodeModule),
        // WORK-113: SAST expansion batch
        Box::new(cargo_audit::CargoAuditModule),
        Box::new(cargo_deny::CargoDenyModule),
        Box::new(tflint::TflintModule),
        Box::new(kics::KicsModule),
        Box::new(slither::SlitherModule),
        Box::new(brakeman::BrakemanModule),
        // WORK-114: container/cloud tool batch
        Box::new(dockle::DockleModule),
        Box::new(kubescape::KubescapeModule),
        Box::new(scoutsuite::ScoutsuiteModule),
    ]
}
