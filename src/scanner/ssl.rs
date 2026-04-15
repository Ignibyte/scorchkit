use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::engine::tls_probe::{check_certificate, probe_tls, TlsMode};

/// Analyzes TLS/SSL configuration of the target.
#[derive(Debug)]
pub struct SslModule;

#[async_trait]
impl ScanModule for SslModule {
    fn name(&self) -> &'static str {
        "TLS/SSL Analysis"
    }

    fn id(&self) -> &'static str {
        "ssl"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Analyze TLS/SSL certificate and configuration"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        if !ctx.target.is_https {
            return Ok(vec![Finding::new(
                "ssl",
                Severity::High,
                "No TLS/SSL Encryption",
                "The target is served over plain HTTP without TLS encryption. \
                 All traffic is transmitted in cleartext.",
                ctx.target.url.as_str(),
            )
            .with_remediation("Enable HTTPS with a valid TLS certificate")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(319)
            .with_confidence(0.9)]);
        }

        let domain = ctx.target.domain.as_deref().ok_or_else(|| ScorchError::InvalidTarget {
            target: ctx.target.raw.clone(),
            reason: "no domain for TLS check".to_string(),
        })?;

        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        match probe_tls(domain, ctx.target.port, TlsMode::Implicit).await {
            Ok(cert_info) => {
                findings.extend(check_certificate(&cert_info, "ssl", domain, url));
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "ssl",
                        Severity::High,
                        "TLS Connection Failed",
                        format!("Could not establish a TLS connection: {e}"),
                        url,
                    )
                    .with_owasp("A02:2021 Cryptographic Failures")
                    .with_confidence(0.9),
                );
            }
        }

        Ok(findings)
    }
}

// Cert-inspection helpers live in `crate::engine::tls_probe` so the
// DAST path here and the infra `TlsInfraModule` share one
// implementation. See that module for [`CertInfo`], [`probe_tls`],
// [`check_certificate`], and the STARTTLS preamble machinery.
