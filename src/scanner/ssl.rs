use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use x509_parser::prelude::*;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

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

        match connect_and_inspect(domain, ctx.target.port).await {
            Ok(cert_info) => {
                check_expiration(&cert_info, url, &mut findings);
                check_self_signed(&cert_info, url, &mut findings);
                check_weak_signature(&cert_info, url, &mut findings);
                check_subject_mismatch(&cert_info, domain, url, &mut findings);
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

/// Certificate information extracted from the TLS handshake.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CertInfo {
    subject_cn: String,
    issuer_cn: String,
    not_before: String,
    not_after: String,
    days_until_expiry: i64,
    is_expired: bool,
    is_self_signed: bool,
    signature_algorithm: String,
    san_names: Vec<String>,
}

/// Connect to the target and extract certificate info.
async fn connect_and_inspect(domain: &str, port: u16) -> std::result::Result<CertInfo, String> {
    let addr = format!("{domain}:{port}");

    let tcp_stream =
        TcpStream::connect(&addr).await.map_err(|e| format!("TCP connection failed: {e}"))?;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config =
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let (_, server_conn) = tls_stream.get_ref();

    let certs =
        server_conn.peer_certificates().ok_or_else(|| "no peer certificates".to_string())?;

    if certs.is_empty() {
        return Err("empty certificate chain".to_string());
    }

    let leaf_cert = &certs[0];
    parse_certificate(leaf_cert.as_ref())
}

/// Parse a DER-encoded certificate using x509-parser.
fn parse_certificate(cert_der: &[u8]) -> std::result::Result<CertInfo, String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse certificate: {e}"))?;

    // Extract subject CN
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Extract issuer CN
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Extract SAN names
    let mut san_names = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => san_names.push((*dns).to_string()),
                GeneralName::IPAddress(ip) => {
                    san_names.push(format!("{ip:?}"));
                }
                _ => {}
            }
        }
    }

    // Validity
    let not_before =
        cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "unknown".to_string());
    let not_after =
        cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "unknown".to_string());

    let now = chrono::Utc::now();
    let expiry_epoch = cert.validity().not_after.timestamp();
    let now_epoch = now.timestamp();
    let days_until_expiry = (expiry_epoch - now_epoch) / 86400;
    let is_expired = days_until_expiry < 0;

    // Self-signed check
    let is_self_signed = cert.subject() == cert.issuer();

    // Signature algorithm
    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();

    // Map OID to human-readable name
    let sig_name = match signature_algorithm.as_str() {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA (WEAK)",
        "1.2.840.113549.1.1.4" => "MD5 with RSA (WEAK)",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.3.101.112" => "Ed25519",
        other => other,
    };

    Ok(CertInfo {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        days_until_expiry,
        is_expired,
        is_self_signed,
        signature_algorithm: sig_name.to_string(),
        san_names,
    })
}

fn check_expiration(cert: &CertInfo, url: &str, findings: &mut Vec<Finding>) {
    if cert.is_expired {
        findings.push(
            Finding::new(
                "ssl",
                Severity::Critical,
                "TLS Certificate Expired",
                format!("The TLS certificate expired. Not After: {}", cert.not_after),
                url,
            )
            .with_evidence(format!(
                "Subject: {} | Issuer: {} | Expired: {}",
                cert.subject_cn, cert.issuer_cn, cert.not_after
            ))
            .with_remediation("Renew the TLS certificate immediately")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(295)
            .with_confidence(0.9),
        );
    } else if cert.days_until_expiry < 30 {
        findings.push(
            Finding::new(
                "ssl",
                Severity::Medium,
                "TLS Certificate Expiring Soon",
                format!(
                    "The TLS certificate expires in {} days ({})",
                    cert.days_until_expiry, cert.not_after
                ),
                url,
            )
            .with_evidence(format!(
                "Subject: {} | Expires: {} | Days remaining: {}",
                cert.subject_cn, cert.not_after, cert.days_until_expiry
            ))
            .with_remediation("Renew the TLS certificate before it expires")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_confidence(0.9),
        );
    }
}

fn check_self_signed(cert: &CertInfo, url: &str, findings: &mut Vec<Finding>) {
    if cert.is_self_signed {
        findings.push(
            Finding::new(
                "ssl",
                Severity::High,
                "Self-Signed TLS Certificate",
                "The server uses a self-signed certificate. Browsers will show \
                 security warnings and users may be vulnerable to MITM attacks.",
                url,
            )
            .with_evidence(format!(
                "Subject: {} | Issuer: {} (self-signed)",
                cert.subject_cn, cert.issuer_cn
            ))
            .with_remediation(
                "Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt)",
            )
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(295)
            .with_confidence(0.9),
        );
    }
}

fn check_weak_signature(cert: &CertInfo, url: &str, findings: &mut Vec<Finding>) {
    if cert.signature_algorithm.contains("WEAK") {
        findings.push(
            Finding::new(
                "ssl",
                Severity::High,
                "Weak Certificate Signature Algorithm",
                format!(
                    "The certificate uses a weak signature algorithm: {}. \
                     This is vulnerable to collision attacks.",
                    cert.signature_algorithm
                ),
                url,
            )
            .with_evidence(format!("Signature Algorithm: {}", cert.signature_algorithm))
            .with_remediation("Reissue the certificate with SHA-256 or stronger")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(328)
            .with_confidence(0.9),
        );
    }
}

fn check_subject_mismatch(cert: &CertInfo, domain: &str, url: &str, findings: &mut Vec<Finding>) {
    let domain_lower = domain.to_lowercase();

    // Check CN match
    let cn_matches = cert.subject_cn.to_lowercase() == domain_lower
        || matches_wildcard(&cert.subject_cn.to_lowercase(), &domain_lower);

    // Check SAN match
    let san_matches = cert.san_names.iter().any(|san| {
        let san_lower = san.to_lowercase();
        san_lower == domain_lower || matches_wildcard(&san_lower, &domain_lower)
    });

    if !cn_matches && !san_matches && cert.subject_cn != "unknown" {
        let san_list =
            if cert.san_names.is_empty() { "none".to_string() } else { cert.san_names.join(", ") };

        findings.push(
            Finding::new(
                "ssl",
                Severity::High,
                "Certificate Subject Mismatch",
                format!(
                    "The certificate does not match domain '{}'. CN='{}', SANs=[{}]",
                    domain, cert.subject_cn, san_list
                ),
                url,
            )
            .with_evidence(format!(
                "Domain: {} | CN: {} | SANs: {}",
                domain, cert.subject_cn, san_list
            ))
            .with_remediation("Obtain a certificate that includes this domain name")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(295)
            .with_confidence(0.9),
        );
    }
}

fn matches_wildcard(cert_name: &str, domain: &str) -> bool {
    cert_name.strip_prefix("*.").is_some_and(|suffix| {
        domain.ends_with(suffix) && domain.matches('.').count() == suffix.matches('.').count() + 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for the TLS/SSL analysis module's pure helper functions.

    /// Verify that `matches_wildcard` correctly matches single-level wildcard certificates
    /// and rejects multi-level, bare-domain, and non-matching domains.
    #[test]
    fn test_matches_wildcard() {
        // Arrange & Assert: valid single-level wildcard matches
        assert!(matches_wildcard("*.example.com", "www.example.com"));
        assert!(matches_wildcard("*.example.com", "api.example.com"));

        // Should not match the bare domain (no subdomain prefix)
        assert!(!matches_wildcard("*.example.com", "example.com"));

        // Should not match multi-level subdomains
        assert!(!matches_wildcard("*.example.com", "a.b.example.com"));

        // Non-wildcard cert should never match via this function
        assert!(!matches_wildcard("www.example.com", "www.example.com"));

        // Completely different domain
        assert!(!matches_wildcard("*.example.com", "www.other.com"));
    }

    /// Verify that `check_expiration` produces a Critical finding for expired certificates
    /// and a Medium finding for certificates expiring within 30 days, but no finding
    /// for certificates with ample remaining validity.
    #[test]
    fn test_check_expiration_findings() {
        // Arrange: expired cert
        let expired = CertInfo {
            subject_cn: "expired.example.com".to_string(),
            issuer_cn: "Test CA".to_string(),
            not_before: "2020-01-01".to_string(),
            not_after: "2021-01-01".to_string(),
            days_until_expiry: -365,
            is_expired: true,
            is_self_signed: false,
            signature_algorithm: "SHA-256 with RSA".to_string(),
            san_names: vec![],
        };
        let mut findings = Vec::new();

        // Act
        check_expiration(&expired, "https://expired.example.com", &mut findings);

        // Assert
        assert_eq!(findings.len(), 1, "Expected one finding for expired cert");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Expired"));

        // Arrange: expiring in 15 days
        let soon = CertInfo { days_until_expiry: 15, is_expired: false, ..expired };
        let mut soon_findings = Vec::new();

        // Act
        check_expiration(&soon, "https://soon.example.com", &mut soon_findings);

        // Assert
        assert_eq!(soon_findings.len(), 1, "Expected one finding for cert expiring soon");
        assert_eq!(soon_findings[0].severity, Severity::Medium);

        // Arrange: valid cert with 365 days remaining
        let valid = CertInfo {
            subject_cn: "valid.example.com".to_string(),
            issuer_cn: "Real CA".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2026-01-01".to_string(),
            days_until_expiry: 365,
            is_expired: false,
            is_self_signed: false,
            signature_algorithm: "SHA-256 with RSA".to_string(),
            san_names: vec![],
        };
        let mut valid_findings = Vec::new();

        // Act
        check_expiration(&valid, "https://valid.example.com", &mut valid_findings);

        // Assert
        assert!(valid_findings.is_empty(), "No finding expected for valid cert");
    }

    /// Verify that `check_weak_signature` flags certificates using weak algorithms
    /// (SHA-1, MD5) and passes those using strong algorithms (SHA-256).
    #[test]
    fn test_check_weak_signature() {
        // Arrange: weak signature
        let weak = CertInfo {
            subject_cn: "weak.example.com".to_string(),
            issuer_cn: "Test CA".to_string(),
            not_before: "2024-01-01".to_string(),
            not_after: "2026-01-01".to_string(),
            days_until_expiry: 365,
            is_expired: false,
            is_self_signed: false,
            signature_algorithm: "SHA-1 with RSA (WEAK)".to_string(),
            san_names: vec![],
        };
        let mut findings = Vec::new();

        // Act
        check_weak_signature(&weak, "https://weak.example.com", &mut findings);

        // Assert
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Weak"));

        // Arrange: strong signature
        let strong = CertInfo { signature_algorithm: "SHA-256 with RSA".to_string(), ..weak };
        let mut strong_findings = Vec::new();

        // Act
        check_weak_signature(&strong, "https://strong.example.com", &mut strong_findings);

        // Assert
        assert!(strong_findings.is_empty(), "No finding expected for SHA-256");
    }
}
