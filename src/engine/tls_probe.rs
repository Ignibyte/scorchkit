//! Shared TLS probe — certificate inspection used by both DAST
//! ([`crate::scanner::ssl`]) and infra ([`crate::infra::tls_probe`]).
//!
//! Extracts the parts that don't depend on "is this an HTTPS URL or an
//! IP + port?" so DAST and infra can both analyse a peer certificate
//! without duplicating the rustls/x509 glue.
//!
//! ## Probe modes
//!
//! - [`TlsMode::Implicit`] — `TcpStream::connect` → immediate TLS
//!   handshake. Used for HTTPS (443), SMTPS (465), LDAPS (636),
//!   IMAPS (993), POP3S (995).
//! - [`TlsMode::Starttls`] — plain TCP connect, read the service
//!   greeting, send a protocol-specific `STARTTLS`-equivalent command,
//!   read the positive response, then upgrade the same stream to TLS.
//!   Used for SMTP (25/587), IMAP (143), POP3 (110).
//!
//! ## Cert-check helpers
//!
//! [`check_certificate`] runs the same four checks regardless of
//! caller (expiration, self-signed, weak signature, subject/SAN
//! mismatch) and returns a `Vec<Finding>` tagged with the caller's
//! module id. DAST and infra surface consistent findings this way.
//!
//! ## What's out of scope
//!
//! - TLS protocol-version enumeration (forced min/max handshakes).
//! - Cipher-suite enumeration (one handshake per cipher).
//! - RDP-TLS (requires X.224 Connection Request negotiation).

use std::io::{self};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use x509_parser::prelude::*;

use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

/// Maximum bytes we'll read while waiting for a STARTTLS-phase
/// response. 4 KiB is far above any legitimate greeting and protects
/// us from misbehaving peers.
const STARTTLS_READ_BUDGET: usize = 4 * 1024;

/// Time to wait for each network phase (TCP connect, greeting read,
/// STARTTLS response read, TLS handshake).
const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Certificate information extracted from a TLS handshake.
///
/// Mirrors the shape used across the scanner + infra + reporting
/// layers. All fields are owned — the struct survives past the
/// short-lived parse borrow.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Subject Common Name (or `"unknown"` if missing).
    pub subject_cn: String,
    /// Issuer Common Name (or `"unknown"` if missing).
    pub issuer_cn: String,
    /// Not-Before timestamp in RFC 2822 form.
    pub not_before: String,
    /// Not-After timestamp in RFC 2822 form.
    pub not_after: String,
    /// Signed days until expiry — negative when already expired.
    pub days_until_expiry: i64,
    /// Convenience: `days_until_expiry < 0`.
    pub is_expired: bool,
    /// True when subject == issuer.
    pub is_self_signed: bool,
    /// Human-readable signature algorithm (e.g. `"SHA-256 with RSA"`
    /// or `"SHA-1 with RSA (WEAK)"`).
    pub signature_algorithm: String,
    /// Subject Alternative Names (DNS + IP forms).
    pub san_names: Vec<String>,
}

/// How to reach the TLS handshake.
#[derive(Debug, Clone, Copy)]
pub enum TlsMode {
    /// Direct TLS — port is TLS-wrapped from byte zero.
    Implicit,
    /// Plain connect → protocol-specific upgrade → TLS.
    Starttls(StarttlsProtocol),
}

/// Protocols that carry their own STARTTLS-equivalent command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StarttlsProtocol {
    /// SMTP — `EHLO` then `STARTTLS`.
    Smtp,
    /// IMAP — `a001 STARTTLS`.
    Imap,
    /// POP3 — `STLS`.
    Pop3,
}

/// Probe a host/port for a TLS certificate.
///
/// Returns the parsed [`CertInfo`] on success, or a human-readable
/// error string on any failure (TCP refused, STARTTLS rejected, TLS
/// handshake failed, unparseable cert). The caller surfaces the
/// error as a finding — the probe itself never panics.
///
/// The total wall-clock bound is roughly
/// `4 * DEFAULT_PHASE_TIMEOUT` (connect + greeting + STARTTLS
/// response + handshake).
///
/// # Errors
///
/// Returns an `Err(String)` describing the failure phase.
pub async fn probe_tls(
    host: &str,
    port: u16,
    mode: TlsMode,
) -> std::result::Result<CertInfo, String> {
    let addr = format!("{host}:{port}");
    let tcp = timeout(DEFAULT_PHASE_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("tcp connect to {addr} timed out"))?
        .map_err(|e| format!("tcp connect to {addr} failed: {e}"))?;

    let tcp = match mode {
        TlsMode::Implicit => tcp,
        TlsMode::Starttls(protocol) => run_starttls_preamble(tcp, protocol)
            .await
            .map_err(|e| format!("STARTTLS preamble failed ({protocol:?}): {e}"))?,
    };

    // Install a default crypto provider lazily; `install_default`
    // returns `Err` if one is already set — safe to ignore.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls_stream = timeout(DEFAULT_PHASE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("TLS handshake with {addr} timed out"))?
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let (_, server_conn) = tls_stream.get_ref();
    let certs =
        server_conn.peer_certificates().ok_or_else(|| "no peer certificates".to_string())?;
    if certs.is_empty() {
        return Err("empty certificate chain".to_string());
    }
    parse_certificate(certs[0].as_ref())
}

/// Drive the STARTTLS-equivalent command dance for the given
/// protocol, returning the same `TcpStream` ready for TLS upgrade.
async fn run_starttls_preamble(
    mut tcp: TcpStream,
    protocol: StarttlsProtocol,
) -> io::Result<TcpStream> {
    // Read initial greeting.
    read_line_with_budget(&mut tcp).await?;

    match protocol {
        StarttlsProtocol::Smtp => {
            tcp.write_all(b"EHLO scorchkit\r\n").await?;
            // SMTP EHLO response is multi-line: every line but the
            // last has `-` after the code, last has a space. Read
            // until we see the single-space terminator.
            read_smtp_multiline(&mut tcp).await?;
            tcp.write_all(b"STARTTLS\r\n").await?;
            let resp = read_line_with_budget(&mut tcp).await?;
            if !resp.starts_with(b"220") {
                return Err(io::Error::other(format!(
                    "SMTP server rejected STARTTLS: {}",
                    String::from_utf8_lossy(&resp).trim_end()
                )));
            }
        }
        StarttlsProtocol::Imap => {
            tcp.write_all(b"a001 STARTTLS\r\n").await?;
            let resp = read_line_with_budget(&mut tcp).await?;
            if !resp.starts_with(b"a001 OK") {
                return Err(io::Error::other(format!(
                    "IMAP server rejected STARTTLS: {}",
                    String::from_utf8_lossy(&resp).trim_end()
                )));
            }
        }
        StarttlsProtocol::Pop3 => {
            tcp.write_all(b"STLS\r\n").await?;
            let resp = read_line_with_budget(&mut tcp).await?;
            if !resp.starts_with(b"+OK") {
                return Err(io::Error::other(format!(
                    "POP3 server rejected STLS: {}",
                    String::from_utf8_lossy(&resp).trim_end()
                )));
            }
        }
    }
    Ok(tcp)
}

/// Read until `\n`, capped at [`STARTTLS_READ_BUDGET`] and
/// [`DEFAULT_PHASE_TIMEOUT`]. Returns the line bytes including the
/// terminating newline.
async fn read_line_with_budget(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut buf = [0u8; 1];
    loop {
        let read = timeout(DEFAULT_PHASE_TIMEOUT, tcp.read(&mut buf)).await.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "timed out reading STARTTLS phase")
        })??;
        if read == 0 {
            return Err(io::Error::other("peer closed before newline"));
        }
        out.push(buf[0]);
        if buf[0] == b'\n' {
            return Ok(out);
        }
        if out.len() >= STARTTLS_READ_BUDGET {
            return Err(io::Error::other("STARTTLS response exceeded read budget"));
        }
    }
}

/// Read an SMTP multi-line response until we see a line whose 4th
/// character is a space (final line per RFC 5321 §4.2).
async fn read_smtp_multiline(tcp: &mut TcpStream) -> io::Result<()> {
    loop {
        let line = read_line_with_budget(tcp).await?;
        // RFC 5321: `220-foo` continues; `220 foo` terminates.
        if line.len() >= 4 && line[3] == b' ' {
            return Ok(());
        }
        if line.len() < 4 {
            return Err(io::Error::other("SMTP line shorter than 4 bytes"));
        }
    }
}

/// Parse a DER-encoded certificate into a [`CertInfo`].
///
/// # Errors
///
/// Returns an error string when the DER is malformed or missing
/// required fields.
pub fn parse_certificate(cert_der: &[u8]) -> std::result::Result<CertInfo, String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse certificate: {e}"))?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let mut san_names = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => san_names.push((*dns).to_string()),
                GeneralName::IPAddress(ip) => san_names.push(format!("{ip:?}")),
                _ => {}
            }
        }
    }

    let not_before =
        cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "unknown".to_string());
    let not_after =
        cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "unknown".to_string());

    let now = chrono::Utc::now();
    let expiry_epoch = cert.validity().not_after.timestamp();
    let now_epoch = now.timestamp();
    let days_until_expiry = (expiry_epoch - now_epoch) / 86400;
    let is_expired = days_until_expiry < 0;
    let is_self_signed = cert.subject() == cert.issuer();

    let oid = cert.signature_algorithm.algorithm.to_string();
    let signature_algorithm = map_signature_oid(&oid).to_string();

    Ok(CertInfo {
        subject_cn,
        issuer_cn,
        not_before,
        not_after,
        days_until_expiry,
        is_expired,
        is_self_signed,
        signature_algorithm,
        san_names,
    })
}

/// Map a signature-algorithm OID string to a human-readable label.
/// Appends `(WEAK)` for algorithms `ScorchKit` flags as insecure.
fn map_signature_oid(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA (WEAK)",
        "1.2.840.113549.1.1.4" => "MD5 with RSA (WEAK)",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "1.3.101.112" => "Ed25519",
        _ => "unknown",
    }
}

/// Run every standard certificate check and return accumulated findings.
///
/// `module_id` becomes the `Finding.module_id` so callers surface
/// consistent but caller-tagged results (e.g. `"ssl"` for DAST,
/// `"tls_infra"` for infra). `affected` is the affected-resource
/// string (URL, `host:port`, etc.). `hostname` is the domain we
/// expected the cert to cover.
#[must_use]
pub fn check_certificate(
    cert: &CertInfo,
    module_id: &'static str,
    hostname: &str,
    affected: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    check_expiration(cert, module_id, affected, &mut findings);
    check_self_signed(cert, module_id, affected, &mut findings);
    check_weak_signature(cert, module_id, affected, &mut findings);
    check_subject_mismatch(cert, module_id, hostname, affected, &mut findings);
    findings
}

fn check_expiration(
    cert: &CertInfo,
    module_id: &'static str,
    affected: &str,
    findings: &mut Vec<Finding>,
) {
    if cert.is_expired {
        findings.push(
            Finding::new(
                module_id,
                Severity::Critical,
                "TLS Certificate Expired",
                format!("The TLS certificate expired. Not After: {}", cert.not_after),
                affected,
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
                module_id,
                Severity::Medium,
                "TLS Certificate Expiring Soon",
                format!(
                    "The TLS certificate expires in {} days ({})",
                    cert.days_until_expiry, cert.not_after
                ),
                affected,
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

fn check_self_signed(
    cert: &CertInfo,
    module_id: &'static str,
    affected: &str,
    findings: &mut Vec<Finding>,
) {
    if cert.is_self_signed {
        findings.push(
            Finding::new(
                module_id,
                Severity::High,
                "Self-Signed TLS Certificate",
                "The server uses a self-signed certificate. Clients will show \
                 security warnings and users may be vulnerable to MITM attacks.",
                affected,
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

fn check_weak_signature(
    cert: &CertInfo,
    module_id: &'static str,
    affected: &str,
    findings: &mut Vec<Finding>,
) {
    if cert.signature_algorithm.contains("WEAK") {
        findings.push(
            Finding::new(
                module_id,
                Severity::High,
                "Weak Certificate Signature Algorithm",
                format!(
                    "The certificate uses a weak signature algorithm: {}. \
                     This is vulnerable to collision attacks.",
                    cert.signature_algorithm
                ),
                affected,
            )
            .with_evidence(format!("Signature Algorithm: {}", cert.signature_algorithm))
            .with_remediation("Reissue the certificate with SHA-256 or stronger")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(328)
            .with_confidence(0.9),
        );
    }
}

fn check_subject_mismatch(
    cert: &CertInfo,
    module_id: &'static str,
    hostname: &str,
    affected: &str,
    findings: &mut Vec<Finding>,
) {
    let hostname_lower = hostname.to_lowercase();
    let cn_matches = cert.subject_cn.to_lowercase() == hostname_lower
        || matches_wildcard(&cert.subject_cn.to_lowercase(), &hostname_lower);
    let san_matches = cert.san_names.iter().any(|san| {
        let san_lower = san.to_lowercase();
        san_lower == hostname_lower || matches_wildcard(&san_lower, &hostname_lower)
    });
    if !cn_matches && !san_matches && cert.subject_cn != "unknown" {
        let san_list =
            if cert.san_names.is_empty() { "none".to_string() } else { cert.san_names.join(", ") };
        findings.push(
            Finding::new(
                module_id,
                Severity::High,
                "Certificate Subject Mismatch",
                format!(
                    "The certificate does not match host '{hostname}'. CN='{}', SANs=[{san_list}]",
                    cert.subject_cn,
                ),
                affected,
            )
            .with_evidence(format!("Host: {hostname} | CN: {} | SANs: {san_list}", cert.subject_cn))
            .with_remediation("Obtain a certificate that includes this host name")
            .with_owasp("A02:2021 Cryptographic Failures")
            .with_cwe(295)
            .with_confidence(0.9),
        );
    }
}

fn matches_wildcard(cert_name: &str, host: &str) -> bool {
    cert_name.strip_prefix("*.").is_some_and(|suffix| {
        host.ends_with(suffix) && host.matches('.').count() == suffix.matches('.').count() + 1
    })
}

#[cfg(test)]
mod tests {
    //! Pure-function coverage for [`check_certificate`] and the
    //! STARTTLS preamble wire format. The full TLS handshake path
    //! exercises real network I/O and lives in caller-side tests
    //! (scanner/ssl.rs and infra/tls_probe.rs).

    use super::*;
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    fn fixture_cert(
        is_expired: bool,
        is_self_signed: bool,
        algo: &str,
        san: Vec<&str>,
    ) -> CertInfo {
        CertInfo {
            subject_cn: "example.com".to_string(),
            issuer_cn: if is_self_signed {
                "example.com".to_string()
            } else {
                "Test CA".to_string()
            },
            not_before: "2020-01-01".to_string(),
            not_after: if is_expired { "2021-01-01".to_string() } else { "2099-01-01".to_string() },
            days_until_expiry: if is_expired { -365 } else { 365 },
            is_expired,
            is_self_signed,
            signature_algorithm: algo.to_string(),
            san_names: san.into_iter().map(String::from).collect(),
        }
    }

    /// A valid, non-expired, trusted cert produces zero findings when
    /// the hostname matches.
    #[test]
    fn check_certificate_clean_cert_no_findings() {
        let cert = fixture_cert(false, false, "SHA-256 with RSA", vec!["example.com"]);
        let findings = check_certificate(&cert, "tls_infra", "example.com", "example.com:443");
        assert!(findings.is_empty());
    }

    /// Expired cert yields a Critical finding with module_id = caller.
    #[test]
    fn check_certificate_expired_tagged_with_caller_module_id() {
        let cert = fixture_cert(true, false, "SHA-256 with RSA", vec!["example.com"]);
        let findings = check_certificate(&cert, "tls_infra", "example.com", "example.com:443");
        let expired = findings.iter().find(|f| f.title.contains("Expired")).expect("expired");
        assert_eq!(expired.severity, Severity::Critical);
        assert_eq!(expired.module_id, "tls_infra");
    }

    /// Self-signed yields a High finding.
    #[test]
    fn check_certificate_self_signed_high() {
        let cert = fixture_cert(false, true, "SHA-256 with RSA", vec!["example.com"]);
        let findings = check_certificate(&cert, "ssl", "example.com", "https://example.com");
        let f = findings.iter().find(|f| f.title.contains("Self-Signed")).expect("self-signed");
        assert_eq!(f.severity, Severity::High);
    }

    /// Weak signature (SHA-1, MD5) yields a High finding with CWE-328.
    #[test]
    fn check_certificate_weak_signature_high() {
        let cert = fixture_cert(false, false, "SHA-1 with RSA (WEAK)", vec!["example.com"]);
        let findings = check_certificate(&cert, "ssl", "example.com", "https://example.com");
        let f = findings.iter().find(|f| f.title.contains("Weak")).expect("weak");
        assert_eq!(f.severity, Severity::High);
    }

    /// A cert issued for a different hostname (no matching CN or SAN)
    /// yields a High mismatch finding.
    #[test]
    fn check_certificate_subject_mismatch_high() {
        // Override subject_cn so neither CN nor SAN covers "target.test".
        let mut cert = fixture_cert(false, false, "SHA-256 with RSA", vec!["other.test"]);
        cert.subject_cn = "unrelated.host".to_string();
        let findings = check_certificate(&cert, "ssl", "target.test", "https://target.test");
        let f = findings.iter().find(|f| f.title.contains("Mismatch")).expect("mismatch");
        assert_eq!(f.severity, Severity::High);
    }

    /// Wildcard cert `*.example.com` matches `www.example.com` but
    /// NOT `a.b.example.com` (per RFC 6125).
    #[test]
    fn check_certificate_wildcard_san_single_level_only() {
        let cert = fixture_cert(false, false, "SHA-256 with RSA", vec!["*.example.com"]);
        // www.example.com — should match, so no mismatch finding.
        let findings =
            check_certificate(&cert, "ssl", "www.example.com", "https://www.example.com");
        assert!(findings.iter().all(|f| !f.title.contains("Mismatch")));
        // a.b.example.com — should NOT match, mismatch expected.
        let findings =
            check_certificate(&cert, "ssl", "a.b.example.com", "https://a.b.example.com");
        assert!(findings.iter().any(|f| f.title.contains("Mismatch")));
    }

    /// An unknown signature OID is surfaced literally, without the
    /// `(WEAK)` marker that triggers the weak-signature finding.
    #[test]
    fn map_signature_oid_unknown_is_not_weak() {
        let name = map_signature_oid("1.2.3.4.5.666");
        assert_eq!(name, "unknown");
        assert!(!name.contains("WEAK"));
    }

    /// Ephemeral-listener integration test: scripts an SMTP greeting
    /// + EHLO response + STARTTLS 220, asserts our client sends the
    /// right command bytes. Proves the preamble wire format without
    /// needing a real TLS server.
    #[tokio::test]
    async fn starttls_preamble_client_sends_starttls_smtp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"220 smtp.test ESMTP ready\r\n").await.expect("w1");
            let mut buf = vec![0u8; 256];
            let n = sock.read(&mut buf).await.expect("r1");
            let got = std::str::from_utf8(&buf[..n]).expect("utf8");
            assert!(got.starts_with("EHLO "), "expected EHLO, got {got:?}");
            sock.write_all(b"250-smtp.test\r\n250 STARTTLS\r\n").await.expect("w2");
            let n = sock.read(&mut buf).await.expect("r2");
            let got = std::str::from_utf8(&buf[..n]).expect("utf8");
            assert_eq!(got, "STARTTLS\r\n", "client must send bare STARTTLS");
            // Reply with 220 so the client thinks it can upgrade.
            sock.write_all(b"220 ready for TLS\r\n").await.expect("w3");
            // Close — client will then attempt the real TLS handshake
            // which will fail; that's fine for *this* test's purpose.
        });

        // Call into our private helper directly via `run_starttls_preamble`.
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        let _ = run_starttls_preamble(tcp, StarttlsProtocol::Smtp).await.expect("preamble");
        // Don't attempt TLS upgrade here — the test server is plain TCP.

        server.await.expect("server task");
    }

    /// POP3 preamble sends exactly `STLS\r\n` and needs a `+OK` reply.
    #[tokio::test]
    async fn starttls_preamble_client_sends_stls_pop3() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"+OK POP3 ready\r\n").await.expect("w1");
            let mut buf = vec![0u8; 64];
            let n = sock.read(&mut buf).await.expect("r1");
            assert_eq!(&buf[..n], b"STLS\r\n");
            sock.write_all(b"+OK begin TLS\r\n").await.expect("w2");
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        let _ = run_starttls_preamble(tcp, StarttlsProtocol::Pop3).await.expect("preamble");
        server.await.expect("server task");
    }

    /// IMAP preamble sends a tagged `a001 STARTTLS\r\n` and needs
    /// `a001 OK`.
    #[tokio::test]
    async fn starttls_preamble_client_sends_starttls_imap() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"* OK IMAP ready\r\n").await.expect("w1");
            let mut buf = vec![0u8; 64];
            let n = sock.read(&mut buf).await.expect("r1");
            assert_eq!(&buf[..n], b"a001 STARTTLS\r\n");
            sock.write_all(b"a001 OK Begin TLS\r\n").await.expect("w2");
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        let _ = run_starttls_preamble(tcp, StarttlsProtocol::Imap).await.expect("preamble");
        server.await.expect("server task");
    }
}
