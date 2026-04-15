//! TLS protocol-version + cipher-suite enumeration.
//!
//! Complements [`crate::engine::tls_probe`] (which inspects *one* peer
//! certificate after a successful handshake). This module answers a
//! different question: **which TLS versions and cipher suites does the
//! server accept at all?** Use [`probe_tls`](crate::engine::tls_probe::probe_tls)
//! for certificate findings, [`probe_tls_version`] / [`probe_tls_cipher`]
//! for hardening findings.
//!
//! ## Approach
//!
//! - **Modern versions (TLS1.2, TLS1.3):** rustls-based probe. Build a
//!   `ClientConfig` scoped to one protocol version, install a
//!   deliberately-dangerous cert verifier, and attempt a handshake. We
//!   classify based on the rustls error *text* — peer-version-related
//!   alerts mean Rejected, any other outcome (even a cert-validation
//!   error) means we got past the version negotiation, so Accepted.
//! - **Legacy versions (`SSLv3`, `TLSv1.0`, `TLSv1.1`) + all cipher probes:**
//!   raw-socket `ClientHello`. rustls 0.23 does not implement pre-TLS1.2
//!   and does not implement weak ciphers (RC4, 3DES, EXPORT, NULL, anon)
//!   — both detection paths require hand-crafted `ClientHello` bytes. We
//!   send one, read the server's first record, and classify the response
//!   as [`ProbeOutcome::Accepted`], [`ProbeOutcome::Rejected`], or
//!   [`ProbeOutcome::Unknown`].
//!
//! ## What's out of scope
//!
//! - **TLS1.3 cipher enumeration.** RFC 8446 defines only 5 AEAD ciphers,
//!   all modern; enumeration adds no security value.
//! - **Full cipher-strength scoring.** We classify suites as `Ok`,
//!   `Legacy`, `Weak`, or `Critical`. Finer gradations (per-primitive
//!   scoring) belong to a tool like testssl.sh.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::engine::severity::Severity;
use crate::engine::tls_probe::{run_starttls_preamble, TlsMode};

/// Time budget per network phase (TCP connect, STARTTLS read, hello
/// send, first-record read). Kept in sync with
/// [`crate::engine::tls_probe`].
const PHASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Soft upper bound on bytes we read while classifying the server's
/// first record. We only need the first ~6 bytes; the extra budget is
/// insurance.
const RESPONSE_READ_BUDGET: usize = 512;

// =============================================================
// TlsVersionId
// =============================================================

/// TLS protocol version identifier.
///
/// Wire values match the `ProtocolVersion` enum in TLS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersionId {
    /// SSL 3.0 (`0x0300`). RFC 6101; historically vulnerable (POODLE).
    Ssl30,
    /// TLS 1.0 (`0x0301`). RFC 2246; deprecated by RFC 8996.
    Tls10,
    /// TLS 1.1 (`0x0302`). RFC 4346; deprecated by RFC 8996.
    Tls11,
    /// TLS 1.2 (`0x0303`). RFC 5246; baseline modern.
    Tls12,
    /// TLS 1.3 (`0x0304`). RFC 8446; current best practice.
    Tls13,
}

impl TlsVersionId {
    /// Wire-format 2-byte version ID used in TLS record + `ClientHello` fields.
    #[must_use]
    pub const fn wire(self) -> u16 {
        match self {
            Self::Ssl30 => 0x0300,
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    /// IETF-style label for reports and findings.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssl30 => "SSLv3",
            Self::Tls10 => "TLSv1.0",
            Self::Tls11 => "TLSv1.1",
            Self::Tls12 => "TLSv1.2",
            Self::Tls13 => "TLSv1.3",
        }
    }

    /// Severity tier to raise when the server *accepts* this version.
    ///
    /// Returns `None` for TLSv1.2 and TLSv1.3 — those are expected to
    /// be supported and do not trigger findings on their own.
    #[must_use]
    pub const fn severity_when_accepted(self) -> Option<Severity> {
        match self {
            Self::Ssl30 | Self::Tls10 => Some(Severity::Critical),
            Self::Tls11 => Some(Severity::High),
            Self::Tls12 | Self::Tls13 => None,
        }
    }

    /// Whether this version uses the raw-socket `ClientHello` path
    /// (returns `true` for `SSLv3` / `TLSv1.0` / `TLSv1.1`, `false` for
    /// `TLSv1.2` / `TLSv1.3` which go through rustls).
    #[must_use]
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::Ssl30 | Self::Tls10 | Self::Tls11)
    }
}

impl fmt::Display for TlsVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Every version we enumerate by default.
pub const ALL_PROBED_VERSIONS: &[TlsVersionId] = &[
    TlsVersionId::Ssl30,
    TlsVersionId::Tls10,
    TlsVersionId::Tls11,
    TlsVersionId::Tls12,
    TlsVersionId::Tls13,
];

// =============================================================
// CipherSuiteId + CipherWeakness
// =============================================================

/// A TLS cipher suite identified by its 2-byte IANA registry ID.
///
/// See the [IANA TLS Cipher Suites registry][1] for the canonical list.
///
/// [1]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuiteId(pub u16);

/// Weakness classification for a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherWeakness {
    /// Modern AEAD suite (AES-GCM, ChaCha20-Poly1305). No finding raised.
    Ok,
    /// Legacy CBC mode — not broken but deprecated. Medium severity.
    Legacy,
    /// RC4 / 3DES / MD5 MAC. High severity.
    Weak,
    /// NULL / anonymous DH / EXPORT-grade. Critical severity.
    Critical,
}

impl CipherWeakness {
    /// Severity tier to raise when the server accepts a suite of this
    /// weakness. Returns `None` for [`CipherWeakness::Ok`].
    #[must_use]
    pub const fn severity(self) -> Option<Severity> {
        match self {
            Self::Critical => Some(Severity::Critical),
            Self::Weak => Some(Severity::High),
            Self::Legacy => Some(Severity::Medium),
            Self::Ok => None,
        }
    }
}

impl CipherSuiteId {
    /// Canonical IANA name, or `"Unknown (0xNNNN)"` for IDs not in our
    /// catalog.
    #[must_use]
    pub fn name(self) -> String {
        match self.0 {
            0x0000 => "TLS_NULL_WITH_NULL_NULL".into(),
            0x0001 => "TLS_RSA_WITH_NULL_MD5".into(),
            0x0002 => "TLS_RSA_WITH_NULL_SHA".into(),
            0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5".into(),
            0x0004 => "TLS_RSA_WITH_RC4_128_MD5".into(),
            0x0005 => "TLS_RSA_WITH_RC4_128_SHA".into(),
            0x0006 => "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5".into(),
            0x0008 => "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA".into(),
            0x0009 => "TLS_RSA_WITH_DES_CBC_SHA".into(),
            0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
            0x0011 => "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA".into(),
            0x0012 => "TLS_DHE_DSS_WITH_DES_CBC_SHA".into(),
            0x0013 => "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA".into(),
            0x0014 => "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA".into(),
            0x0015 => "TLS_DHE_RSA_WITH_DES_CBC_SHA".into(),
            0x0016 => "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA".into(),
            0x0017 => "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5".into(),
            0x0018 => "TLS_DH_anon_WITH_RC4_128_MD5".into(),
            0x0019 => "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA".into(),
            0x001A => "TLS_DH_anon_WITH_DES_CBC_SHA".into(),
            0x001B => "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA".into(),
            0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
            0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA".into(),
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
            0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA".into(),
            0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256".into(),
            0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256".into(),
            0x006B => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256".into(),
            0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
            0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384".into(),
            0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".into(),
            0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
            0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".into(),
            0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
            0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
            0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
            0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
            0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
            other => format!("Unknown (0x{other:04X})"),
        }
    }

    /// Classify this cipher's weakness for finding-severity purposes.
    #[must_use]
    pub const fn weakness(self) -> CipherWeakness {
        match self.0 {
            // NULL / EXPORT / anonymous / DES — Critical
            // (DES-CBC variants 0x0009/0x0012/0x0015 included: 56-bit effective key)
            0x0000 | 0x0001 | 0x0002 | 0x0003 | 0x0006 | 0x0008 | 0x0009 | 0x0011 | 0x0012
            | 0x0014 | 0x0015 | 0x0017 | 0x0018 | 0x0019 | 0x001A | 0x001B => {
                CipherWeakness::Critical
            }
            // RC4 / 3DES — Weak
            0x0004 | 0x0005 | 0x000A | 0x0013 | 0x0016 => CipherWeakness::Weak,
            // CBC-mode AES — Legacy
            0x002F | 0x0033 | 0x0035 | 0x0039 | 0x003C | 0x003D | 0x006B | 0xC013 | 0xC014 => {
                CipherWeakness::Legacy
            }
            // GCM / ChaCha20 AEAD — Ok
            0x009C | 0x009D | 0x009E | 0x009F | 0xC02B | 0xC02C | 0xC02F | 0xC030 | 0xCCA8
            | 0xCCA9 => CipherWeakness::Ok,
            // Unknown — conservatively Legacy (don't raise Critical for IDs we can't classify)
            _ => CipherWeakness::Legacy,
        }
    }
}

impl fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04X})", self.name(), self.0)
    }
}

/// Cipher suites worth probing.
///
/// Every known Critical / Weak / Legacy entry from our catalog, plus a
/// small set of Ok baselines so reports can confirm "we checked, and
/// the server does offer modern AEAD too."
///
/// This list is a contribution-friendly seam. PRs welcome to add
/// additional IDs.
#[must_use]
pub const fn weak_cipher_catalog() -> &'static [CipherSuiteId] {
    const CATALOG: &[CipherSuiteId] = &[
        // Critical
        CipherSuiteId(0x0000),
        CipherSuiteId(0x0001),
        CipherSuiteId(0x0002),
        CipherSuiteId(0x0003),
        CipherSuiteId(0x0006),
        CipherSuiteId(0x0008),
        CipherSuiteId(0x0009),
        CipherSuiteId(0x0011),
        CipherSuiteId(0x0012),
        CipherSuiteId(0x0014),
        CipherSuiteId(0x0015),
        CipherSuiteId(0x0017),
        CipherSuiteId(0x0018),
        CipherSuiteId(0x0019),
        CipherSuiteId(0x001A),
        CipherSuiteId(0x001B),
        // Weak
        CipherSuiteId(0x0004),
        CipherSuiteId(0x0005),
        CipherSuiteId(0x000A),
        CipherSuiteId(0x0013),
        CipherSuiteId(0x0016),
        // Legacy (CBC)
        CipherSuiteId(0x002F),
        CipherSuiteId(0x0033),
        CipherSuiteId(0x0035),
        CipherSuiteId(0x0039),
        CipherSuiteId(0x003C),
        CipherSuiteId(0x003D),
        CipherSuiteId(0x006B),
        CipherSuiteId(0xC013),
        CipherSuiteId(0xC014),
        // Ok baselines (AEAD)
        CipherSuiteId(0x009C),
        CipherSuiteId(0x009D),
        CipherSuiteId(0xC02B),
        CipherSuiteId(0xC02C),
        CipherSuiteId(0xC02F),
        CipherSuiteId(0xC030),
        CipherSuiteId(0xCCA8),
        CipherSuiteId(0xCCA9),
    ];
    CATALOG
}

// =============================================================
// ProbeOutcome
// =============================================================

/// Outcome of a single version- or cipher-acceptance probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Server responded with a `ServerHello` — it accepts this version
    /// or cipher.
    Accepted,
    /// Server responded with a TLS alert rejecting the handshake, or
    /// rustls returned a peer-version-related error.
    Rejected,
    /// Network-level error, timeout, TCP close without an alert, or
    /// otherwise indeterminate. Information-only; do not surface as a
    /// finding.
    Unknown,
}

// =============================================================
// ClientHello crafting + response classification
// =============================================================

/// Build a minimal TLS `ClientHello` record for legacy-version + cipher
/// probes.
///
/// Layout (see RFC 5246 §7.4.1.2):
///
/// ```text
/// TLS record layer (5 bytes):
///   content_type = 0x16 (handshake)
///   record_version = 0x0301 (TLSv1.0; legacy servers don't care)
///   length
/// Handshake header (4 bytes):
///   msg_type = 0x01 (client_hello)
///   length (u24, big-endian)
/// ClientHello body:
///   client_version (2 bytes) = probe version
///   random (32 bytes)
///   session_id (1 byte len + 0)
///   cipher_suites (2 bytes len + N*2 bytes)
///   compression_methods (1 byte len + 1 byte = null compression)
///   extensions (2 bytes len + bytes):
///     server_name (SNI): type 0x0000, list with one host_name entry
/// ```
#[must_use]
#[allow(clippy::too_many_lines)]
// JUSTIFICATION: TLS ClientHello wire format is inherently monolithic.
// Splitting across helpers fragments the spec-to-code mapping and hurts
// readability for anyone cross-referencing RFC 5246 §7.4.1.2.
pub fn build_client_hello(
    client_version: TlsVersionId,
    ciphers: &[CipherSuiteId],
    sni_hostname: &str,
) -> Vec<u8> {
    // ---- Extensions (built first; length needed for body header). ----
    let mut extensions = Vec::with_capacity(32 + sni_hostname.len());

    // server_name extension
    {
        // extension_type = 0x0000 (server_name)
        extensions.extend_from_slice(&[0x00, 0x00]);
        let host = sni_hostname.as_bytes();
        // Inner body:
        //   server_name_list_length (u16)
        //   name_type (u8) = 0x00 (host_name)
        //   host_name_length (u16)
        //   host_name bytes
        let sn_list_len: u16 = 1 + 2 + u16::try_from(host.len()).unwrap_or(0);
        let ext_body_len: u16 = 2 + sn_list_len; // includes list-length field itself
        extensions.extend_from_slice(&ext_body_len.to_be_bytes());
        extensions.extend_from_slice(&sn_list_len.to_be_bytes());
        extensions.push(0x00); // name_type
        extensions.extend_from_slice(&u16::try_from(host.len()).unwrap_or(0).to_be_bytes());
        extensions.extend_from_slice(host);
    }

    // ---- ClientHello body ----
    let mut body = Vec::with_capacity(64 + ciphers.len() * 2 + extensions.len());
    body.extend_from_slice(&client_version.wire().to_be_bytes());
    // random (32 bytes) — static placeholder; content doesn't matter
    // for the acceptance probe.
    body.extend_from_slice(&[0x42u8; 32]);
    body.push(0x00); // session_id length=0
    let ciphers_bytes_len: u16 = u16::try_from(ciphers.len() * 2).unwrap_or(0);
    body.extend_from_slice(&ciphers_bytes_len.to_be_bytes());
    for cs in ciphers {
        body.extend_from_slice(&cs.0.to_be_bytes());
    }
    // compression_methods: length 1, null (0x00)
    body.push(0x01);
    body.push(0x00);
    // extensions: 2-byte length + extensions body
    body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&extensions);

    // ---- Handshake header ----
    let body_len: u32 = u32::try_from(body.len()).unwrap_or(0);
    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(0x01); // msg_type = client_hello
    handshake.push(((body_len >> 16) & 0xFF) as u8);
    handshake.push(((body_len >> 8) & 0xFF) as u8);
    handshake.push((body_len & 0xFF) as u8);
    handshake.extend_from_slice(&body);

    // ---- Record layer ----
    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // content_type = handshake
                       // record_version — always TLSv1.0 for broadest legacy compat. The
                       // probed version sits inside the handshake body.
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Classify the first record bytes returned by the server.
///
/// - `0x16 .. 0x02` → `ServerHello`, meaning version/cipher accepted.
/// - `0x15 ..` → TLS alert (level+desc), meaning rejected.
/// - Anything else (including fewer than 5 bytes) → indeterminate.
#[must_use]
pub fn parse_server_response(bytes: &[u8]) -> ProbeOutcome {
    if bytes.len() < 5 {
        return ProbeOutcome::Unknown;
    }
    match bytes[0] {
        0x16 => {
            if bytes.len() >= 6 && bytes[5] == 0x02 {
                ProbeOutcome::Accepted
            } else {
                ProbeOutcome::Unknown
            }
        }
        0x15 => ProbeOutcome::Rejected,
        _ => ProbeOutcome::Unknown,
    }
}

// =============================================================
// Raw-socket probes (legacy versions + all ciphers)
// =============================================================

/// Probe whether the server accepts a legacy TLS version via
/// raw-socket `ClientHello`.
async fn probe_legacy_version(
    host: &str,
    port: u16,
    mode: TlsMode,
    version: TlsVersionId,
) -> ProbeOutcome {
    // Offer a broad legacy cipher list so the server has a chance to
    // pick something; we don't care which one.
    let ciphers = [
        CipherSuiteId(0x002F), // TLS_RSA_WITH_AES_128_CBC_SHA
        CipherSuiteId(0x0035), // TLS_RSA_WITH_AES_256_CBC_SHA
        CipherSuiteId(0x000A), // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        CipherSuiteId(0x0005), // TLS_RSA_WITH_RC4_128_SHA
        CipherSuiteId(0x0004), // TLS_RSA_WITH_RC4_128_MD5
    ];
    send_client_hello_and_classify(host, port, mode, version, &ciphers).await
}

/// Probe whether the server accepts a specific cipher suite under
/// `TLSv1.2` via raw-socket `ClientHello`.
pub async fn probe_tls_cipher(
    host: &str,
    port: u16,
    mode: TlsMode,
    cipher: CipherSuiteId,
) -> ProbeOutcome {
    send_client_hello_and_classify(host, port, mode, TlsVersionId::Tls12, &[cipher]).await
}

/// Shared helper: open TCP, optionally run STARTTLS preamble, send
/// `ClientHello`, read first record bytes, classify.
async fn send_client_hello_and_classify(
    host: &str,
    port: u16,
    mode: TlsMode,
    version: TlsVersionId,
    ciphers: &[CipherSuiteId],
) -> ProbeOutcome {
    let addr = format!("{host}:{port}");
    let Ok(Ok(tcp)) = timeout(PHASE_TIMEOUT, TcpStream::connect(&addr)).await else {
        return ProbeOutcome::Unknown;
    };

    let mut tcp = match mode {
        TlsMode::Implicit => tcp,
        TlsMode::Starttls(protocol) => match run_starttls_preamble(tcp, protocol).await {
            Ok(t) => t,
            Err(_) => return ProbeOutcome::Unknown,
        },
        // RDP-TLS cipher / version enumeration would require driving the
        // X.224 CR/CC dance before every probe handshake. Not supported
        // today — return Unknown so no findings are fabricated.
        TlsMode::RdpTls => return ProbeOutcome::Unknown,
    };

    let hello = build_client_hello(version, ciphers, host);
    if timeout(PHASE_TIMEOUT, tcp.write_all(&hello)).await.is_err() {
        return ProbeOutcome::Unknown;
    }

    read_first_record(&mut tcp).await
}

/// Read up to [`RESPONSE_READ_BUDGET`] bytes or until we have enough
/// to classify the first record.
async fn read_first_record(tcp: &mut TcpStream) -> ProbeOutcome {
    let mut buf = Vec::with_capacity(32);
    let mut chunk = [0u8; 64];
    loop {
        let Ok(Ok(read)) = timeout(PHASE_TIMEOUT, tcp.read(&mut chunk)).await else {
            break;
        };
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() >= 6 {
            return parse_server_response(&buf);
        }
        if buf.len() >= RESPONSE_READ_BUDGET {
            break;
        }
    }
    parse_server_response(&buf)
}

// =============================================================
// Modern-version probe via rustls
// =============================================================

/// Dangerously-permissive cert verifier used only for version-probe
/// handshakes. We do not care about cert validity here — the cert path
/// is owned by [`crate::engine::tls_probe::check_certificate`].
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Probe whether the server accepts TLSv1.2 or TLSv1.3 via a
/// rustls-driven handshake with a permissive cert verifier.
async fn probe_modern_version(
    host: &str,
    port: u16,
    mode: TlsMode,
    version: TlsVersionId,
) -> ProbeOutcome {
    let rustls_version: &'static rustls::SupportedProtocolVersion = match version {
        TlsVersionId::Tls12 => &rustls::version::TLS12,
        TlsVersionId::Tls13 => &rustls::version::TLS13,
        _ => return ProbeOutcome::Unknown,
    };

    // Install the default crypto provider lazily (idempotent — mirrors
    // engine::tls_probe behavior).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = rustls::ClientConfig::builder_with_protocol_versions(&[rustls_version])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    let addr = format!("{host}:{port}");
    let Ok(Ok(tcp)) = timeout(PHASE_TIMEOUT, TcpStream::connect(&addr)).await else {
        return ProbeOutcome::Unknown;
    };

    let tcp = match mode {
        TlsMode::Implicit => tcp,
        TlsMode::Starttls(protocol) => match run_starttls_preamble(tcp, protocol).await {
            Ok(t) => t,
            Err(_) => return ProbeOutcome::Unknown,
        },
        // RDP-TLS version enumeration would require driving the X.224
        // CR/CC dance before every probe handshake. Not supported today —
        // return Unknown so no findings are fabricated.
        TlsMode::RdpTls => return ProbeOutcome::Unknown,
    };

    let Ok(server_name) = rustls::pki_types::ServerName::try_from(host.to_string()) else {
        return ProbeOutcome::Unknown;
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    match timeout(PHASE_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(_)) => ProbeOutcome::Accepted,
        Ok(Err(e)) => classify_rustls_error(&e),
        Err(_) => ProbeOutcome::Unknown,
    }
}

/// Map a rustls handshake error to a [`ProbeOutcome`].
///
/// Errors whose message mentions a version-related TLS alert or a
/// peer-incompatibility report are treated as [`ProbeOutcome::Rejected`];
/// everything else maps to [`ProbeOutcome::Unknown`].
fn classify_rustls_error(err: &std::io::Error) -> ProbeOutcome {
    let msg = err.to_string().to_ascii_lowercase();
    if msg.contains("protocol version")
        || msg.contains("handshake_failure")
        || msg.contains("protocolversion")
        || msg.contains("peerincompatible")
        || msg.contains("insufficient_security")
    {
        ProbeOutcome::Rejected
    } else {
        ProbeOutcome::Unknown
    }
}

// =============================================================
// Top-level probe entry points
// =============================================================

/// Probe whether the server accepts a specific TLS version.
///
/// Dispatches to the raw-socket path for SSLv3/TLSv1.0/TLSv1.1 and to
/// the rustls path for TLSv1.2/TLSv1.3.
pub async fn probe_tls_version(
    host: &str,
    port: u16,
    mode: TlsMode,
    version: TlsVersionId,
) -> ProbeOutcome {
    if version.is_legacy() {
        probe_legacy_version(host, port, mode, version).await
    } else {
        probe_modern_version(host, port, mode, version).await
    }
}

/// Enumerate every version in [`ALL_PROBED_VERSIONS`] against a target.
///
/// Returns outcomes in order. Never fails — every probe contributes a
/// ([version](TlsVersionId), [outcome](ProbeOutcome)) pair even on
/// network error.
pub async fn enumerate_tls_versions(
    host: &str,
    port: u16,
    mode: TlsMode,
) -> Vec<(TlsVersionId, ProbeOutcome)> {
    let mut results = Vec::with_capacity(ALL_PROBED_VERSIONS.len());
    for version in ALL_PROBED_VERSIONS {
        let outcome = probe_tls_version(host, port, mode, *version).await;
        results.push((*version, outcome));
    }
    results
}

/// Enumerate weak cipher suites the server accepts under TLSv1.2.
///
/// Returns only ciphers that responded [`ProbeOutcome::Accepted`].
/// `limit` caps the number of ciphers probed; `None` means probe the
/// entire catalog (~38 probes). Use a small explicit limit for
/// production scans — each probe is a full TCP handshake.
pub async fn enumerate_weak_ciphers(
    host: &str,
    port: u16,
    mode: TlsMode,
    limit: Option<usize>,
) -> Vec<CipherSuiteId> {
    let catalog = weak_cipher_catalog();
    let take = limit.unwrap_or(catalog.len()).min(catalog.len());
    let mut accepted = Vec::new();
    for cipher in &catalog[..take] {
        if probe_tls_cipher(host, port, mode, *cipher).await == ProbeOutcome::Accepted {
            accepted.push(*cipher);
        }
    }
    accepted
}

// =============================================================
// Tests
// =============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // ---- Pure classifier tests ----

    #[test]
    fn tls_version_id_wire_values() {
        assert_eq!(TlsVersionId::Ssl30.wire(), 0x0300);
        assert_eq!(TlsVersionId::Tls10.wire(), 0x0301);
        assert_eq!(TlsVersionId::Tls11.wire(), 0x0302);
        assert_eq!(TlsVersionId::Tls12.wire(), 0x0303);
        assert_eq!(TlsVersionId::Tls13.wire(), 0x0304);
    }

    #[test]
    fn tls_version_severity_classification() {
        assert_eq!(TlsVersionId::Ssl30.severity_when_accepted(), Some(Severity::Critical));
        assert_eq!(TlsVersionId::Tls10.severity_when_accepted(), Some(Severity::Critical));
        assert_eq!(TlsVersionId::Tls11.severity_when_accepted(), Some(Severity::High));
        assert_eq!(TlsVersionId::Tls12.severity_when_accepted(), None);
        assert_eq!(TlsVersionId::Tls13.severity_when_accepted(), None);
    }

    #[test]
    fn tls_version_labels_match_ietf() {
        assert_eq!(TlsVersionId::Ssl30.label(), "SSLv3");
        assert_eq!(TlsVersionId::Tls10.label(), "TLSv1.0");
        assert_eq!(TlsVersionId::Tls11.label(), "TLSv1.1");
        assert_eq!(TlsVersionId::Tls12.label(), "TLSv1.2");
        assert_eq!(TlsVersionId::Tls13.label(), "TLSv1.3");
    }

    #[test]
    fn tls_version_is_legacy() {
        assert!(TlsVersionId::Ssl30.is_legacy());
        assert!(TlsVersionId::Tls10.is_legacy());
        assert!(TlsVersionId::Tls11.is_legacy());
        assert!(!TlsVersionId::Tls12.is_legacy());
        assert!(!TlsVersionId::Tls13.is_legacy());
    }

    #[test]
    fn cipher_suite_critical_classification() {
        assert_eq!(CipherSuiteId(0x0000).weakness(), CipherWeakness::Critical); // NULL
        assert_eq!(CipherSuiteId(0x0017).weakness(), CipherWeakness::Critical); // anon
        assert_eq!(CipherSuiteId(0x0008).weakness(), CipherWeakness::Critical); // EXPORT
        assert_eq!(CipherSuiteId(0x0009).weakness(), CipherWeakness::Critical); // DES
    }

    #[test]
    fn cipher_suite_weak_classification() {
        assert_eq!(CipherSuiteId(0x0004).weakness(), CipherWeakness::Weak); // RC4_MD5
        assert_eq!(CipherSuiteId(0x0005).weakness(), CipherWeakness::Weak); // RC4_SHA
        assert_eq!(CipherSuiteId(0x000A).weakness(), CipherWeakness::Weak); // 3DES
    }

    #[test]
    fn cipher_suite_ok_classification() {
        assert_eq!(CipherSuiteId(0x009C).weakness(), CipherWeakness::Ok);
        assert_eq!(CipherSuiteId(0xC02F).weakness(), CipherWeakness::Ok);
        assert_eq!(CipherSuiteId(0xCCA8).weakness(), CipherWeakness::Ok);
    }

    #[test]
    fn cipher_suite_name_lookup() {
        assert_eq!(CipherSuiteId(0x0004).name(), "TLS_RSA_WITH_RC4_128_MD5");
        assert_eq!(CipherSuiteId(0xC02F).name(), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(CipherSuiteId(0xFFFF).name(), "Unknown (0xFFFF)");
    }

    #[test]
    fn weak_cipher_catalog_shape() {
        let catalog = weak_cipher_catalog();
        assert!(!catalog.is_empty());
        assert!(catalog.len() >= 25, "catalog should cover the main weak+legacy set");
        let has_critical = catalog.iter().any(|c| c.weakness() == CipherWeakness::Critical);
        let has_weak = catalog.iter().any(|c| c.weakness() == CipherWeakness::Weak);
        let has_legacy = catalog.iter().any(|c| c.weakness() == CipherWeakness::Legacy);
        let has_ok = catalog.iter().any(|c| c.weakness() == CipherWeakness::Ok);
        assert!(has_critical);
        assert!(has_weak);
        assert!(has_legacy);
        assert!(has_ok, "catalog includes Ok baselines so reports confirm modern AEAD");
        let mut seen = std::collections::HashSet::new();
        for c in catalog {
            assert!(seen.insert(c.0), "duplicate cipher in catalog: 0x{:04X}", c.0);
        }
    }

    #[test]
    fn cipher_weakness_severity_mapping() {
        assert_eq!(CipherWeakness::Critical.severity(), Some(Severity::Critical));
        assert_eq!(CipherWeakness::Weak.severity(), Some(Severity::High));
        assert_eq!(CipherWeakness::Legacy.severity(), Some(Severity::Medium));
        assert_eq!(CipherWeakness::Ok.severity(), None);
    }

    // ---- Wire-format tests ----

    #[test]
    fn build_client_hello_record_header() {
        let ciphers = [CipherSuiteId(0x002F)];
        let hello = build_client_hello(TlsVersionId::Tls10, &ciphers, "example.com");
        assert!(hello.len() >= 5);
        assert_eq!(hello[0], 0x16, "content_type must be handshake");
        assert_eq!(hello[1], 0x03, "record_version major");
        assert_eq!(hello[2], 0x01, "record_version minor (always TLSv1.0 for compat)");
        let payload_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(payload_len, hello.len() - 5);
    }

    #[test]
    fn build_client_hello_client_version_matches_probe() {
        for version in ALL_PROBED_VERSIONS {
            let hello = build_client_hello(*version, &[CipherSuiteId(0x002F)], "h");
            // client_version bytes sit at offset 5 (record) + 4 (handshake header) = 9.
            let client_version_bytes = [hello[9], hello[10]];
            assert_eq!(
                u16::from_be_bytes(client_version_bytes),
                version.wire(),
                "client_version mismatch for {version:?}"
            );
        }
    }

    #[test]
    fn build_client_hello_cipher_list_encoded() {
        let ciphers = [CipherSuiteId(0x002F), CipherSuiteId(0x0035), CipherSuiteId(0x000A)];
        let hello = build_client_hello(TlsVersionId::Tls12, &ciphers, "h");
        // Offsets: 5 (record) + 4 (handshake) + 2 (client_version) + 32 (random)
        //   + 1 (session_id len) = 44.
        let cs_len_bytes = &hello[44..46];
        assert_eq!(u16::from_be_bytes([cs_len_bytes[0], cs_len_bytes[1]]), 6);
        let cs_bytes = &hello[46..52];
        assert_eq!(&cs_bytes[..2], &[0x00, 0x2F]);
        assert_eq!(&cs_bytes[2..4], &[0x00, 0x35]);
        assert_eq!(&cs_bytes[4..6], &[0x00, 0x0A]);
    }

    #[test]
    fn build_client_hello_sni_extension_present() {
        let hello =
            build_client_hello(TlsVersionId::Tls12, &[CipherSuiteId(0x002F)], "mail.example.com");
        let bytes = b"mail.example.com";
        let found = hello.windows(bytes.len()).any(|w| w == bytes);
        assert!(found, "SNI hostname bytes must appear in the ClientHello");
    }

    #[test]
    fn parse_server_response_server_hello_accepted() {
        let bytes = [0x16, 0x03, 0x03, 0x00, 0x32, 0x02, 0x00, 0x00];
        assert_eq!(parse_server_response(&bytes), ProbeOutcome::Accepted);
    }

    #[test]
    fn parse_server_response_alert_rejected() {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(parse_server_response(&bytes), ProbeOutcome::Rejected);
    }

    #[test]
    fn parse_server_response_short_or_empty_unknown() {
        assert_eq!(parse_server_response(&[]), ProbeOutcome::Unknown);
        assert_eq!(parse_server_response(&[0x16, 0x03, 0x03]), ProbeOutcome::Unknown);
    }

    #[test]
    fn parse_server_response_handshake_not_server_hello_unknown() {
        let bytes = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_server_response(&bytes), ProbeOutcome::Unknown);
    }

    // ---- Ephemeral-listener tests ----

    /// Canned ServerHello bytes — minimal but parse-valid first record.
    const CANNED_SERVER_HELLO: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x30, // record header
        0x02, 0x00, 0x00, 0x2C, // handshake header (server_hello, length=44)
        0x03, 0x03, // server_version
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x00, // session_id_length=0
        0x00, 0x2F, // cipher_suite
        0x00, // compression_method=null
        0x00, 0x00, // extensions length=0
    ];

    /// Canned Alert bytes — level=fatal, description=handshake_failure.
    const CANNED_ALERT: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

    #[tokio::test]
    async fn probe_tls_version_against_accept_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(CANNED_SERVER_HELLO).await;
            let _ = stream.shutdown().await;
        });

        let outcome =
            probe_tls_version("127.0.0.1", addr.port(), TlsMode::Implicit, TlsVersionId::Tls10)
                .await;
        server.await.ok();
        assert_eq!(outcome, ProbeOutcome::Accepted);
    }

    #[tokio::test]
    async fn probe_tls_version_against_reject_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(CANNED_ALERT).await;
            let _ = stream.shutdown().await;
        });

        let outcome =
            probe_tls_version("127.0.0.1", addr.port(), TlsMode::Implicit, TlsVersionId::Tls10)
                .await;
        server.await.ok();
        assert_eq!(outcome, ProbeOutcome::Rejected);
    }

    #[tokio::test]
    async fn probe_tls_version_against_closing_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = stream.shutdown().await;
            drop(stream);
        });

        let outcome =
            probe_tls_version("127.0.0.1", addr.port(), TlsMode::Implicit, TlsVersionId::Tls10)
                .await;
        server.await.ok();
        assert_eq!(outcome, ProbeOutcome::Unknown);
    }

    #[tokio::test]
    async fn probe_tls_cipher_against_accept_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(CANNED_SERVER_HELLO).await;
            let _ = stream.shutdown().await;
        });

        let outcome =
            probe_tls_cipher("127.0.0.1", addr.port(), TlsMode::Implicit, CipherSuiteId(0x0004))
                .await;
        server.await.ok();
        assert_eq!(outcome, ProbeOutcome::Accepted);
    }

    // ---- #[ignore]-gated live tests ----

    /// Live smoke: requires operator to set `SCORCHKIT_TLS_ENUM_HOST`
    /// to a real target (e.g. `badssl.com:443`). Run with
    /// `cargo test tls_version_enum_live -- --ignored`.
    #[tokio::test]
    #[ignore = "live-network — requires SCORCHKIT_TLS_ENUM_HOST=host:port"]
    async fn tls_version_enum_live() {
        let Ok(target) = std::env::var("SCORCHKIT_TLS_ENUM_HOST") else {
            return;
        };
        let Some((host, port_str)) = target.split_once(':') else {
            return;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            return;
        };
        let results = enumerate_tls_versions(host, port, TlsMode::Implicit).await;
        assert_eq!(results.len(), ALL_PROBED_VERSIONS.len());
    }

    /// Live smoke for cipher enum. See [`tls_version_enum_live`] for setup.
    #[tokio::test]
    #[ignore = "live-network — requires SCORCHKIT_TLS_ENUM_HOST=host:port"]
    async fn tls_cipher_enum_live() {
        let Ok(target) = std::env::var("SCORCHKIT_TLS_ENUM_HOST") else {
            return;
        };
        let Some((host, port_str)) = target.split_once(':') else {
            return;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            return;
        };
        let _accepted = enumerate_weak_ciphers(host, port, TlsMode::Implicit, Some(5)).await;
    }
}
