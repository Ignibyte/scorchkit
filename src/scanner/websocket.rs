//! WebSocket security testing module.
//!
//! Probes common WebSocket endpoint paths, tests for Cross-Site WebSocket
//! Hijacking (CSWSH) via origin validation, detects unencrypted `ws://`
//! connections, and checks for unauthenticated WebSocket access.

use std::time::Duration;

use async_trait::async_trait;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// WebSocket connect timeout.
const WS_TIMEOUT: Duration = Duration::from_secs(5);

/// WebSocket security testing via endpoint discovery and connection-level checks.
///
/// Discovers WebSocket endpoints by probing common paths, then tests each for
/// origin validation (CSWSH), unencrypted transport, and unauthenticated access.
#[derive(Debug)]
pub struct WebSocketModule;

#[async_trait]
impl ScanModule for WebSocketModule {
    fn name(&self) -> &'static str {
        "WebSocket Security"
    }

    fn id(&self) -> &'static str {
        "websocket"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Test WebSocket endpoints for CSWSH, unencrypted transport, and auth bypass"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base = ctx.target.base_url();
        let mut findings = Vec::new();

        // Phase 1: Discover WS endpoints via HTTP Upgrade probe
        let ws_paths = generate_ws_paths();
        let mut discovered: Vec<WsEndpoint> = Vec::new();

        for path in &ws_paths {
            let http_url = format!("{base}{path}");

            let Ok(response) = ctx
                .http_client
                .get(&http_url)
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .send()
                .await
            else {
                continue;
            };

            if is_upgrade_response(response.status().as_u16(), response.headers()) {
                discovered
                    .push(WsEndpoint { url: http_to_ws_url(&http_url), path: path.to_string() });
            }
        }

        if discovered.is_empty() {
            return Ok(findings);
        }

        // Phase 2: Test each discovered endpoint
        for endpoint in &discovered {
            // Test CSWSH (origin validation)
            test_cswsh(endpoint, &base, &mut findings).await;

            // Check for unencrypted WS when HTTPS is available
            if ctx.target.is_https && endpoint.url.starts_with("ws://") {
                findings.push(
                    Finding::new(
                        "websocket",
                        Severity::Medium,
                        format!("Unencrypted WebSocket: {}", endpoint.path),
                        format!(
                            "The WebSocket endpoint at '{}' uses unencrypted ws:// \
                             while the main site uses HTTPS. WebSocket traffic is \
                             transmitted in cleartext, exposing it to interception.",
                            endpoint.url
                        ),
                        &endpoint.url,
                    )
                    .with_evidence(format!("Protocol: ws:// (unencrypted) at {}", endpoint.path))
                    .with_remediation(
                        "Use wss:// (WebSocket Secure) for all WebSocket connections. \
                         Configure the server to reject ws:// connections.",
                    )
                    .with_owasp("A02:2021 Cryptographic Failures")
                    .with_cwe(319)
                    .with_confidence(0.7),
                );
            }

            // Test unauthenticated access
            test_unauth_access(endpoint, &mut findings).await;
        }

        Ok(findings)
    }
}

/// A discovered WebSocket endpoint.
#[derive(Debug, Clone)]
struct WsEndpoint {
    /// Full WebSocket URL (ws:// or wss://).
    url: String,
    /// Path component (e.g., "/ws", "/socket.io").
    path: String,
}

/// Convert an HTTP(S) URL to a WebSocket URL.
///
/// Replaces `http://` with `ws://` and `https://` with `wss://`.
/// URLs already using `ws://` or `wss://` are returned unchanged.
#[must_use]
fn http_to_ws_url(url: &str) -> String {
    url.strip_prefix("https://")
        .map(|rest| format!("wss://{rest}"))
        .or_else(|| url.strip_prefix("http://").map(|rest| format!("ws://{rest}")))
        .unwrap_or_else(|| url.to_string())
}

/// Generate common WebSocket endpoint paths to probe.
#[must_use]
fn generate_ws_paths() -> Vec<&'static str> {
    vec![
        "/ws",
        "/wss",
        "/websocket",
        "/socket",
        "/socket.io",
        "/sockjs",
        "/cable",
        "/hub",
        "/signalr",
        "/graphql",
        "/subscriptions",
        "/realtime",
        "/events",
        "/stream",
        "/chat",
        "/live",
        "/api/ws",
        "/api/websocket",
        "/api/stream",
    ]
}

/// Check if an HTTP response indicates a successful WebSocket upgrade.
///
/// A valid upgrade response has status 101 and contains the `Upgrade: websocket`
/// header. Some servers also return 200 with upgrade headers for polling fallback.
fn is_upgrade_response(status: u16, headers: &reqwest::header::HeaderMap) -> bool {
    if status == 101 {
        return true;
    }

    // Some WS servers respond with 200 + upgrade headers (Socket.IO, etc.)
    if status == 200 {
        if let Some(upgrade) = headers.get("upgrade") {
            if let Ok(val) = upgrade.to_str() {
                return val.eq_ignore_ascii_case("websocket");
            }
        }
    }

    // 400 with "websocket" in response often means the path exists but
    // the handshake was incomplete (missing key, wrong version) — still discoverable
    false
}

/// Test for Cross-Site WebSocket Hijacking (CSWSH).
///
/// Attempts a WebSocket connection with a spoofed `Origin` header. If the
/// server accepts the connection without validating the origin, an attacker
/// could hijack the WebSocket from a malicious page.
async fn test_cswsh(endpoint: &WsEndpoint, legitimate_origin: &str, findings: &mut Vec<Finding>) {
    let evil_origin = "https://evil-attacker.com";

    // Try connecting with the evil origin
    let Ok(mut request) = endpoint.url.as_str().into_client_request() else {
        return;
    };

    request.headers_mut().insert("Origin", HeaderValue::from_static("https://evil-attacker.com"));

    let connect_result =
        tokio::time::timeout(WS_TIMEOUT, tokio_tungstenite::connect_async(request)).await;

    if let Ok(Ok((_ws_stream, _response))) = connect_result {
        // Connection succeeded with evil origin — CSWSH!
        findings.push(
            Finding::new(
                "websocket",
                Severity::High,
                format!("Cross-Site WebSocket Hijacking: {}", endpoint.path),
                format!(
                    "The WebSocket endpoint at '{}' accepts connections from \
                     arbitrary origins. An attacker can create a malicious web page \
                     that connects to this WebSocket endpoint on behalf of an \
                     authenticated user, stealing data or performing actions.",
                    endpoint.url
                ),
                &endpoint.url,
            )
            .with_evidence(format!(
                "Connection accepted with Origin: {evil_origin} \
                 (legitimate: {legitimate_origin})"
            ))
            .with_remediation(
                "Validate the Origin header on WebSocket upgrade requests. \
                 Reject connections from origins not in your allowlist. \
                 Implement CSRF tokens in the WebSocket handshake.",
            )
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(346)
            .with_confidence(0.7),
        );
    }
}

/// Test for unauthenticated WebSocket access.
///
/// Attempts a plain WebSocket connection without any authentication credentials.
/// If the connection succeeds, the endpoint may lack proper authentication.
async fn test_unauth_access(endpoint: &WsEndpoint, findings: &mut Vec<Finding>) {
    let Ok(request) = endpoint.url.as_str().into_client_request() else {
        return;
    };

    let connect_result =
        tokio::time::timeout(WS_TIMEOUT, tokio_tungstenite::connect_async(request)).await;

    if let Ok(Ok((_ws_stream, _response))) = connect_result {
        findings.push(
            Finding::new(
                "websocket",
                Severity::Medium,
                format!("Unauthenticated WebSocket Access: {}", endpoint.path),
                format!(
                    "The WebSocket endpoint at '{}' accepts connections without \
                     authentication credentials. If this endpoint provides access \
                     to sensitive data or functionality, it may be exploitable.",
                    endpoint.url
                ),
                &endpoint.url,
            )
            .with_evidence(format!(
                "WebSocket connection established without auth at {}",
                endpoint.path
            ))
            .with_remediation(
                "Require authentication for WebSocket connections. Validate \
                 session tokens or API keys during the WebSocket handshake. \
                 Do not rely solely on browser-sent cookies for WebSocket auth.",
            )
            .with_owasp("A07:2021 Identification and Authentication Failures")
            .with_cwe(306)
            .with_confidence(0.7),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for WebSocket security module.
    ///
    /// Tests URL conversion, path generation, and upgrade response detection
    /// without requiring a live WebSocket server.

    /// Verify HTTP-to-WS URL conversion for standard schemes.
    ///
    /// `http://` → `ws://`, `https://` → `wss://`, preserving host, port, and path.
    #[test]
    fn test_http_to_ws_url() {
        assert_eq!(http_to_ws_url("http://example.com"), "ws://example.com");
        assert_eq!(http_to_ws_url("https://example.com"), "wss://example.com");
        assert_eq!(http_to_ws_url("https://example.com/ws"), "wss://example.com/ws");
        assert_eq!(http_to_ws_url("http://example.com:8080/api"), "ws://example.com:8080/api");
    }

    /// Verify edge cases in URL conversion.
    ///
    /// Already-WS URLs pass through unchanged, custom ports are preserved.
    #[test]
    fn test_http_to_ws_url_edge_cases() {
        // Already ws://
        assert_eq!(http_to_ws_url("ws://example.com"), "ws://example.com");

        // Already wss://
        assert_eq!(http_to_ws_url("wss://example.com"), "wss://example.com");

        // With port and path
        assert_eq!(
            http_to_ws_url("https://example.com:443/socket.io"),
            "wss://example.com:443/socket.io"
        );
    }

    /// Verify all expected WebSocket paths are generated.
    ///
    /// The path list should cover common framework conventions: Express (socket.io),
    /// Rails (cable), ASP.NET (signalr/hub), GraphQL, and generic paths.
    #[test]
    fn test_generate_ws_paths() {
        let paths = generate_ws_paths();

        assert!(paths.len() >= 15, "Expected at least 15 WS paths, got {}", paths.len());

        // Framework-specific paths
        assert!(paths.contains(&"/socket.io"), "Missing Socket.IO path");
        assert!(paths.contains(&"/cable"), "Missing Rails ActionCable path");
        assert!(paths.contains(&"/hub"), "Missing SignalR hub path");
        assert!(paths.contains(&"/graphql"), "Missing GraphQL path");

        // Generic paths
        assert!(paths.contains(&"/ws"), "Missing /ws path");
        assert!(paths.contains(&"/websocket"), "Missing /websocket path");

        // All paths start with /
        for path in &paths {
            assert!(path.starts_with('/'), "Path '{path}' doesn't start with /");
        }
    }

    /// Verify upgrade response detection from HTTP headers.
    ///
    /// Status 101 should always be detected. Status 200 with `Upgrade: websocket`
    /// header should also be detected (Socket.IO compatibility).
    #[test]
    fn test_is_upgrade_response() {
        let empty_headers = reqwest::header::HeaderMap::new();

        // 101 = always upgrade
        assert!(is_upgrade_response(101, &empty_headers));

        // 200 + Upgrade: websocket
        let mut upgrade_headers = reqwest::header::HeaderMap::new();
        upgrade_headers.insert("upgrade", "websocket".parse().expect("valid header"));
        assert!(is_upgrade_response(200, &upgrade_headers));

        // 200 without upgrade header = not WS
        assert!(!is_upgrade_response(200, &empty_headers));

        // 404 = not WS
        assert!(!is_upgrade_response(404, &empty_headers));

        // 400 = not WS (even though path may exist)
        assert!(!is_upgrade_response(400, &empty_headers));
    }

    /// Verify `WsEndpoint` struct construction.
    #[test]
    fn test_ws_endpoint_construction() {
        let ep = WsEndpoint { url: "wss://example.com/ws".to_string(), path: "/ws".to_string() };
        assert_eq!(ep.url, "wss://example.com/ws");
        assert_eq!(ep.path, "/ws");
    }

    /// Verify URL conversion preserves query strings.
    #[test]
    fn test_http_to_ws_url_with_query() {
        assert_eq!(
            http_to_ws_url("https://example.com/ws?token=abc"),
            "wss://example.com/ws?token=abc"
        );
    }
}
