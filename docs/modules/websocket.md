# WebSocket Security

**Module ID:** `websocket` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/websocket.rs`

## What It Does

Tests WebSocket endpoints for security vulnerabilities. Discovers WebSocket endpoints by probing 19 common paths with HTTP Upgrade requests, then tests each for Cross-Site WebSocket Hijacking (CSWSH) via origin validation, unencrypted `ws://` transport when HTTPS is available, and unauthenticated WebSocket access.

## Checks Performed

| Check | Description |
|-------|-------------|
| Endpoint discovery | Probes 19 common WS paths (`/ws`, `/socket.io`, `/cable`, `/hub`, `/signalr`, etc.) via HTTP Upgrade |
| CSWSH (origin validation) | Attempts WebSocket connection with `Origin: https://evil-attacker.com` |
| Unencrypted transport | Flags `ws://` endpoints when the main site uses HTTPS |
| Unauthenticated access | Attempts plain WebSocket connection without any credentials |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Cross-Site WebSocket Hijacking | High | 346 | WebSocket accepts connection from arbitrary origin (`evil-attacker.com`) |
| Unencrypted WebSocket | Medium | 319 | Endpoint uses `ws://` while main site uses HTTPS |
| Unauthenticated WebSocket Access | Medium | 306 | WebSocket connection succeeds without authentication credentials |

## OWASP Coverage

- **A01:2021 -- Broken Access Control.** Covers CSWSH where an attacker's page can connect to the WebSocket on behalf of an authenticated user.
- **A02:2021 -- Cryptographic Failures.** Covers unencrypted WebSocket transport exposing data to interception.
- **A07:2021 -- Identification and Authentication Failures.** Covers missing authentication on WebSocket handshakes.

## How It Works

1. **Discovery**: Sends HTTP GET requests with `Upgrade: websocket`, `Connection: Upgrade`, and WebSocket handshake headers to 19 common paths. A response with status 101 or status 200 with `Upgrade: websocket` header confirms a WebSocket endpoint.
2. **CSWSH test**: Uses `tokio-tungstenite` to attempt a real WebSocket connection to the discovered endpoint with `Origin: https://evil-attacker.com`. If the connection succeeds (within 5-second timeout), the server does not validate origins.
3. **Unencrypted check**: If the main target uses HTTPS but the WebSocket URL starts with `ws://`, a finding is emitted. The `http_to_ws_url` function converts HTTP(S) URLs to their WS(S) equivalents.
4. **Auth check**: Attempts a plain WebSocket connection without any authentication headers or cookies. If the connection succeeds, the endpoint may lack authentication requirements.

## Paths Probed

Common framework-specific paths covered: Express/Socket.IO (`/socket.io`), Rails ActionCable (`/cable`), ASP.NET SignalR (`/hub`, `/signalr`), GraphQL Subscriptions (`/graphql`, `/subscriptions`), plus generic paths (`/ws`, `/websocket`, `/stream`, `/realtime`, `/events`, `/chat`, `/live`, `/api/ws`).

## Example Output

```
[High] Cross-Site WebSocket Hijacking: /ws
  The WebSocket endpoint at 'wss://example.com/ws' accepts connections from
  arbitrary origins. An attacker can create a malicious web page that connects
  to this WebSocket endpoint on behalf of an authenticated user, stealing data
  or performing actions.
  Evidence: Connection accepted with Origin: https://evil-attacker.com (legitimate: https://example.com)
  Remediation: Validate the Origin header on WebSocket upgrade requests
  OWASP: A01:2021 Broken Access Control | CWE-346
```
