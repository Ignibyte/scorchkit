# Rustal local console

`scorchkit-console` is an optional loopback-only operator frontend over the versioned ScorchKit
control API. It is a separately locked Rustal application under `apps/scorchkit-console`, not a
member of the root Cargo workspace. Core builds, CLI, MCP, storage, scanners, and policy do not
resolve or compile Rustal.

```text
browser ── same-origin HTTP ──> scorchkit-console (Rustal)
                                      |
                                      | server-held bearer
                                      v
                              v1 loopback control API
                                      |
                         policy / jobs / canonical storage
```

The console is a projection and command adapter. It owns no engagement grant, project authority,
scanner evidence, durable finding state, or database handle. The active engagement is read-only.
Target registration and run selections can narrow that configured authority; they cannot widen it.
Every target, job, cancellation, and triage mutation is an ordinary authenticated v1 control
command and receives the service's normal policy and canonical-data validation.

## Process and dependency boundary

The app depends on `scorchkit-control` DTOs and a sibling Rustal source checkout. `bin/console.sh`
requires the exact reviewed Rustal Git revision and a clean Rustal crate source tree before format,
lint, test, build, or execution. The app's own `Cargo.lock` makes its complete dependency graph
independent of the root lockfile. Root metadata and architecture tests reject a Rustal edge in the
core workspace.

Startup validates all configuration before Rustal listens:

- the console bind is a literal IPv4 or IPv6 loopback socket with a nonzero port;
- the control URL is a credential-free `http` origin with a literal loopback host and explicit
  port;
- the immutable engagement is an exact UUID;
- the bearer comes through a named environment variable, is 32–4096 printable bytes, and becomes a
  sensitive server-only header.

The control client disables ambient HTTP proxy discovery, rejects redirects, and connects only to
the validated literal loopback origin. This prevents a process-level proxy setting from receiving
the control bearer.

The console and control API use distinct listeners. Public or non-loopback hosting, TLS termination,
sessions, multiple principals, tenants, and RBAC remain out of scope until the authenticated team
deployment supplies those boundaries.

## Request and rendering boundary

The browser receives only same-origin HTML, CSS, JavaScript, and finite SSE responses. It never
receives the control URL or bearer. Every read requires the exact configured Host. Every form POST
also requires the exact Origin, optional `Sec-Fetch-Site` parity, a process-scoped CSRF value, a
bounded body, and typed route/form identities before an upstream command is constructed.

Pages consume only typed v1 response envelopes whose schema, request identity, authenticated
principal kind, and engagement binding match the request. Control redirects are denied, JSON and
response sizes are bounded, page limits are fixed, continuation presence is visible, and rendered
HTML has a final output ceiling. Askama escapes every projected value. Scanner records, separately
labeled model analysis, evidence, triage transitions, correlations, suppressions, and degraded job
coverage remain visually distinct.

Security headers restrict assets and connections to the console origin, deny framing, and preserve
the same-origin Origin header needed by POST enforcement. The enhancement script uses JSON parsing,
`CSS.escape`, and `textContent`; it has no storage, cookie, remote URL, HTML injection, or control
authorization branch.

## Event boundary

One server task consumes the authenticated canonical `/v1/events` stream. Its incremental parser
rejects oversized or malformed frames, unsupported event types, schema drift, non-job resources,
and non-contiguous sequences. A fixed deque retains only the newest validated events. Reconnects
resume after the last accepted sequence with bounded exponential delay. An authenticated typed
expired cursor can move the empty mirror only to the validated retained-history boundary; a typed
future cursor clears it to zero after an upstream restart. Other errors cannot move the cursor.

The browser-facing `/events` route returns a finite same-origin SSE replay and then closes. Native
`EventSource` reconnect supplies the next cursor. Expired and future cursors produce explicit reset
events rather than silently skipping or reordering job changes. The upstream bearer never enters
browser state.

## Delivery evidence

`bash bin/console.sh check` runs the independent app's formatting, strict all-target Clippy, unit,
integration, and documentation tests after the revision preflight. Delivery gates 17–19 additionally
build the app and drive the real Rustal server through Chrome against a typed loopback control mock,
cover representative mobile/high-contrast/reduced-motion renders, and verify the reviewed CSS
digest plus template/script source policy. The ordinary root lanes continue proving that headless
operation is complete without the app.
