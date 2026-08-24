---
aar: AAR-033-rustal-console
ticket: TICKET-033
pipeline: rustal-console
status: submitted
opened: 2026-08-24
submitted: 2026-08-24
effectiveness: 4 - strong
---

# AAR-033 — Add an optional Rustal local operator console

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-attribution-not-authorization-001` | Browser state and page membership can look privileged while only the server bearer establishes a control principal. | Yes; the browser receives neither bearer nor authority metadata and every mutation remains an API decision. |
| `PR-scorchkit-local-frontend-bind-boundary-001` | A full console is still pre-SK-056 and has no tenant or remote identity boundary. | Yes; startup rejects every non-loopback listener and control URL. |
| `PR-scorchkit-durable-canonical-parity-001` and `PR-scorchkit-projection-validate-canonical-001` | The console renders findings, evidence, triage, reports, and events from durable data. | Yes; it consumes only validated typed control responses and does not reinterpret database rows. |
| `PR-scorchkit-secretless-control-target-001` | Target URLs appear in forms, jobs, and project pages. | Yes; all values originate from secretless API projections and every submitted target is reauthorized by the service. |
| `PR-scorchkit-immutable-store-pagination-001` | Dashboard collections could silently look complete after a UI cap. | Yes; page bounds and visible continuation state are part of the UI contract. |
| `PR-scorchkit-ui-fixture-canonical-shape-001` | A prior UI fixture used plausible but nonexistent DTO fields. | Yes; render fixtures must deserialize exact `scorchkit-control` DTOs before snapshots. |
| `PR-scorchkit-loopback-harness-nonblocking-driver-001` | Browser and mock-control fixtures own loopback servers in the same process. | Yes; all clients and harnesses remain asynchronous so they cannot starve their own server. |
| Rustal 0.48.0 source and ADR-0014 | The console needs a real Rustal route/render/SSE boundary without coupling the root workspace to an unpublished crate. | Yes; the console is separately locked, source-revision checked, and uses finite replay responses over a bounded background event mirror. |

## What happened

- ScorchKit gained a separately locked, loopback-only Rustal console over the authenticated v1
  control API. The app renders bounded canonical operational views, mirrors ordered job events,
  and sends target, job, cancellation, and triage changes only as existing control commands.
- The browser remained an untrusted presentation client: the server retains the bearer and exact
  engagement, while Host, Origin, CSRF, fetch-site, route, body, output, and cursor bounds guard
  browser traffic. The root workspace and core package graph remained Rustal-free.
- Real framework and browser tests exposed optional-query, form-sequence, security-header,
  responsive-layout, and event-retention assumptions that unit-level render tests had not shown.
  Each was repaired at its owning boundary and retained as executable evidence.
- Rustal advanced during implementation, but the exact dependency-source diff was empty. The
  approved revision, manifest metadata, helper preflight, docs, and lock evidence were repinned
  together to `8b741c4c0e4c87542dea575aea9be9acfa3bf728`.

## Novel findings

- Rustal's current `Query` extractor treats a missing URI query component as extraction failure;
  optional fields inside the query type do not make the URI component itself optional.
- Rustal's current URL-encoded form path cannot round-trip repeated keys into `Vec<String>`.
- `Referrer-Policy: no-referrer` suppresses the same-origin POST Origin header in Chrome, which
  conflicts with a server policy that deliberately requires exact Origin on every mutation.
- A console joining after the control journal's retention window needs a typed cursor reset from
  the authenticated error details; retrying the same expired cursor cannot recover.
- SSE frame ceilings must be applied while splitting the byte stream into frames. A transport chunk
  can validly contain multiple individually bounded frames and be larger than one frame ceiling.
- A literal-loopback URL does not prevent a default HTTP client from honoring ambient proxy
  configuration; bearer-bearing local clients must disable implicit proxies explicitly.
- HTML escaping prevents markup injection but does not make an untrusted string safe as a
  whitespace-separated CSS class list.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-rustal-optional-query-extractor-001` | A clean dashboard URI returned 500 because an optional status query used a component-requiring extractor. | Real Rustal route dispatch. |
| `BF-scorchkit-form-sequence-decoder-001` | Repeated evidence form keys failed to deserialize into a vector. | Real triage form dispatch. |
| `BF-scorchkit-referrer-origin-guard-conflict-001` | A legitimate same-origin Chrome POST omitted Origin and was rejected by the exact guard. | Browser mutation test. |
| `BF-scorchkit-flex-min-content-overflow-001` | A long hostile title pushed the severity badge beyond the mobile viewport. | Representative mobile render. |
| `BF-scorchkit-sse-cursor-retention-loop-001` | A late console retried the same expired upstream cursor forever. | Adversarial event-worker review. |
| `BF-scorchkit-sse-chunk-frame-bound-conflation-001` | A chunk containing multiple valid frames was rejected when its aggregate size exceeded the per-frame ceiling. | Adversarial SSE-decoder review. |
| `BF-scorchkit-loopback-bearer-ambient-proxy-001` | The authenticated literal-loopback client still inherited ambient HTTP proxy behavior. | Credential-boundary inspection. |
| `BF-scorchkit-untrusted-css-class-token-001` | Escaped severity text could add multiple presentation classes through whitespace. | Untrusted-presentation inspection. |
| `BF-scorchkit-local-upstream-error-erasure-001` | Local command validation and authenticated API failures became the same 502 class. | API error-semantics inspection. |
| `BF-scorchkit-nested-app-generated-scan-scope-001` | A new nested target tree expanded secret scanning dramatically while app checks remained after mutation. | Fast gate. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-optional-uri-component-extractor-001` | When a URI component is optional, test the component's complete absence and do not use an extractor that requires it merely because the decoded fields are optional. | Type optionality and transport-component optionality are separate contracts. |
| `PR-scorchkit-framework-form-roundtrip-001` | Round-trip every generated scalar and collection form through the exact production framework decoder; use one bounded structured field when repeated keys are unsupported. | Browser encoding conventions do not prove framework decoder support. |
| `PR-scorchkit-browser-header-guard-composition-001` | Prove the complete response-header and request-guard set with a successful real-browser mutation as well as rejection cases. | Individually reasonable security headers can suppress inputs another guard requires. |
| `PR-scorchkit-adversarial-responsive-content-001` | Render long canonical untrusted strings across mobile, forced-color, and reduced-motion profiles and assert document overflow and active-markup absence. | Escaping alone does not prevent hostile content from breaking usable layout. |
| `PR-scorchkit-typed-sse-cursor-reset-001` | Recover retained event continuity only from an authenticated typed expired/future cursor response with validated bounds; clear the local mirror before adopting the new baseline. | Blind retry cannot recover retention loss, while untyped cursor movement can hide gaps. |
| `PR-scorchkit-sse-frame-streaming-bound-001` | Enforce SSE limits per decoded frame while streaming across arbitrary chunk boundaries, and test a chunk larger than the frame limit that contains multiple valid frames. | Network chunk boundaries are not protocol record boundaries. |
| `PR-scorchkit-loopback-credential-no-proxy-001` | Disable ambient proxy discovery on every literal-loopback client that carries credentials, in addition to denying redirects and DNS names. | Loopback URL validation alone does not constrain the HTTP client's proxy route. |
| `PR-scorchkit-closed-presentation-token-001` | Map untrusted display values through a closed vocabulary before using them as CSS classes, IDs, selectors, or other token lists; preserve the escaped original only as text. | HTML escaping does not constrain token grammar or presentation effects. |
| `PR-scorchkit-adapter-error-provenance-001` | Preserve local validation, transport/integrity, and authenticated-service error classes through adapters and prove whether a rejected request reached the next boundary. | Erased errors misstate failures and obscure effect evidence. |
| `PR-scorchkit-optional-app-gate-parity-001` | When adding an out-of-workspace app, wire its format, lint, tests, audit, dependency hygiene, generated-tree exclusions, and UI evidence into appropriately ordered root lanes. | Root workspace tools neither discover the app nor understand its nested generated paths automatically. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Recalled knowledge kept the console as an optional presentation and command adapter over the
existing authenticated control boundary, prevented browser-, project-, or loopback-derived
authority, and preserved a Rustal-free core graph. Real Rustal and Chrome execution then exposed
transport-component, form-decoder, header-composition, responsive-layout, cursor-retention, and
frame-boundary assumptions that source-only checks would not have found. Adversarial inspection
also caught ambient proxy credential routing, untrusted CSS tokenization, validation-error erasure,
and optional-app gate drift. The resulting ten prevention rules are independently reusable. The
completed DIFF passed every lane and proved the root mutation selection was empty, so no mutant or
repeat broad inventory was run.
