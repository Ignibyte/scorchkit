# Authenticated application DAST

ScorchKit owns the application DAST request, authorization, schema validation, persona isolation,
ZAP Automation Framework plan, execution limits, parser, and coverage result. OWASP ZAP is an
external evidence producer. Its plan, reports, statistics, and alerts are input to ScorchKit, not
authorization and not a replacement for the engine policy.

## Public request

`ApplicationDastRequest` contains one HTTP(S) target, one phase profile, an optional anonymous run,
an ordered set of configured persona IDs, and zero or more local schema descriptors. A schema
descriptor names `openapi` or `graphql`, a local path, an expected SHA-256, and a same-origin
GraphQL endpoint when applicable. A request never contains a password, token, cookie, arbitrary
Automation Framework YAML, external URL, or ZAP option.

The three phase profiles are:

| Profile | Ordered ZAP work | Active scanner |
|---|---|---|
| `passive` | auth check, schema import, traditional spider, passive wait, exports and reports | absent |
| `standard` | passive work plus strict Client Spider and a second passive wait | absent |
| `active` | standard work plus bounded active scan and a final passive wait | present |

These names describe ZAP phases, not an authorization downgrade. Every plan requires
`DastScan/Intrusive` and `ExternalTool/Intrusive` because schema import and automated exploration
can exercise application behavior. Every named persona also requires
`ExternalTool/CredentialTest` and `CredentialUse/CredentialTest`. Each schema file requires
`LocalState/Passive` for its canonical path. All decisions are collected before credentials are
resolved, file contents are read, a workspace is created, or a process is launched.

CLI exposes `scorchkit dast`; MCP exposes `application_dast`; the library facade exposes
`Engine::application_dast`. All three build the same provider-neutral request and return the same
`ScanResult`. Codex is the preferred host, but no core or execution type names an agent provider.

## Persona configuration

`AppConfig::dast.personas` is keyed by a stable operator label. It supports:

- header authentication with a header name, a secret environment-variable reference, and an
  explicit verification URL/status/indicator contract;
- browser authentication with a login URL, username and password environment-variable references,
  an explicit verification contract, and the reviewed headless browser ID.

The configuration stores environment-variable names only. ScorchKit resolves their values after
the complete grant matrix passes. The generated YAML contains `${SCORCHKIT_ZAP_*}` placeholders,
and the child receives values through a clean environment. Header values use ZAP's documented
process-level authentication variables and are restricted to the authorized site. Browser users
use Automation Framework variables and explicit user selection on requestor, import, spider,
Client Spider, and active-scan jobs.

Browser authentication also requires an operator-pinned WebDriver whose major version matches the
installed browser. ScorchKit resolves the configured `tools.chromedriver` or `tools.geckodriver`
before creating the child environment and supplies only that resolved path to ZAP. The path cannot
contain whitespace, and neither the driver nor the browser is downloaded or updated during a scan.

One request can select anonymous, user, and admin runs. Each persona executes sequentially in a
fresh process, ZAP home, plan, report directory, and evidence namespace. Process-global header
authentication and browser sessions can therefore never bleed between roles. `ToolInvocation`
debug output exposes environment names and configured byte lengths, never values or stdin bytes.

## Schema boundary

ScorchKit canonicalizes metadata first, authorizes the canonical file, and then performs one
bounded read. The accepted bytes must match the request SHA-256. OpenAPI documents must be a
supported Swagger/OpenAPI object and GraphQL inputs must be valid SDL. Only local fragment `$ref`
values are accepted. File, relative-file, HTTP, and HTTPS references or imports fail closed.

Schema validation records every normalized route, HTTP method, operation ID when supplied, and
schema digest. OpenAPI server values are never trusted for execution; the generated job uses
`targetUrl` to force the authorized target. A GraphQL request supplies an explicit same-origin,
in-scope endpoint. The accepted bytes are copied once into the persona workspace and only that
owned copy is passed to ZAP.

An alert instance is matched back to the schema table by method and normalized route template.
When matched, the finding receives an operation correlation key. Missing operation IDs remain
explicit rather than being invented.

## Plan and execution

ScorchKit serializes a typed plan model. It does not concatenate YAML and does not accept user jobs.
Every plan uses an exact context, anchored include pattern, explicit exclusion list, strict client
scope, form-post suppression for the traditional spider, one browser, bounded depth/children,
bounded job durations, in-scope passive scanning, and a bounded active policy. Scan-time add-on
installation or update jobs, scripts, remote schemas, remote reports, arbitrary requestor bodies,
and external resource origins are not representable.

The ordered job skeleton is:

1. configure passive scanning in scope;
2. force an authenticated verification request, export a bounded pre-discovery HAR trace, and add
   an authentication-success statistic test for a named persona;
3. import each verified OpenAPI or GraphQL schema;
4. run the traditional spider;
5. wait for passive scanning;
6. run Client Spider and wait again for `standard` and `active`;
7. run active scan and wait again only for `active`;
8. export the in-context URL set and a method-bearing traffic HAR;
9. emit Traditional JSON Plus with statistics and Automation Framework state;
10. emit the bounded authentication JSON report for named personas.

The service first executes version mode with the owned home, loopback host, and no target, and
requires exactly one standalone `2.17.0` version line. It then reserves a nonzero ephemeral
loopback port and passes that explicit port to plan execution because ZAP treats port zero as its
default port rather than asking the operating system to select one. Plan execution explicitly
disables release checks, release downloads, and add-on update installation before running
`-cmd -autorun <owned-plan>`. It accepts only framework exits 0 and 2. Exit 2 is never silently
clean: the required report must contain parsed warnings and the persona outcome becomes degraded or
incomplete according to the warning class. Exit 1 or any other status is failure.

The shared executor owns the process group, wall clock, stdout/stderr bounds, and a recursive
artifact budget rooted at the already-created persona workspace. The budget counts every
filesystem entry without following links, sums regular-file bytes, and stops the process tree when
total bytes or entry count exceeds the
request. The workspace uses owner-only permissions and is removed on success, failure,
cancellation, timeout, parse failure, and drop.

## Evidence and coverage

Four final artifacts are mandatory: URL export, method-bearing traffic HAR, Traditional JSON Plus,
and, for a named persona, authentication JSON. Named personas also produce a bounded pre-discovery
HAR trace. ScorchKit
validates the exact verification URL, status, login indicator, and expected credential transport
in that trace, then combines the result with ZAP's authentication statistics. Bootstrap polling is
not silently ignored: the persona's explicit `max_logged_out` limit is the maximum allowed count.
Reads are bounded and reject links, changed ancestry, missing files, truncation, duplicate keys
where the parser can detect them, and incompatible schema shapes.

Schema operation coverage requires both the normalized route template and HTTP method to appear in
the final traffic HAR. The URL export still records the broader discovered route set; it cannot by
itself prove that a particular method or schema operation executed.

`ApplicationDastAssessment` records:

- profile, target, ZAP version, and each accepted schema digest;
- one persona outcome with plan digest and authentication state;
- ordered phase outcomes and typed gaps;
- expected schema routes and observed exported routes;
- Automation Framework errors and warnings after redaction.

A phase can be complete, incomplete, or failed. Missing schemas, tools, routes, or prerequisites are
incomplete. Process, authentication, artifact, and parser failures are degraded. The parent
`ScanResult` derives its execution status from both module outcomes and the DAST assessment, so an
empty findings list is clean only when every selected persona and phase is complete.

Each alert instance becomes a separate finding with ZAP plugin ID, CWE, confidence, persona,
runtime location, normalized route, parameter identity, plan digest, scanner version, and schema
operation identity when matched. Request and response headers and bodies pass through
`HttpEvidence` redaction before attachment. Attack values, tokens, cookies, authorization headers,
passwords, diagnostics, and tool stderr are redacted again at finding, JSON, report, MCP, and
storage boundaries.

Terminal, JSON, HTML, PDF, SARIF, MCP, and PostgreSQL project the same assessment. Storage keeps the
complete assessment in the scan execution evidence document and continues to append normalized
finding evidence through the existing v2 transaction.

## Runtime contract

The reviewed runtime is the official ZAP 2.17.0 Linux archive:

- release asset: `ZAP_2.17.0_Linux.tar.gz`;
- SHA-256: `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`;
- required Java: 17 or newer;
- build-host install root: `/mnt/fast/scorchkit/tools/zap/2.17.0`;
- executable override: `/mnt/fast/scorchkit/tools/zap/2.17.0/zap.sh`.

The reviewed browser-authentication runtime additionally uses ChromeDriver `151.0.7922.137` at
`/mnt/fast/scorchkit/tools/chromedriver/151.0.7922.137/chromedriver`. The downloaded Linux archive
has SHA-256 `6796e1d222c0a37befa1385c69ff2d62592ebbe2d98ed36c874ae3a67d1d5cba`; the installed executable
has SHA-256 `8f4f204a7977351c3408f46d4234435f522935921578e8758c178f99fb2f44bb`. The driver major must
continue to match the installed Chrome major. Firefox deployments configure `tools.geckodriver`
under the same no-download rule.

`doctor --deep` verifies the exact version and required Automation Framework job/report
availability without contacting a target. Add-on updates are an operator-owned maintenance action
outside scan execution. The test suite uses recording executors and loopback applications only.
