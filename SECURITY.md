# ScorchKit Security Policy

## Review scope

Security review covers the Rust workspace, migrations, scan rules, plugin definitions, scripts,
CI, examples, and documentation that can cause users or agents to run commands.

Pay particular attention to:

- target authorization and scope propagation;
- redirect, DNS, CIDR, localhost, and cloud-metadata boundaries;
- subprocess construction, executable resolution, child cleanup, and output limits;
- credentials, cookies, tokens, cloud identities, evidence, logs, and report redaction;
- MCP authentication, tool annotations, destructive actions, and database isolation;
- plugins, hooks, YAML rules, temporary files, and untrusted scanner output;
- finding provenance, confidence, validation, and agent-generated claims.

## Authorized testing

Only scan systems you own or have explicit permission to test. Authorization must name the target
and permitted effect classes. Registration in a project or inclusion in a prompt is not sufficient
authorization by itself.

ScorchKit uses these effect classes:

- `passive`: reads local data or public metadata without probing the target;
- `active-safe`: sends bounded, non-destructive discovery or validation requests;
- `intrusive`: sends mutation payloads, uploads, high-volume enumeration, or service stress probes;
- `credential-test`: attempts authentication using supplied or generated credentials;
- `exploit`: attempts to obtain execution, persistence, privilege, or lateral movement.

The safety kernel is enforced at the public engine, CLI, MCP, project, and scheduler boundaries.
Every scan requires an `Engagement`; no-engagement configuration fails before a network client,
credential-bearing cloud client, filesystem traversal, or scanner process is created. Project
registration, legacy scope fields, agent manifests, prompts, and host approvals remain context only.

Automated development runs must remain on loopback, mock servers, fixtures, or disposable lab
infrastructure. The test suite never treats a timeout against an external address as success.

## Required invariants

- Every effect is denied unless an engagement policy allows its canonical target, capability, and
  effect class.
- Redirects, resolved IPs, discovered targets, scheduled runs, and subprocess arguments receive the
  same policy check as direct inputs.
- Secrets are redacted from terminal output, structured reports, MCP responses, logs, and stored
  evidence.
- External processes have bounded time, output, filesystem ownership, and termination behavior.
- Agent analysis never replaces or silently changes scanner evidence.
- Model analysis resolves only one exact configured provider/model per role, requires complete
  exact-key evaluation before production use, and remains labeled interpretation without evidence,
  lifecycle, grant, or execution authority. Service-managed inference requires separate external-
  tool and credential-use authorization, canonical redaction, no redirects, no retention, bounded
  input/output/time, and an awaited audit decision before send.
- Finding validation, disposition, correlation, and suppression are append-only children of the
  immutable scanner record. Every user mutation requires an independently bound principal and an
  exact `local-state`/`active-safe` grant for the canonical finding target before storage changes.
  Model analysis is provenance only; suppressions are exact and time-bounded; malformed history or
  duplicated projections fail the complete public read.
- Local run processors use versioned bounded contracts. Their target, module, capability, effect,
  and credential proposals may only narrow the host-built authorization ceiling; finding proposals
  remain separately labeled and cannot replace normalized scanner findings.
- Remote MCP transport requires bearer authentication, exact principal-to-engagement binding,
  loopback backend ownership, host/origin validation, bounded input and sessions, and an explicit
  TLS-termination policy before listening.
- Optional MCP Apps views are presentation only. They render validated canonical tool envelopes
  with text-only DOM construction, have no external domains or browser permissions, and route every
  mutation through an existing authorized MCP tool; capability and client metadata grant nothing.
- The optional Rustal console is a separate loopback-only control client. Its browser never receives
  the control bearer; exact Host, same-origin Origin, CSRF, body, page, response, render, event, and
  replay bounds apply before its server sends an ordinary authenticated control command. Ambient
  HTTP proxies and redirects are disabled for that literal-loopback client. The engagement is
  read-only, and local page membership grants nothing.
- The local control API is absent by default and requires an environment-backed bearer, exact
  principal-to-engagement binding, loopback bind and Host, constant-time credential verification,
  credential scrubbing, and bounded bodies, responses, concurrency, journals, and subscribers.
- The optional team service binds each environment-backed bearer to one subject, role, cell,
  organization, project, and engagement before routing. Cells require distinct live PostgreSQL
  databases, non-overlapping exact-authorized object roots and key rings, per-cell queues,
  journals, quotas, append-only intent/outcome audit, authenticated encryption, and
  distinct-destination snapshot verification. The backend remains loopback-only behind a trusted
  same-host TLS proxy.
- Webhook events are redacted before durable enqueue, and every delivery requires an exact
  `webhook-delivery`/`active-safe` grant for the configured URL, redirects, and resolved addresses.
- Release publication requires one immutable semantic-version tag and revision, exact native
  target/toolchain/features, header-verified bounded binaries, per-subject hashes and SBOMs, signed
  provenance, and complete readback verification before a draft becomes public.
- Third-party extensions require explicitly named, policy-authorized manifests and digest-bound
  WebAssembly modules. They run without WASI or ambient imports in a bounded owned worker; every
  host effect is separately authorized and its awaited audit event is published before it begins,
  and guest output is treated as an untrusted proposal rather than engine evidence or authority.

The current implementation has direct regression coverage for absence denial, HTTP redirects and
DNS answers, project membership, stored schedule snapshots, CVE-provider endpoints and cache paths,
webhook queue ownership and redaction, authenticated remote MCP identity/session isolation,
process-tree cleanup, terminal-control neutralization, and secret-safe configuration diagnostics.
The executable gate and its exact-worktree receipt remain the delivery evidence.

## Current support boundary

- Default DAST and code profiles, CLI module listing, MCP catalogs, and AI planning expose only
  application source, dependency, artifact, runtime, and attack-path modules. Network, enterprise,
  and cloud-account posture adapters require explicit compatibility selection. Selection never
  supplies an engagement or a missing capability or effect grant.
- Isolated third-party extensions are disabled by default and registered only through exact
  manifest paths. Version 1 supports credential-free, no-redirect HTTP `GET` and `HEAD` plus
  opaque pre-opened inputs; filesystem, credential, subprocess, native-library, automatic
  discovery, and direct storage access are unsupported. Trusted Rust modules and legacy command
  wrappers remain separate in-process or configured trust surfaces, not sandboxed extensions.
- Typed local run processors are available only in the standard DAST and code runners. They execute
  through the policy-sealed process owner with exact input, output, and wall-time ceilings. Required
  failures abort; optional failures retain only a redacted degraded outcome. Local notification
  processors are rejected in favor of the durable webhook queue. Legacy checkpoint/phased DAST and
  infra/cloud runners do not gain processor support.
- Provider-neutral model analysis is disabled by default and does not replace the legacy `[ai]`
  compatibility adapters. V1 supports exact host-managed and clean-environment local contract
  processes plus credential-free HTTP(S) service endpoints with environment-indirect bearer
  credentials. ScorchKit does not enroll a model, acquire provider access, select a fallback,
  support provider retention, or grant model output scanner-evidence or policy status. Credential-
  safe readiness is available through the control contract without invoking an adapter.
- Scanner descriptors declare their strongest effect. DAST process authorization reads the same
  canonical tool-effect mapping: Hydra, Kerbrute, NetExec, onesixtyone, and SMBMap require
  `credential-test` and `credential-use`; Commix and Metasploit require `exploit`. The legacy
  web-family Prowler adapter separately requires passive `credential-use` before it can inherit
  cloud credentials.
- Linux, macOS, and Windows are supported. External subprocesses use Unix process groups or Windows
  kill-on-close Job Objects and retain the same descendant-process cleanup guarantee.
- MCP uses local stdio by default. `serve --remote` enables the only supported remote profile:
  stateful Streamable HTTP behind a same-host trusted reverse proxy. The cleartext backend must bind
  to loopback; the proxy must terminate TLS, replace rather than append `X-Forwarded-Proto: https`,
  preserve the public Host, and forward `Authorization`. ScorchKit validates the exact path, Host,
  optional Origin, HTTPS assertion, body and concurrency bounds, body-read deadline, and bearer
  credential before rmcp routing. The proxy must independently enforce public connection, header,
  request, and idle timeouts and rate limits. Credentials are environment references resolved to
  runtime-only SHA-256 digests, and the raw authorization header is removed before rmcp routing.
  Every binding must name the exact enabled, unexpired configured engagement. Each principal owns
  a separate bounded session manager, so session IDs do not cross valid credentials. Direct TLS,
  non-loopback backends, OAuth/OIDC, multi-engagement selection, tenants, and RBAC are not supported.
- UI-capable MCP clients may negotiate one self-contained
  `ui://scorchkit/conversation-workbench/v1` resource for posture, finding, and attack-path results.
  Headless text and structured results remain complete. The resource has empty connect, asset,
  frame, and base-URI domain sets; no direct API, credential, storage, or scanner access; and no
  vendor-specific identity branch. Finding lifecycle changes use `finding_update_status` and its
  unchanged authorization and audit boundary.
- `scorchkit control-api` is the only control HTTP startup path. It binds loopback directly, has no
  remote/public mode, and authenticates before routing or body parsing. Canonical findings and
  evidence are normalized and checked against duplicated durable projections before response
  serialization; finding triage children additionally verify ordered state, exact contributor and
  evidence ownership, suppression scope and time bounds, and current-state parity. Divergence fails
  the complete query.
- A build with `team` adds the separate `scorchkit team-api` startup path. It supports static
  environment-indirect bearer bindings and database-per-project cells only. Direct TLS/public
  binds, OAuth/OIDC/password/session ownership, browser-held bearers, row-shared tenants,
  cross-cell superadministration, cloud object credentials, and in-place restore are unsupported.
  See [team-service architecture](docs/architecture/team-service.md).
- Durable CLI and MCP job hosts may deliver configured webhooks through PostgreSQL. Queue records
  contain a destination identity, redacted event payload, and engagement snapshot, never the
  destination URL or authorization value. Each direct and redirected request uses the shared
  policy-owned client under `webhook-delivery`/`active-safe`; resolved addresses are reauthorized.
  Credentials are environment-variable references resolved only for a claimed authorized attempt.
  Queue, payload, batch, timeout, redirect, retry, and backoff bounds are mandatory. Delivery and
  retry cannot change the scan's terminal result. Webhook-enabled stateless MCP startup is rejected.
- CVE provider access is separate from the scan target. NVD or OSV use requires scope grants for the
  provider hostname and resolved addresses plus a path-prefix grant for an existing cache directory.
- Native DNS, TLS, TCP, and infrastructure probes use the engagement-owned network policy. They
  authorize a derived hostname before resolution and every returned address before a query or
  connection. Tests cover denied derived names, mixed answer sets, private and metadata addresses,
  and authorized loopback traffic.
- Native AWS, GCP, and Azure SDK modules are not part of the production registry. Their source is
  compiled only by tests until provider authentication and service requests use a policy-owned
  transport. Production cloud scans expose five bounded external-tool adapters and require exact
  cloud, credential-use, and external-tool grants.
- Release qualification supports four raw native targets and the exact `infra,cloud,mcp` feature
  set. GitHub workflow actions, Rust, Syft, Cosign, and the local Sigstore trusted root are pinned;
  only the aggregate job receives OIDC and release-write permissions. Upgrade proof starts at
  v2.1.0, uses disposable databases, verifies a snapshot before restore into a separate database,
  and never performs a destructive down migration. Implementing the workflow does not authorize a
  live tag or publication.

## Vulnerability reports

Include the affected component and version, reproduction steps using a local or authorized target,
impact, and any suggested mitigation. Do not include real credentials, private customer data, or
payloads executed against systems you do not control.

Do not open a public issue for an unpatched vulnerability that could put users at immediate risk.
Use the repository owner's private reporting channel when one is published. Until then, contact the
owner privately before disclosure.
