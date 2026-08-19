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
- Remote MCP transport requires authentication and host validation.

The current implementation has direct regression coverage for absence denial, HTTP redirects and
DNS answers, project membership, stored schedule snapshots, CVE-provider endpoints and cache paths,
process-tree cleanup, terminal-control neutralization, and secret-safe configuration diagnostics.
The executable gate and its exact-worktree receipt remain the delivery evidence.

## Current support boundary

- Default DAST and code profiles, CLI module listing, MCP catalogs, and AI planning expose only
  application source, dependency, artifact, runtime, and attack-path modules. Network, enterprise,
  and cloud-account posture adapters require explicit compatibility selection. Selection never
  supplies an engagement or a missing capability or effect grant.
- Scanner descriptors declare their strongest effect. DAST process authorization reads the same
  canonical tool-effect mapping: Hydra, Kerbrute, NetExec, onesixtyone, and SMBMap require
  `credential-test` and `credential-use`; Commix and Metasploit require `exploit`. The legacy
  web-family Prowler adapter separately requires passive `credential-use` before it can inherit
  cloud credentials.
- Linux and macOS are supported. Non-Unix builds fail until Windows Job Object cleanup provides the
  same descendant-process guarantee.
- MCP is local stdio only. Do not expose it through an unauthenticated remote wrapper. Any future
  remote transport must authenticate its principal, validate the host, and define TLS termination.
- Outbound webhook delivery is disabled. The configuration shape remains readable for compatibility,
  but delivery may return only after it uses the policy-owned network client.
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

## Vulnerability reports

Include the affected component and version, reproduction steps using a local or authorized target,
impact, and any suggested mitigation. Do not include real credentials, private customer data, or
payloads executed against systems you do not control.

Do not open a public issue for an unpatched vulnerability that could put users at immediate risk.
Use the repository owner's private reporting channel when one is published. Until then, contact the
owner privately before disclosure.
