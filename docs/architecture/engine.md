# Engine and policy contexts

`scorchkit::facade::Engine` is the public boundary for effectful library use. It normalizes a target,
requires an engagement decision, and constructs a context that carries the proof and shared effect
controls used by downstream modules.

## Construction

Use one of these paths:

```rust,no_run
use std::sync::Arc;

use scorchkit::config::AppConfig;
use scorchkit::engine::policy::{
    Capability, EffectClass, Engagement, EngagementPolicy,
};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::facade::Engine;

let config = Arc::new(AppConfig::default());
let policy = EngagementPolicy::default()
    .allow_scope(ScopeRule::parse("127.0.0.1").expect("scope"))
    .allow_capability(Capability::DastScan)
    .allow_effect(EffectClass::ActiveSafe);
let engagement = Arc::new(Engagement::new("local test", policy));
let engine = Engine::for_engagement(config, engagement);
```

`Engine::new(config)` also works when `config.engagement` is present. If it is absent, the engine can
be inspected but every effectful method fails before resource creation.

Low-level context constructors are crate-private. Custom module selection starts from
`Engine::dast_context`, `code_context`, `infra_context`, or `cloud_context`, not an arbitrary HTTP
client or an unverified target.

## Public operations

| Method | Behavior |
|---|---|
| `scan` | Thorough DAST scan |
| `scan_with_profile` | DAST using quick, standard, thorough, or pentest policy |
| `code_scan` / `code_scan_language` | SAST over a canonical path |
| `full_scan` | Concurrent DAST and SAST merge |
| `infra_scan` | Native and tool-backed host/network scan when `infra` is enabled |
| `cloud_scan` | Posture scan when `cloud` is enabled |
| `full_assessment` | Requested DAST, SAST, infrastructure, and cloud families merged |

Family failures in a combined assessment are recorded and handled by the facade's merge rules. They
do not create synthetic findings.

## DAST profiles

| Profile | Primary effect | External tools | Credential grants | Exploit grants |
|---|---|---:|---:|---:|
| quick | `ActiveSafe` | no | no | no |
| standard | `Intrusive` | no | no | no |
| thorough | `Intrusive` | yes | no | no |
| pentest | `Intrusive` | yes | yes | yes |

Configured lifecycle hooks also require `ExternalTool` for the profile's primary effect. Hydra,
NetExec, and SMBMap require credential-test grants. Commix and exploit paths require exploit grants.

## Network authorization

DAST and infrastructure contexts carry `PolicyNetwork`, the shared native resolver and connector.
Its order is deliberate:

1. Normalize and authorize the hostname or address.
2. Resolve the hostname within a time budget.
3. Authorize every returned IPv4 and IPv6 address as one set.
4. Connect to a concrete approved socket address.
5. Preserve the original hostname for TLS SNI and certificate comparison.

HTTP clients use the same resolver and add a fresh authorization decision for every redirect URL.
This prevents an exact hostname grant from silently becoming a grant for a private, metadata, or
changed DNS address. Derived subdomains and authoritative DNS servers are checked before their query
or connection.

## Context contents

All contexts carry the target, application configuration, shared data, and an event bus. Additional
fields are family-specific:

- `ScanContext`: policy-bound redirecting and non-redirecting clients, native network policy, and a
  DAST tool executor.
- `CodeContext`: canonical code root, detected language/manifests, and a passive tool executor.
- `InfraContext`: parsed network target, optional network credentials, native network policy, and an
  infrastructure tool executor.
- `CloudContext`: parsed cloud target, resolved cloud credentials, and a cloud tool executor.

Successful authorization decisions remain inside each context. A tool adapter cannot change its
declared effect class by changing arguments.

Family orchestrators pass context-bound module futures to the shared executor. The executor cannot
inspect or widen the authorization proof. Its cancellation-aware methods accept a cloneable token;
the existing run methods create one internally. Persisted jobs and external job control are deferred
to SK-029.

## Results and errors

`ScanResult` retains findings, module runs, module skips, target identity, and timing. Findings keep
severity, confidence, evidence, remediation, standards mapping, and provenance fields.

The engine returns typed errors for invalid targets, policy denials, HTTP failures, tool resolution
or execution failures, output limits, hooks, storage, cancellation, and report failures. Policy
denials contain the engagement, normalized target, capability, effect, matched rule, and denial
reason needed for audit and diagnosis.

## Extension rule

New modules receive a policy-sealed context. They should reuse its HTTP, native network, tool, event,
and shared-data seams. A new raw client, resolver, process launcher, credential loader, or temporary
path is an architecture change and needs a ticket, threat review, negative tests, and gate evidence.
