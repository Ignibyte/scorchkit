# Cloud posture scanning

The cloud family audits AWS accounts, GCP projects, Azure subscriptions, and Kubernetes contexts. It
uses a logical cloud target rather than a URL, filesystem path, or network endpoint and is available
through the `cloud` Cargo feature.

```bash
cargo build --release --features cloud
scorchkit cloud aws:123456789012 --profile quick
```

The engagement must contain an exact cloud scope rule for the target and grant `cloud-scan/passive`,
`credential-use/passive`, and `external-tool/passive`. The future exploit-oriented Pacu module is not
registered in safe profiles and would require explicit exploit grants.

## Target forms

| Input | Meaning |
|---|---|
| `aws:123456789012` | AWS account |
| `gcp:my-project` | GCP project |
| `azure:subscription-id` | Azure subscription |
| `k8s:context-name` | Kubernetes context |
| `all` | every provider configured in the credential context |

Explicit prefixes prevent account IDs, project names, subscription IDs, and host-like strings from
being confused with network targets.

## Context

```rust
pub struct CloudContext {
    pub target: CloudTarget,
    pub config: Arc<AppConfig>,
    pub shared_data: Arc<SharedData>,
    pub events: EventBus,
    pub credentials: Option<Arc<CloudCredentials>>,
    // private bounded executor and authorization proof
}
```

Production code obtains this type through `Engine::cloud_context`; its constructor is crate-private.
The engine authorizes the logical target, capability, effects, and credential use before resolving
credentials or constructing provider clients and processes.

`CloudContext` deliberately has no arbitrary public HTTP client. Production modules use the shared
bounded tool executor. A new provider transport must classify and authorize authentication and
service endpoints separately rather than inheriting the cloud-account grant.

## Registry

Five wrappers are present whenever `cloud` is enabled:

| Module | Provider coverage |
|---|---|
| `cloudsplaining-cloud` | AWS IAM policy analysis |
| `cnspec-cloud` | multi-provider posture |
| `kubescape-cloud` | Kubernetes |
| `prowler-cloud` | AWS |
| `scoutsuite-cloud` | AWS, GCP, Azure |

The production registry contains exactly five modules, all of which use the context-owned executor.
Twelve native implementations exist behind the `aws-native`, `gcp-native`, and `azure-native`
features, four per provider. They compile only in tests and are private to the crate. Their SDK
clients can perform provider authentication and service requests outside ScorchKit's per-address
network policy, so they remain quarantined until that transport boundary is implemented. Pacu also
exists as a type but is not registered because the current safe profiles do not grant its exploit
effects.

## Credentials

`CloudCredentials::from_config_with_env` resolves optional AWS profile/role/region, GCP service
account/project, Azure subscription/tenant, and Kubernetes context. Nonempty `SCORCHKIT_*`
environment variables override TOML. Empty environment values are treated as unset.

Credentials remain indirect wherever the provider or tool supports it. ScorchKit passes profile
names, roles, project IDs, paths, and contexts to bounded tools. Debug rendering is manually redacted
so later direct-secret fields cannot leak by deriving `Debug`.

## Execution and findings

`CloudOrchestrator` filters modules by provider, category, ID, and profile; emits the common lifecycle
events; and returns `ScanResult` with a synthetic `cloud://` target. Runnable modules pass through
the shared job executor for bounded concurrency, a batch wall-time budget, caller cancellation, and
stable outcomes. See [executor.md](executor.md).

All modules normalize evidence through `CloudEvidence`. Service-specific mapping assigns OWASP, CWE,
and compliance controls rather than labeling every cloud problem as generic misconfiguration. Raw
provider/tool details stay attached to the finding.

The quarantined native checks retain pure conversion and control-evaluation tests without requiring
cloud accounts. Those tests preserve the implementation while the transport is replaced, but they
do not make the modules production-supported. Access-denied conditions are never treated as proof
that a control passed.

## Tool adapters

Cloudsplaining, cnspec, Kubescape, Prowler, and Scout Suite execute through `CloudContext` with bounded
timeout, output, exit handling, process-tree cleanup, and credential/profile-specific arguments.
Provider fan-out is sequential where concurrent calls could exceed service quotas.

## Library use

```rust
let context = engine.cloud_context("aws:123456789012")?;
let mut orchestrator = scorchkit::runner::cloud_orchestrator::CloudOrchestrator::new(context);
orchestrator.register_default_modules();
orchestrator.apply_profile("quick");
let result = orchestrator.run(false).await?;
```

The `engine` must carry a matching engagement. Direct context and raw native client construction are
not public integration APIs.

## Follow-on work

- Replace duplicated tool parsers and finding builders in SK-034.
- Add stable evidence/report schema versions in SK-035.
- Restore native provider modules only after authentication and service requests use a policy-owned
  transport with endpoint, DNS-answer, redirect, metadata-denial, and credential-boundary tests.
