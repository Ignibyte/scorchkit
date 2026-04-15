# Cloud-posture scanning (v2.2)

The cloud family is ScorchKit's fourth scanning family, parallel to DAST (`ScanModule`), SAST (`CodeModule`), and Infra (`InfraModule`). It runs posture audits against cloud control planes — AWS accounts, GCP projects, Azure subscriptions, and Kubernetes clusters — rather than against network endpoints or source trees.

**Status (WORK-150):** the trait surface, orchestrator, credentials, CLI wiring, and facade method are in place. The module registry is deliberately empty at this pipeline — concrete posture checks ship in WORK-151+ (Prowler as `CloudModule`, Scoutsuite, Kubescape, then a finding-normalization pass).

```
Family      Trait         Category enum     Target enum      Context            Orchestrator          URL scheme
------      -----         -------------     -----------      -------            ------------          ----------
DAST        ScanModule    (module-local)    Target           ScanContext        Orchestrator          https://
SAST        CodeModule    (module-local)    Target(file://)  CodeContext        CodeOrchestrator      file://
Infra       InfraModule   InfraCategory     InfraTarget      InfraContext       InfraOrchestrator     infra://
Cloud       CloudModule   CloudCategory     CloudTarget      CloudContext       CloudOrchestrator     cloud://
```

## Feature gate

All cloud-family code is behind `feature = "cloud"`. The default build omits it entirely — no orchestrator, no trait, no CLI subcommand, no `[cloud]` config section. Enable explicitly:

```bash
cargo build --features cloud
cargo test --features cloud
scorchkit cloud aws:123456789012
```

At WORK-150 there are no runtime dependencies behind the feature — just the type surface. Native SDK clients (`aws-sdk-*`, `google-cloud-rust`, `azure-sdk-for-rust`) land in WORK-151+ when specific modules need them.

## `CloudModule` trait

```rust
#[async_trait]
pub trait CloudModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> CloudCategory;
    fn description(&self) -> &str;
    async fn run(&self, ctx: &CloudContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
    fn providers(&self) -> &[CloudProvider] { &[] }
}
```

Shape mirrors `InfraModule` with one addition: `providers()` declares which cloud providers the module targets. Unlike the infra family (where protocol implies stack), cloud modules can span providers — a cross-cloud "publicly-readable object storage" check would declare `CloudCategory::Storage` and `providers() == &[Aws, Gcp, Azure]`.

## Two-axis classification

**`CloudCategory`** — posture scope (exactly one per module):

| Variant | Scope |
|---------|-------|
| `Iam` | Identity & access management — users, roles, policies, permission-boundary drift |
| `Storage` | Object/blob storage — public access, missing encryption, missing lifecycle |
| `Network` | VPC / security-group / firewall-rule drift, open-world ingress |
| `Compute` | EC2 / GCE / Azure VM misconfigurations |
| `Kubernetes` | RBAC, admission policies, pod SecurityContext, network policies |
| `Compliance` | Cross-cutting CIS / PCI-DSS / SOC2 / HIPAA benchmarks (bridge into v2.2 Compliance arc) |

**`CloudProvider`** — provider coverage (zero or more per module):

`Aws` · `Gcp` · `Azure` · `Kubernetes`

## `CloudTarget` — prefix-dispatched parser

Unlike `InfraTarget`'s shape-inference parser (CIDR / IP / endpoint / host), `CloudTarget::parse` requires an explicit prefix. Cloud IDs don't have distinguishing syntactic fingerprints — AWS 12-digit account IDs collide with port numbers, GCP project IDs are hostname-shaped, Azure subscription GUIDs are ambiguous. Explicit prefixes self-document intent and eliminate the ambiguity.

| Input | Variant |
|-------|---------|
| `aws:123456789012` | `Account("123456789012")` |
| `gcp:my-project` | `Project("my-project")` |
| `azure:abcd-1234-...` | `Subscription("abcd-1234-...")` |
| `k8s:prod-cluster` | `KubeContext("prod-cluster")` |
| `all` (case-insensitive) | `All` |

`display_raw()` round-trips `parse` for every form.

## `CloudContext` — deliberate absence of `http_client`

```rust
pub struct CloudContext {
    pub target: CloudTarget,
    pub config: Arc<AppConfig>,
    pub shared_data: Arc<SharedData>,
    pub events: EventBus,
    pub credentials: Option<Arc<CloudCredentials>>,
    // NOTE: no http_client field.
}
```

Unlike `InfraContext`, `CloudContext` does **not** carry a `reqwest::Client`. Cloud modules interact with cloud APIs through:

1. **Provider SDKs** — `aws-sdk-*`, `google-cloud-rust`, `azure-sdk-for-rust` — which manage their own HTTP clients with request signing, retry/backoff, and credential refresh built in.
2. **Tool-wrapper subprocesses** — Prowler, Scoutsuite, Kubescape — invoked via `subprocess::run_tool`.

Arbitrary `reqwest::Client` HTTP calls from cloud modules are out of scope for the v2.2 design. If a future module genuinely needs them (e.g., a cloud-metadata endpoint probe), it constructs its own client locally.

## `CloudCredentials` + `[cloud]` config block

Mirrors the `NetworkCredentials` pattern from WORK-146:

```toml
[cloud]
aws_profile = "production"
aws_role_arn = "arn:aws:iam::123456789012:role/ScorchKitAuditor"
aws_region = "us-east-1"
gcp_service_account_path = "~/.config/gcloud/sa.json"
gcp_project_id = "my-project-123"
azure_subscription_id = "abcd-1234-..."
azure_tenant_id = "efgh-5678-..."
kube_context = "prod-cluster"
```

All fields are `Option<String>` and default to `None`. The context carries `Option<Arc<CloudCredentials>>` — `None` when nothing is configured, so downstream code can short-circuit on `is_none()`.

**Env-var precedence** — each field has a matching `SCORCHKIT_*` env var (e.g., `SCORCHKIT_AWS_PROFILE`, `SCORCHKIT_KUBE_CONTEXT`). Env wins when set to a non-empty value; empty strings are treated as unset (matches WORK-146's CI-friendly semantics). See `CloudCredentials::from_config_with_env`.

**Secret-handling contract.** The `Debug` impl is hand-written (never `derive`). Today's eight fields are all identifiers — profile names, ARNs, region codes, paths, project/tenant/subscription IDs — that SDKs use to locate secrets elsewhere on disk. **The hand-written impl is mandatory anyway** so future direct-bearer fields (e.g., `aws_secret_access_key` in WORK-151+) are redacted from day one.

## `CloudOrchestrator`

Structural copy of `InfraOrchestrator` — same lifecycle events (`ScanStarted` → per-module `ModuleStarted` / `FindingProduced` / `ModuleCompleted` / `ModuleError` / `ModuleSkipped` → `ScanCompleted`), same semaphore-bounded concurrency (`config.scan.max_concurrent_modules`), same audit-log wiring via `subscribe_audit_log_if_enabled`. Returns the same `ScanResult` so reporting / storage / AI layers consume cloud scans unchanged.

The ~90% structural duplication with `InfraOrchestrator` is intentional at WORK-150. Refactoring both into a generic `Orchestrator<M: Module, C: Context, T: TargetLike>` is a follow-up pipeline scheduled for after the orchestrator count hits 3+ and a clearer generalization pattern emerges. The duplication is flagged in the module doc comment of `cloud_orchestrator.rs`.

**Empty-registry contract.** `cloud::register_modules()` returns `vec![]` at WORK-150. The orchestrator handles this cleanly — the `for module in runnable {}` loop is skipped and `ScanStarted` + `ScanCompleted` still fire. Pinned by `test_cloud_orchestrator_empty_module_list`.

## CLI

```
scorchkit cloud <target> [--profile quick|standard] [--modules a,b,c] [--skip x,y]
```

`--profile quick` keeps only `CloudCategory::Iam` modules (fastest, no resource enumeration). `--profile standard` (default) keeps everything registered.

Unified assessment extends to four families:

```
scorchkit assess --url https://example.com --code ./src --infra 192.0.2.1 --cloud aws:123456789012
```

At least one of `--url` / `--code` / `--infra` / `--cloud` is required. The four orchestrators run concurrently via `tokio::join!`; per-domain failures are logged and skipped so partial results still return. Merge priority: DAST → SAST → Infra → Cloud.

## `Engine::cloud_scan`

```rust
let engine = Engine::new(Arc::new(AppConfig::default()));
let result = engine.cloud_scan("aws:123456789012").await?;
println!("findings: {}", result.findings.len());
```

Parses the target, constructs a `CloudContext` (with credentials resolved from config + env), runs the orchestrator. Available with `feature = "cloud"`.

## `Engine::full_assessment` — always-present `cloud_target` parameter

```rust
engine.full_assessment(
    Some("https://example.com"),
    Some(Path::new("./src")),
    Some("192.0.2.1"),
    Some("aws:123456789012"),  // <-- new in WORK-150
).await?;
```

The `cloud_target: Option<&str>` parameter is always present in the signature — not `#[cfg]`-gated — so callers don't need their own `#[cfg(feature = "cloud")]` wrappers around every call site. Passing `Some(_)` when the `cloud` feature is **off** returns a `ScorchError::Config` at call time.

## Synthetic `cloud://` URL scheme

`Target::from_cloud(raw)` wraps cloud targets in a `cloud://` URL for the `ScanResult.target` field, so reporting / storage / AI layers consume cloud-scan results identically to DAST / SAST / Infra scans. The `raw` field preserves the original operator input (`aws:123...`). Percent-encoding handles the `:` separator cleanly; parses via `Url::parse`.

## Relationship with existing tool wrappers

Prowler, Scoutsuite, Kubescape, and Dockle already ship as `CodeModule` wrappers under `sast_tools/`. WORK-150 **does not** move them — it ships the seam. WORK-151 reshapes Prowler as a `CloudModule` (AWS coverage), WORK-152 does Scoutsuite (multi-cloud), WORK-153 does Kubescape (K8s). WORK-154 normalizes finding shapes across the three and adds CPE extraction + compliance tagging. The existing `sast_tools/` wrappers stay available for operators who want the raw SAST-style invocation.

## Concrete modules

### `prowler-cloud` (WORK-151) — AWS posture audit

First concrete populator of the cloud registry. Wraps the `prowler` binary for AWS-account posture audits — CIS AWS Foundations plus 400+ checks across IAM, S3, EC2, CloudTrail, KMS, VPC. Module id `"prowler-cloud"` (distinct from the existing DAST `tools::prowler` wrapper's `"prowler"`); `CloudCategory::Compliance` × `CloudProvider::Aws`.

- **Argv layout:** `aws -M json-ocsf --no-banner -q [-p <profile>] [-R <region>] [--role-arn <arn>]` — deterministic field order so golden-byte tests are stable.
- **Subprocess strategy:** `run_tool_lenient` (Prowler 4.x with `output.exit_code_on_fail: true` returns exit 3 on FAIL findings; strict `run_tool` would abort).
- **Target validation:** `CloudTarget::Project` / `Subscription` / `KubeContext` rejected with operator-actionable pointers to WORK-152 / WORK-153. `CloudTarget::All` requires `aws_profile` or `aws_role_arn` configured to prevent silent fallthrough to the AWS CLI default.
- **Findings:** tagged `module_id = "prowler-cloud"`, OWASP A05, CWE-1188 (Insecure Default), confidence 0.8. Evidence carries `provider:aws | service:<name> | severity:<str> | target:<label>` for downstream filtering.
- **OCSF parser duplication:** intentional. ~80 lines mirror `tools::prowler::parse_prowler_output` shape. Cloud findings carry the `provider:aws` evidence tag the DAST findings don't, so a shared parser would force a generic finding-builder closure parameter. Extraction deferred to WORK-154 once Scoutsuite (WORK-152) materializes as the second consumer.

Operator docs: `docs/modules/cloud-prowler.md`.

## Future work

- **WORK-152**: Scoutsuite as `CloudModule` (multi-cloud) — also the trigger point for extracting a shared OCSF parser
- **WORK-153**: Kubescape as `CloudModule` (cluster posture)
- **WORK-154**: Finding-shape normalization + cross-wrapper CPE/compliance tagging + per-check CWE mapping
- **Deferred**: Generic `Orchestrator<M, C, T>` refactor — unify `Orchestrator` / `CodeOrchestrator` / `InfraOrchestrator` / `CloudOrchestrator` once the pattern has more signal
- **v2.3+ polish**: Native Rust AWS/GCP/Azure SDK clients replacing the Prowler subprocess path for hot-path checks
