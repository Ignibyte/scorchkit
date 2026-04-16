# `kubescape-cloud` — Kubernetes Cluster Posture (WORK-153)

Third concrete `CloudModule`. Wraps the `kubescape` binary against a **live Kubernetes cluster** via kubeconfig context. Module id `"kubescape-cloud"`; `CloudCategory::Kubernetes` × `CloudProvider::Kubernetes`.

## Quick start

```bash
# Install Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Scan the current kubeconfig context against any explicit context
scorchkit cloud k8s:prod-cluster
scorchkit cloud k8s:staging
```

## Configuration

```toml
[cloud]
kube_context = "prod-cluster"
```

Or via env var:

```bash
SCORCHKIT_KUBE_CONTEXT=prod-cluster scorchkit cloud all
```

Only `kube_context` is consulted by this module. Other `CloudCredentials` fields (AWS / GCP / Azure) are ignored — for those clouds use `prowler-cloud` (WORK-151) or `scoutsuite-cloud` (WORK-152).

## Target forms

| Target | Behavior |
|--------|----------|
| `k8s:<context>` | Scan the explicit context; **target value overrides any `kube_context` config** |
| `all` | Scan the configured `kube_context`; errors if `kube_context` is unset |
| `aws:<account>` | **Rejected** — use `prowler-cloud` (WORK-151) |
| `gcp:<project>` | **Rejected** — use `scoutsuite-cloud` (WORK-152) |
| `azure:<sub>` | **Rejected** — use `scoutsuite-cloud` (WORK-152) |

## What gets checked

Kubescape evaluates the live cluster against four built-in frameworks:

- **NSA** — National Security Agency Kubernetes Hardening Guidance
- **MITRE** — MITRE ATT&CK for Kubernetes
- **ArmoBest** — Armo's curated defaults
- **CIS Kubernetes Benchmark** — Center for Internet Security baseline

Each `failed` control with a `scoreFactor` lands as a ScorchKit `Finding`.

## Finding shape

| Field | Value |
|-------|-------|
| `module_id` | `"kubescape-cloud"` |
| `severity` | `scoreFactor` mapped: `>= 7.0` → High, `>= 4.0` → Medium, else Low |
| `title` | `"kubescape <controlID>: <name>"` |
| `description` | `"Control <id> (<name>) failed against the live cluster"` |
| `affected_target` | `"cloud://k8s:<context>"` |
| `evidence` | `"provider:kubernetes \| controlID:<id> \| score:<n> \| target:<label>"` |
| `remediation` | `"Review the Kubescape control documentation for remediation steps."` |
| `owasp_category` | `"A05:2021 Security Misconfiguration"` |
| `cwe_id` | `1188` (Insecure Default) |
| `confidence` | `0.9` |

Severity mapping is at parity with `sast_tools::kubescape::parse_kubescape_output` so finding shapes match between the on-disk-manifest path and the live-cluster path.

## Comparison with the SAST `sast_tools::kubescape` wrapper

| | `sast_tools::kubescape` (SAST) | `cloud::kubescape` (Cloud) |
|---|---|---|
| Module id | `kubescape` | `kubescape-cloud` |
| Trait | `CodeModule` | `CloudModule` |
| Subcommand | `scorchkit code <path>` | `scorchkit cloud k8s:<ctx>` |
| Scan target | YAML manifests on disk | Live cluster via kubeconfig |
| CLI family gate | always compiled | `feature = "cloud"` |
| Provider tag in evidence | none | `provider:kubernetes` |
| CWE | none | 1188 |
| Subprocess strategy | `run_tool_lenient` (3-min) | `run_tool_lenient` (10-min) |
| Introduced | WORK-114 batch | WORK-153 |

## Testing

`src/cloud/kubescape.rs` ships 11 unit tests:

- argv builder happy paths (3) — explicit `KubeContext` target, target-overrides-config, `All` with config
- argv builder errors (5) — `All` without context, empty-string context, AWS / GCP / Azure rejection with cross-pipeline pointers
- JSON parser (2) — failed/passed mix with severity scoring + provider tag pin; empty/invalid input
- Module trait surface (1) — id / category / providers / required_tool

Live smoke against a real cluster is deferred to WORK-154 normalization.

## Follow-up work

- **WORK-154** — Cross-cloud finding-shape normalization + per-control CWE/compliance mapping (CIS Kubernetes → CIS Benchmarks export format)
