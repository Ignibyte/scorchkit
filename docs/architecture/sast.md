# SAST Architecture

ScorchKit's SAST (Static Application Security Testing) system operates as a parallel scanning pipeline alongside the DAST (Dynamic Application Security Testing) system and the Infra family. All three share the same `Finding` type, report formats, and storage layer, but differ in their input model and module traits.

## Architecture Decision

**Decision:** Parallel `CodeModule` trait, NOT extending `ScanModule`.

**Rationale:** `ScanModule::run` takes `&ScanContext` which contains an HTTP client and URL-based `Target`. SAST operates on file paths, not URLs, and doesn't need an HTTP client. Forcing SAST through the DAST interface would mean every SAST module ignores half its context. Clean separation means each side can evolve independently.

**Date:** 2026-04-13. Expanded in v1.1–v2.1 with the `sast_tools` batch (2 → 21 tool wrappers) and the `dep-audit` built-in. The same separation principle later justified the `InfraModule` family; see [infra.md](infra.md).

## System Overview

```
CLI: scorchkit code <path>          CLI: scorchkit run <url>           CLI: scorchkit infra <target>
         │                                    │                                    │
    CodeOrchestrator                    Orchestrator                       InfraOrchestrator
         │                                    │                                    │
    CodeModule trait                   ScanModule trait                  InfraModule trait
    CodeContext (path)                 ScanContext (URL + HTTP)          InfraContext (IP/CIDR/host)
         │                                    │                                    │
    ┌────┼────────┐              ┌────────────┼────────────┐                       │
    │    │        │              │            │            │                       │
  sast  sast_tools             recon      scanner       tools                   infra
  (1)   (21)                   (10)       (35)          (46)                    (5)
         │                                    │                                    │
         └────────────────────────────────────┴────────────────────────────────────┘
                                              │
                                         Vec<Finding>
                                              │
                                     ┌────────┼────────┐
                                     │        │        │
                                  Reports   Storage   AI Analysis
```

The unified `scorchkit assess --url ... --code ... --infra ...` command drives all three orchestrators concurrently. See [assess.md](assess.md).

## Key Types

### `CodeModule` trait (`engine/code_module.rs`)

Parallel to `ScanModule`. Adds `languages()` method for language-aware filtering and drops the HTTP client requirement. See [modules.md](modules.md) for the full trait definition.

### `CodeContext` (`engine/code_context.rs`)

- `path: PathBuf` — root directory to scan
- `language: Option<String>` — auto-detected from manifest files
- `manifests: Vec<PathBuf>` — discovered lockfiles / manifests
- `config: Arc<AppConfig>`
- `shared_data: Arc<SharedData>` — same inter-module store as DAST
- `events: EventBus` — same lifecycle event bus as DAST
- `tool_executor: Arc<dyn ToolExecutor>` — shared, injectable bounded-process boundary

### `CodeCategory` enum

- `Sast` — static code analysis (Semgrep, Bandit, Gosec, PHPStan, ESLint-security, Slither, Brakeman, Snyk-code)
- `Sca` — software composition analysis (OSV-Scanner, Grype, cargo-audit, cargo-deny, Snyk-test, dep-audit)
- `Secrets` — secret detection (Gitleaks)
- `Iac` — infrastructure as code (Checkov, Hadolint, TFLint, KICS, Kubescape)
- `Container` — container image / cloud-posture scanning (Grype, Dockle, ScoutSuite)

### `Target::from_path()`

Constructs a `Target` with `file://` URL scheme from a filesystem path. This enables reuse of `ScanResult` and all downstream infrastructure (reports, storage, AI) without duplication.

## Built-in SAST Modules (`sast/`)

| ID | Purpose |
|----|---------|
| `dep-audit` | Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, `go.sum`. Flags duplicate package versions, unpinned dependencies, and known-risky / compromised packages from a curated 11-entry list (event-stream, ua-parser-js, colors, faker, node-ipc, PyPI typosquats). Works with zero external tools. |

## External SAST Tool Wrappers (`sast_tools/`)

21 wrappers, registered in `sast_tools::register_modules()`.

| Tool | Category | Languages | Output Format | Exit Code |
|------|----------|-----------|---------------|-----------|
| Semgrep | Sast | multi | JSON (`results`) | 0 always |
| OSV-Scanner | Sca | multi | JSON (`results.packages.vulnerabilities`) | non-zero on findings |
| Gitleaks | Secrets | any | JSON array | non-zero on findings |
| Bandit | Sast | python | JSON | non-zero on findings |
| Gosec | Sast | go | JSON | non-zero on findings |
| Checkov | Iac | terraform/cloudformation/k8s/dockerfile | JSON | non-zero on findings |
| Grype | Sca / Container | any | JSON | non-zero on findings |
| Hadolint | Iac | dockerfile | JSON | non-zero on findings |
| ESLint-security | Sast | javascript/typescript | JSON | non-zero on findings |
| PHPStan | Sast | php | JSON | non-zero on findings |
| Snyk-test | Sca | multi (auto) | JSON | non-zero on findings |
| Snyk-code | Sast | multi (auto) | JSON | non-zero on findings |
| cargo-audit | Sca | rust | JSON | non-zero on findings |
| cargo-deny | Sca | rust | JSON | non-zero on findings |
| TFLint | Iac | terraform | JSON | non-zero on findings |
| KICS | Iac | tf/cf/k8s/docker/helm/ansible/pulumi/openapi/grpc | JSON | non-zero on findings |
| Slither | Sast | solidity | JSON | non-zero on findings |
| Brakeman | Sast | ruby (rails) | JSON | non-zero on findings |
| Dockle | Container | docker image | JSON | non-zero on findings |
| Kubescape | Iac | kubernetes | JSON | non-zero on findings |
| ScoutSuite | Container | aws/gcp/azure/alicloud/oci | JSON | non-zero on findings |

Tools that exit non-zero for "findings found" use `ctx.run_tool_lenient()`. Strict tools use
`ctx.run_tool()`. Both methods create an owned invocation with a timeout and 8 MiB per-stream limit.

`CodeOrchestrator` submits runnable modules to the shared job executor. The executor enforces
`max_concurrent_modules`, a batch wall-time budget, caller cancellation, and submission-ordered
outcomes. Post-module hooks and finding events consume that stable list. See
[executor.md](executor.md).

## Language Detection

Auto-detects from manifest files in the scan root:

| Manifest | Language |
|----------|----------|
| `Cargo.toml` | rust |
| `package.json` | javascript |
| `go.mod` | go |
| `requirements.txt` / `pyproject.toml` | python |
| `pom.xml` / `build.gradle` | java |
| `Gemfile.lock` | ruby |
| `composer.lock` | php |

Override with `--language <lang>`. Language-filtered modules (e.g. Bandit for python, Gosec for go) run only when the detected / forced language matches. Language-agnostic modules (Gitleaks, OSV-Scanner, dep-audit, Grype) always run.

## Profiles

| Profile | Modules | Use Case |
|---------|---------|----------|
| quick | Secrets + SCA only | CI gate, fast checks |
| standard | All SAST tools whose language matches | Comprehensive code analysis |
| thorough | All SAST tools, unfiltered | Cross-language monorepo sweep |

## Security: Evidence Redaction

Gitleaks findings redact secret values in evidence output. Only the first 8 characters are shown, followed by `...`. This prevents HTML / JSON / PDF reports from leaking exposed credentials.

## Combined DAST + SAST

`scorchkit run <url> --code <path>` runs DAST and SAST concurrently (`tokio::join!`) and merges findings into a single `ScanResult`. SAST failure is non-fatal — DAST results always return. The `Engine::full_scan(url, code_path)` facade method is the library equivalent. For a three-way DAST + SAST + Infra composition, see [assess.md](assess.md).

## Cross-Domain Correlation

`report::correlate_attack_chains()` runs six rule-based correlations that pair a DAST finding with a SAST finding:

1. Confirmed SQL injection (SAST rule + DAST runtime probe)
2. Hardcoded secrets + runtime exposure
3. Vulnerable dependency + exploitable endpoint
4. IaC misconfiguration + runtime misconfig
5. Auth bypass (code-side weakness + runtime bypass)
6. Supply chain risk (risky package + missing CSP)

The `is_sast_module()` helper classifies finding origins so the correlator only pairs across domains.
