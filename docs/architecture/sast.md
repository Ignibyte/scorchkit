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
  (1)   (21)                   (10)       (35)          (45)                    (5)
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
- `language: Option<String>` — compatibility primary language
- `languages: Vec<String>` — every explicit or root-manifest-detected language
- `manifests: Vec<PathBuf>` — discovered lockfiles / manifests
- `config: Arc<AppConfig>`
- `shared_data: Arc<SharedData>` — same inter-module store as DAST
- `events: EventBus` — same lifecycle event bus as DAST
- `tool_executor: Arc<dyn ToolExecutor>` — shared, injectable bounded-process boundary

### `CodeCategory` enum

- `Sast` — security-oriented source analysis (Semgrep, CodeQL, Psalm, Bandit, Gosec, ESLint-security, Slither, Brakeman, Snyk-code)
- `Correctness` — static correctness and type analysis that does not claim vulnerability coverage (PHPStan)
- `Sca` — software composition analysis (cargo-audit, cargo-deny, Snyk-test, dep-audit); ordered
  OSV/Grype coverage lives in the supply-chain service
- `Secrets` — secret detection (Gitleaks)
- `Iac` — infrastructure as code (Checkov, Hadolint, TFLint, KICS, Kubescape)
- `Container` — local container artifact analysis (Dockle) plus the explicit ScoutSuite
  cloud-account compatibility adapter

### `Target::from_path()`

Constructs a `Target` with `file://` URL scheme from a filesystem path. This enables reuse of `ScanResult` and all downstream infrastructure (reports, storage, AI) without duplication.

## Built-in SAST Modules (`sast/`)

| ID | Purpose |
|----|---------|
| `dep-audit` | Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, `go.sum`. Flags duplicate package versions, unpinned dependencies, and known-risky / compromised packages from a curated 11-entry list (event-stream, ua-parser-js, colors, faker, node-ipc, PyPI typosquats). Works with zero external tools. |

## External SAST Tool Wrappers (`sast_tools/`)

21 wrappers are registered in `sast_tools::register_modules()`.

The default code catalog contains 20 of these wrappers plus the native dependency analyzer.
`scoutsuite` remains registered but requires an explicit module-ID selection because it assesses a
cloud account rather than application source or artifacts.

| Tool | Category | Languages | Output Format | Exit Code |
|------|----------|-----------|---------------|-----------|
| Semgrep | Sast, fast | multi | JSON (`results`) | strict |
| CodeQL | Sast, deep | JavaScript/TypeScript, Python, Ruby | SARIF | strict |
| Gitleaks | Secrets | any | JSON array | non-zero on findings |
| Bandit | Sast | python | JSON | non-zero on findings |
| Gosec | Sast | go | JSON | non-zero on findings |
| Checkov | Iac | terraform/cloudformation/k8s/dockerfile | JSON | non-zero on findings |
| Hadolint | Iac | dockerfile | JSON | non-zero on findings |
| ESLint-security | Sast | javascript/typescript | JSON | non-zero on findings |
| PHPStan | Correctness, fast | php | JSON | non-zero on findings |
| Psalm | Sast, deep | php | SARIF | non-zero on findings |
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

The legacy OSV Scanner and Grype wrapper types remain readable for source compatibility but are not
registered. Production application scans use the ordered offline supply-chain service so source
lockfiles, the exact validated SBOM, provider snapshot health, and artifact consumers cannot be
silently reordered or separated. See [Application supply-chain evidence](application-supply-chain.md).

Tools that exit non-zero for "findings found" use `ctx.run_tool_lenient()`. Strict tools use
`ctx.run_tool()`. File-producing deep analyzers use the same context-owned invocation seam with a
working directory, bounded output, scoped artifacts, and a bounded report read. CodeQL uses an
owned database-create step followed by offline analysis. Psalm writes one owned SARIF report.

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
| `Gemfile` / `Gemfile.lock` | ruby |
| `composer.json` / `composer.lock` | php |

Detection records every language represented by a root manifest. Override with `--language <lang>`
to select one explicit language. Language-specific modules stay visible through selection and emit a
typed `not_applicable` outcome when they do not match. Language-agnostic modules remain eligible.

## Profiles

| Profile | Modules | Use Case |
|---------|---------|----------|
| quick | Secrets + SCA only | CI gate, fast checks |
| standard | Fast application code modules whose language matches | Frequent application analysis |
| thorough | Fast plus deep application code modules | Release and deep review |
| pentest | Fast plus deep application code modules | Code side of an authorized application pentest |

All implicit code profiles exclude `scoutsuite`. An explicit `--modules scoutsuite` selection keeps
the compatibility adapter available and still requires the normal code-path, credential, process,
and effect authorization. A valid explicit ID can also select CodeQL or Psalm under another valid
profile. Unknown profiles clear the selection.

## Outcomes and flow evidence

`ScanResult.module_outcomes` records one typed `ran`, `not_applicable`, `skipped`, or `failed`
state for every selected code module. The legacy `modules_run` and `modules_skipped` fields remain
available. Unsupported languages are evaluated before executable lookup so a missing unrelated tool
cannot hide an applicability result.

CodeQL and Psalm share one strict SARIF decoder. Semgrep converts its optional taint trace into the
same code-flow model. Findings retain independent flow paths and ordered steps, redacted
scanner-native structured evidence, rule or query identity, scanner/configuration provenance, and
confidence. Flows enrich evidence without changing stable finding identity. SARIF reports project
the same flow structure back to `codeFlows`.

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
