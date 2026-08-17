# Changelog

All notable changes to ScorchKit will be documented in this file.

## [Unreleased]

### Added
- **Durable scan job lifecycle (TICKET-003 / SK-029)** — Added provider-neutral queued, running,
  cancelling, terminal, interruption, and successor-attempt contracts; bounded reliable
  module-progress persistence; shared cancellation; ownership leases and repeated recovery;
  in-memory and transactional PostgreSQL stores with append-only revision audit; CLI job commands;
  asynchronous MCP job tools; and stateless MCP startup without a database. Existing synchronous
  MCP scans remain compatible through the same lifecycle.
- **Repository-owned delivery pipeline (TICKET-001)** — Added numbered tickets, EARS specs, phase
  evidence, adversarial inspection, AARs, an exact-worktree delivery receipt, Git pre-commit
  enforcement, a Codex repository skill, and stable quality gates 1–22. The workflow is agent-neutral
  and keeps Codex as the preferred development host.
- **Fail-closed engagement policy** — Added canonical target, capability, and effect authorization at
  the facade, CLI, MCP, project, schedule, network, filesystem, credential, cloud, and subprocess
  boundaries. HTTP redirects, DNS answers, native protocol connections, and WebSocket handshakes are
  reauthorized before an effect occurs.
- **Shared bounded tool executor** — Added typed invocations, explicit exit policy, timeouts, 8 MiB
  per-stream limits, injectable test execution, and Unix process-group cleanup for 45 DAST and 21
  SAST one-shot adapters. Interactsh uses the same process owner through its session lifecycle.
- **Focused mutation repair workflow** — Preserved the broad survivor inventory, extracted 42
  observable seams across 14 files, and reran only those repaired functions. The final focused
  repair result caught 162/162 viable mutations with nine unviable variants. A post-archive
  process-exit repair then caught all five viable mutants in its two-function scope, with one
  unviable variant, for cumulative evidence of 167/167 viable caught. Full-repository mutation is a
  scheduled campaign rather than an automatic rerun after each repair. Added an explicit
  focused-repair delivery mode that verifies raw outcomes, mutation-input identity, and evidence
  integrity, including a one-file old-to-new transition proof for later focused repairs, reruns
  every non-mutation delivery lane, and records the mode and evidence digest in the exact-worktree
  receipt.

- **v3.0 Final — Attack-chain reporter + Executive dashboard + Remediation walks + Multi-AI (WORK-139, 140, 141, 142)** — `report::attack_chain` with `format_attack_chains()` (text), `render_mermaid()` (Mermaid flowchart diagrams), `render_mermaid_html()` (standalone HTML with Mermaid.js). `report::dashboard` with `build_dashboard()` producing `Dashboard` struct (risk grade A-F, severity counts, top-5 findings, compliance summary) + `format_dashboard()` ASCII art. `ai::remediation` with `build_remediation_walk()` (risk-ordered fix sequence with effort estimation) + `build_remediation_prompt()` for Claude-guided remediation. `ai::provider` with abstract `AiProvider` trait + `ClaudeCliProvider` + `NoOpProvider` fallback + `default_provider()` selector. Tests: default **696** (+16 new). (WORK-139, 140, 141, 142)

- **v3.0 Correlation engine + AI correlator + Risk scoring (WORK-136, 137, 138)** — New `engine::correlation` module with `AttackChain`/`ChainStep` types and `correlate()` function with 14 built-in rules covering web app chains (XSS+CSP, SQLi+DB, SSRF+cloud), DAST+SAST cross-confirmation (code+runtime SQLi, secrets exposure, auth bypass, vulnerable deps), cloud-specific chains (IAM escalation, data exfiltration, network breach+weak auth, logging blind spots), and recon chains (subdomain takeover, exposed secrets). New `ai::correlator` with `build_correlation_prompt()`, `parse_correlation_response()`, and `correlate_with_ai()` that merges AI-discovered chains with rule-based (graceful fallback). New `engine::risk_score` with multi-factor `compute_risk_score()` (severity 0-40 + confidence 0-20 + exposure 0-20 + compliance impact 0-20 = 0-100), `rank_findings()`, and `risk_grade()`. Tests: default **680** (+23 new). (WORK-136, 137, 138)

- **Compliance profiles + reporter — CIS, PCI-DSS, SOC2, HIPAA (WORK-132, 133, 134, 135)** — 3 CIS benchmark framework implementations (`CisDockerFramework` 19 controls, `CisKubernetesFramework` 16 controls, `CisAwsFramework` 21 controls) added to the compliance engine. Compliance reporter with `format_compliance_report()` for human-readable terminal output and `compliance_report_to_json()` for structured JSON. Registry grows from 4 to 7 frameworks. CIS AWS matches Prowler-native `CIS-*` compliance tags. Tests: default **657** (+7 new). (WORK-132, 133, 134, 135)

- **Compliance engine foundation — `ComplianceFramework` trait + rule registry (WORK-131)** — New `engine::compliance_framework` module with `ComplianceFramework` trait, `Control`/`ControlMatch`/`ControlStatus` types, `ComplianceRegistry`, and `assess_compliance()` function that evaluates findings against registered frameworks to produce per-framework `ComplianceReport` with pass/fail per control and compliance percentage. 4 built-in frameworks: NIST 800-53 Rev 5 (16 controls), PCI-DSS 4.0 (11 controls), SOC 2 TSC (5 controls), HIPAA Security Rule (7 controls). Builds on WORK-154 compliance tags — findings enriched by `enrich_cloud_finding()` are automatically matched. Tests: default **650** (+8 new). (WORK-131)

- **Prowler deep integration + cloud tool wrappers (WORK-129, WORK-130)** — Enhanced Prowler OCSF parser to extract per-control compliance IDs (CIS, PCI-DSS, NIST) from Prowler's `compliance` field and merge with WORK-154 enrichment controls. 3 new cloud tool wrappers: `cnspec-cloud` (Mondoo cloud security), `pacu-cloud` (Rhino Security AWS exploitation recon for authorized testing), `cloudsplaining-cloud` (Salesforce IAM least-privilege auditor). Cloud tool-wrapper registry grows from 3 → 6. Tests: `--features cloud` **728** (+14 new). (WORK-129, WORK-130)

- **Azure native cloud checks — RBAC / Storage / NSG / Key Vault (WORK-128)** — 4 built-in Azure cloud modules using `azure_identity` (`DefaultAzureCredential`) + reqwest REST calls to ARM endpoints, behind new `azure-native` feature flag. `AzureRbacCloudModule` (subscription-level Owner sprawl), `AzureStorageCloudModule` (public access, infrastructure encryption, soft delete), `AzureNsgCloudModule` (open management ports), `AzureKeyVaultCloudModule` (purge protection, soft delete, public network access). Tests: `--features azure-native` **729** (+15 new). (WORK-128)

- **GCP native cloud checks — IAM / GCS / Firewall / Audit Logs (WORK-127)** — 4 built-in GCP cloud modules using `google-cloud-auth` + reqwest REST calls, behind new `gcp-native` feature flag. `GcpIamCloudModule` (user-managed service account keys), `GcsCloudModule` (public access prevention, CMEK encryption, uniform bucket-level access), `GcpFirewallCloudModule` (0.0.0.0/0 ingress on sensitive ports, default-rule awareness), `GcpAuditCloudModule` (allServices audit log completeness). Same two-layer architecture as AWS: auth token → REST API → intermediate types → pure check functions. Tests: `--features gcp-native` **731** (+17 new). (WORK-127)

- **AWS native cloud checks — IAM / S3 / Security Groups / CloudTrail (WORK-126)** — First native-Rust cloud modules using `aws-sdk-rust`, behind new `aws-native` feature flag (depends on `cloud`). 4 modules: `IamCloudModule` (root access keys, MFA, password policy), `S3CloudModule` (public access, encryption, versioning, logging), `SecurityGroupCloudModule` (0.0.0.0/0 ingress on 11 sensitive ports), `CloudTrailCloudModule` (multi-region, KMS encryption, log validation, active logging). Two-layer architecture: thin async `run()` calls AWS SDK, converts to intermediate types; pure check functions take intermediates and return findings. All findings use `CloudEvidence` + `enrich_cloud_finding()` (WORK-154) for per-service OWASP/CWE/compliance. Credential resolution via standard AWS chain (env → shared config → IMDS) with optional ScorchKit `aws_profile`/`aws_region` overrides. `AccessDenied` → Info finding (graceful degrade). New Cargo deps: `aws-config`, `aws-sdk-iam`, `aws-sdk-s3`, `aws-sdk-ec2`, `aws-sdk-cloudtrail` (all optional). Cloud registry grows from 3 → 7 modules with `aws-native`. Tests: default 642 (unchanged); `--features cloud` 714 (unchanged); `--features aws-native` **738** (+24 new). (WORK-126)

- **Cloud finding normalization — common evidence builder + compliance extraction (WORK-154)** — Replaces freeform pipe-delimited evidence strings and blanket `A05:2021 / CWE-1188` across all 3 cloud modules with structured types and per-service compliance mapping. New `engine::cloud_evidence::CloudEvidence` struct with typed fields (`provider`, `service`, `check_id`, `resource`, `detail: BTreeMap`) and `Display` impl that serializes to the existing pipe-delimited format for backward compatibility. New `engine::cloud_evidence::enrich_cloud_finding()` function maps cloud services to appropriate OWASP / CWE pairs (IAM→A01/CWE-287, storage→A01/CWE-200, compute→A05/CWE-16, network→A05/CWE-284, logging→A09/CWE-778, crypto→A02/CWE-311, unknown→A05/CWE-1188 fallback) and auto-populates `Finding.compliance` via existing `compliance_for_owasp` / `compliance_for_cwe` lookups (NIST 800-53, PCI-DSS 4.0, SOC2 TSC, HIPAA). All 3 cloud modules (`prowler-cloud`, `scoutsuite-cloud`, `kubescape-cloud`) updated. New CWE mappings in `compliance.rs`: CWE-16 (Configuration), CWE-284 (Improper Access Control), CWE-778 (Insufficient Logging). Tests: default 642 (+1); `--features cloud` 714 (+12 new tests — 11 regression plan + 1 bonus). Zero fix iterations in validation. (WORK-154)

- **Kubescape as `CloudModule` — K8s cluster posture (WORK-153)** — Third concrete cloud module after WORK-151 Prowler and WORK-152 Scoutsuite. New `cloud::kubescape::KubescapeCloudModule` (module id `"kubescape-cloud"`, distinct from the existing `sast_tools::kubescape` SAST wrapper's `"kubescape"`); `CloudCategory::Kubernetes` × `CloudProvider::Kubernetes`. Scans a **live Kubernetes cluster** via kubeconfig context, evaluating against Kubescape's framework battery (NSA, MITRE, ArmoBest, CIS Kubernetes Benchmark) — vs the SAST wrapper which scans YAML manifests on disk. **Target validation:** only `CloudTarget::KubeContext` and `CloudTarget::All` (with `kube_context` set) accepted; `Account` / `Project` / `Subscription` rejected with cross-pipeline pointers to `prowler-cloud` / `scoutsuite-cloud`. **Target-overrides-config semantics:** explicit `KubeContext(ctx)` value wins over `creds.kube_context`. **Argv layout:** `scan --format json --kube-context <ctx>`. **Subprocess strategy:** `run_tool_lenient` with 10-min timeout. **JSON parser** walks `results[]`, filters `status == "failed"`, maps `scoreFactor` to severity at parity with `sast_tools::kubescape` (`>= 7.0` → High, `>= 4.0` → Medium, else Low); tags findings `module_id = "kubescape-cloud"`, OWASP A05, CWE-1188 (Insecure Default), confidence 0.9, evidence `provider:kubernetes | controlID:<id> | score:<n> | target:<label>`. **No new Cargo deps.** No doctor changes — `kubescape` already in `cli::doctor::tool_specs()` from WORK-114. `cloud::register_modules()` now returns 3 modules in lexicographic order (`kubescape-cloud`, `prowler-cloud`, `scoutsuite-cloud`); `test_cloud_register_modules_v2` replaced by `test_cloud_register_modules_v3` with full metadata pins on all three. Tests (all `#[cfg(feature = "cloud")]`-gated): default 641 unchanged; `--features cloud` 691 → **702** (+11 — 11 new tests covering argv builder × 8, JSON parser × 2, module metadata × 1); `--all-features` 874 → **885** (+11). Lib clippy clean. New operator docs at `docs/modules/cloud-kubescape.md`; extended `docs/architecture/cloud.md` with `kubescape-cloud` section. Architecture decision `cloud.module.kubescape` recorded. (WORK-153)

- **Scout Suite as `CloudModule` — multi-cloud (AWS / GCP / Azure) (WORK-152)** — Second concrete cloud module after WORK-151 Prowler. New `cloud::scoutsuite::ScoutsuiteCloudModule` (module id `"scoutsuite-cloud"`, distinct from the existing `sast_tools::scoutsuite` SAST wrapper's `"scoutsuite"`); `CloudCategory::Compliance` × `CloudProvider::{Aws, Gcp, Azure}`. **Multi-cloud fan-out** — `CloudTarget::All` resolves to the list of providers with configured credentials and runs Scout sequentially per provider, merging findings (concurrent execution risks tripping cloud-API rate limits). Single-provider targets (`Account` → AWS, `Project` → GCP, `Subscription` → Azure) run a single scout invocation. `KubeContext` rejected with a pointer to WORK-153 Kubescape. **Provider selection** via private `select_providers` helper — gracefully skips providers in `All` mode whose creds are absent (debug log); explicit `Project(_)` without `gcp_service_account_path` errors with remediation. **Per-provider argv layouts** (golden-byte tests pin each): AWS `scout aws [--profile P] --report-dir D --no-browser`, GCP `scout gcp --service-account PATH [--project-id ID] --report-dir D --no-browser`, Azure `scout azure [--subscription-id ID] --cli --report-dir D --no-browser`. **Subprocess strategy:** `run_tool_lenient` with 15-min per-provider sub-timeout (30-min total wall clock for `All`). **JSON parser** walks Scout's `services.<svc>.findings.<rule>` schema — maps `level` (`danger`→High, `warning`→Medium, else Low) at parity with `sast_tools::scoutsuite`; filters `flagged_items == 0`; tags findings `module_id = "scoutsuite-cloud"`, OWASP A05, CWE-1188 (Insecure Default), confidence 0.85, evidence `provider:<x> | service:<y> | rule:<z> | flagged:<n>` for downstream filtering and per-provider report grouping. **JSON parser duplicated** from `sast_tools::scoutsuite::parse_scoutsuite_output` (~50 lines) — same deferred-extraction reasoning as WORK-151's OCSF parser; the cloud-family `provider:<x>` evidence tag would force a generic finding-builder closure parameter for sharing. **No new Cargo deps** — `tempfile` already in production deps from WORK-111. No doctor changes — `scout` already in `cli::doctor::tool_specs()` from WORK-114. `cloud::register_modules()` now returns 2 modules in lexicographic order (`prowler-cloud`, `scoutsuite-cloud`); `test_cloud_register_modules_contains_prowler` replaced by `test_cloud_register_modules_v2` with full metadata pins. Tests (all `#[cfg(feature = "cloud")]`-gated): default 641 unchanged; `--features cloud` 675 → **691** (+16 — 16 new tests covering provider selection × 8, per-provider argv × 5, JSON parser × 2, module metadata × 1, plus the renamed register test); `--all-features` 858 → **874** (+16). Lib clippy clean. New operator docs at `docs/modules/cloud-scoutsuite.md`; extended `docs/architecture/cloud.md` with `scoutsuite-cloud` section. Architecture decision `cloud.module.scoutsuite` recorded. (WORK-152)

- **Prowler as `CloudModule` — first concrete v2.2 cloud module (WORK-151)** — First populator of the WORK-150 cloud registry. New `cloud::prowler::ProwlerCloudModule` (module id `"prowler-cloud"`, `CloudCategory::Compliance` × `CloudProvider::Aws`) wraps the `prowler` binary for AWS-account posture audits — CIS AWS Foundations + 400+ checks across IAM, S3, EC2, `CloudTrail`, KMS, VPC. **Argv builder** validates `CloudTarget` (AWS only — rejects `Project`/`Subscription`/`KubeContext` with pointers to WORK-152/WORK-153) and assembles deterministic `aws -M json-ocsf --no-banner -q [-p <profile>] [-R <region>] [--role-arn <arn>]` from optional `CloudCredentials` fields; empty-string values treated as unset. **`CloudTarget::All`** requires `aws_profile` or `aws_role_arn` configured to prevent silent fallthrough to the AWS CLI default. **Subprocess strategy:** `run_tool_lenient` (Prowler 4.x with `output.exit_code_on_fail: true` returns exit 3 on FAIL findings; strict `run_tool` would abort the scan — matches the WORK-094 Snyk lesson). **OCSF parser** handles both array form and JSON-lines fallback; skips `status_id == 1` (PASS); maps 5 severity strings. **Findings** tagged `module_id = "prowler-cloud"`, OWASP A05, CWE-1188 (Insecure Default), confidence 0.8, with `provider:aws | service:<name> | severity:<str> | target:<label>` evidence for downstream filtering. **Coexists** with the existing `tools::prowler` DAST wrapper (id `"prowler"`) — operators with existing DAST-orchestrator scan profiles are unaffected. `cloud::register_modules()` now returns exactly 1 module (was `vec![]` at WORK-150). OCSF parser duplicated from `tools::prowler::parse_prowler_output` — extraction to a shared helper deferred to WORK-154 once Scoutsuite (WORK-152) provides the second consumer. No new Cargo deps. No doctor changes — `prowler` already in `cli::doctor::tool_specs()` from the DAST wrapper era. Tests (all `#[cfg(feature = "cloud")]`-gated): default 641 unchanged; `--features cloud` 661 → **675** (+14 net: 15 new tests, 1 replaces WORK-150's `test_cloud_register_modules_empty`); `--all-features` 844 → **858** (+14). Lib clippy clean. New operator docs at `docs/modules/cloud-prowler.md`; extended `docs/architecture/cloud.md` with "Concrete modules" section. Architecture decision `cloud.module.prowler` recorded. (WORK-151)

- **Cloud-posture scanning foundation — `CloudModule` trait + `InfraCategory::Cloud` + `CloudCredentials` (WORK-150)** — Kicks off the v2.2 Cloud arc. Lands the load-bearing type surface + orchestrator + CLI wiring that subsequent cloud-posture modules (WORK-151 Prowler-as-`CloudModule`, WORK-152 Scoutsuite, WORK-153 Kubescape, WORK-154 normalization) plug into. New `feature = "cloud"` gates everything; default build unchanged. **Two-axis classification** — `CloudCategory` (Iam / Storage / Network / Compute / Kubernetes / Compliance) × `CloudProvider` (Aws / Gcp / Azure / Kubernetes); a single module lives under one category but may target multiple providers. **Prefix-dispatched `CloudTarget::parse`** (`aws:123456789012` / `gcp:my-project` / `azure:<sub-guid>` / `k8s:<context>` / `all`) — explicit prefixes trump shape inference because cloud IDs lack syntactic fingerprints. **`CloudContext` drops the `http_client` field** — cloud modules call SDKs or tool-wrapper subprocesses, not arbitrary HTTP; future modules needing HTTP construct their own client. **`CloudCredentials`** with hand-written `Debug` (never `derive`), `SCORCHKIT_*` env-var precedence (env-wins-non-empty), 8 `Option<String>` identifier fields (`aws_profile`, `aws_role_arn`, `aws_region`, `gcp_service_account_path`, `gcp_project_id`, `azure_subscription_id`, `azure_tenant_id`, `kube_context`) — WORK-146 pattern applied to cloud. **`CloudOrchestrator`** structural copy of `InfraOrchestrator` (~90% identical; generic refactor deferred to a later pipeline); empty-registry contract verified — `cloud::register_modules()` returns `vec![]` at WORK-150 and the orchestrator emits `ScanStarted` + `ScanCompleted` with zero findings without panicking. **CLI**: new `scorchkit cloud <target>` subcommand; `scorchkit assess` extended with `--cloud <target>` for 4-way `tokio::join!`. **`Engine::full_assessment`** signature gains an always-present `cloud_target: Option<&str>` parameter — not `#[cfg]`-gated (avoids viral `#[cfg]` in callers); passing `Some(_)` without `--features cloud` errors at call time. **`Target::from_cloud(raw)`** wraps in a synthetic `cloud://` URL so reporting / storage / AI consume cloud scans identically. **`InfraCategory::Cloud`** variant added for unified `--category` CLI filtering across families. Tests (all `#[cfg(feature = "cloud")]`-gated): default 639 → 639 unchanged; `--features cloud` → **+23** (cloud_credentials: 5, cloud_module: 4, cloud_target: 5, cloud_context: 1, cloud_orchestrator: 4, cloud::mod: 1, target::from_cloud: 2, plus `InfraCategory::Cloud` coverage extending 2 existing tests). Architecture docs: new `docs/architecture/cloud.md`; extended `docs/architecture/engine.md`. Zero new Cargo deps — SDK clients deferred to WORK-151+. (WORK-150)

## [2.1.0] - 2026-04-15

### Fixed
- **NVD pagination — CPEs matching more than one page no longer silently truncate (WORK-147, closes #121)** — `NvdCveLookup::query` now follows NVD's `startIndex` pagination automatically, aggregating records across pages until `records.len() >= totalResults` or the hard `MAX_PAGES = 10` (≈20,000-record) ceiling. Pre-v2.1.x the query discarded everything past the first 2000 records silently, meaning CPEs for heavy software (`nginx`, `openssh`, `apache_httpd`) returned incomplete CVE sets. A zero-record page breaks the loop unconditionally to defend against misbehaving mirrors. Page count is logged at `debug!` so operators see the request cost. (WORK-147)

### Added
- **RDP-TLS probe via X.224 Connection Request negotiation (WORK-148, closes v2.1.x arc)** — Closes the last deferred follow-up from WORK-109. New `TlsMode::RdpTls` variant in `engine::tls_probe` drives the MS-RDPBCGR X.224 Connection Request / Connection Confirm negotiation before handing the socket to rustls. The CR is a fixed 38-byte packet pinned via golden-byte test: TPKT header (big-endian length) + X.224 CR TPDU + `Cookie: mstshash=\r\n` stub (matches rdesktop/FreeRDP defaults; modern Windows RDP servers reject CRs without it) + `RDP_NEG_REQ` requesting `PROTOCOL_SSL` (little-endian protocol mask). The CC response is parsed by pulling the trailing 8 bytes of the X.224 TPDU: `RDP_NEG_RSP` with `selectedProtocol = PROTOCOL_SSL` → TLS handshake proceeds; `RDP_NEG_FAILURE` (NLA-only hosts) → `Err` that surfaces as the existing confidence-0.3 Info "TLS probe skipped" finding per the WORK-109 error-to-Info contract. Port 3389 now probed by default in `TlsInfraModule::DEFAULT_PROBE_TARGETS` with label `"RDP-TLS"`. All failure modes (bad TPKT version, implausible length, non-CC TPDU type, `RDP_NEG_FAILURE`, unexpected `selectedProtocol`, peer close mid-negotiation) return `io::Error` / `Err(String)` and never panic — verified by a dedicated `peer_close_yields_err_no_panic` test. 4 new tests in `engine::tls_probe` (golden CR layout + ephemeral-listener CR→CC for success / `RDP_NEG_FAILURE` / peer-close); 1 modified test in `infra::tls_probe` (port-3389 + label pin). Tests: default **+4** across default, `--features infra`, and `--all-features` builds. Lib clippy clean. `engine::tls_enum` exhaustive matches extended with `TlsMode::RdpTls => ProbeOutcome::Unknown` (RDP-TLS cipher/version enumeration deferred — follow-up would drive the X.224 preamble per probe). Docs updated (module doc comments, `docs/modules/tls-infra.md`, `docs/architecture/infra.md`, `docs/architecture/engine.md`) to reflect RDP-TLS shipping. Architecture decision `engine.tls-probe.rdp-mode` recorded. (WORK-148)

- **NVD delta-sync mode (WORK-147)** — New optional `[cve.nvd] delta_sync = true` flag. When enabled and a cache entry exists for a CPE, subsequent queries issue a delta fetch with `lastModStartDate = cache_write_time − 1h safety margin` (and matching `lastModEndDate = now`) so only records modified since the cache write are retrieved. The delta is merged into the cached set keyed by CVE ID (delta wins on collision — it's newer), and the merged set is written back. Reduces NVD load + scan latency for operators running frequent scans against infrastructure whose CVE-relevant CPEs don't churn daily. `FsCache` gains a `get_with_meta` method returning `(records, fetched_at_unix)` so callers that need the timestamp opt in explicitly. No new Cargo dependencies — `chrono` (already direct) powers RFC 3339 formatting. Architecture decision `cve.backend.nvd-pagination` recorded. `docs/modules/cve-nvd.md` Pagination + Delta Sync sections added; operator-facing limitation "No pagination" removed. Tests: default 586 → **587** (+1), `--all-features` 724 → **731** (+7 including 6 new integration tests covering single-page, multi-page aggregation, zero-records break, delta-disabled skip, delta-enabled cache-hit URL construction + merge, delta-enabled cache-miss full query). Zero fix iterations in Phase 4+; two test-only fix iterations in Phase 3 (struct-literal completions + httpmock matcher API upgrade). (WORK-147, closes #121)

- **Authenticated network scanning foundation — `NetworkCredentials` + `[network_credentials]` config (WORK-146, closes #117)** — Finishes the `InfraContext` architecture by wiring the credentials field stubbed in WORK-101. New `engine::network_credentials::NetworkCredentials` struct with six optional fields (`ssh_user`, `ssh_key_path`, `smb_username`, `smb_password`, `snmp_community`, `kerberos_principal`). Secret-handling discipline is enforced at the type level: `Debug` is **hand-written** (never `derive`) and redacts `smb_password` + `snmp_community` as `"***"` so any `tracing::debug!("{:?}", creds)` anywhere in the codebase is automatically safe. Env-var precedence via `NetworkCredentials::from_config_with_env(&cfg)` merges the config block with env vars (`SCORCHKIT_*` per field), env wins when set + non-empty. Empty-string env treated as unset to handle the common CI pattern where a variable is exported unconditionally. New `[network_credentials]` block on `AppConfig`. `InfraContext::credentials: Option<Arc<NetworkCredentials>>` field resolved at context construction (`None` when empty so downstream code can short-circuit). New `format_redacted_argv` pure helper swaps values after `-p`/`--password`/`-c`/`--community` flags for `debug!`-level logs — argv passed to the actual subprocess stays real. Three existing tool wrappers updated to forward creds when present: `tools::nxc` (`-u USER -p PASS` SMB auth vs existing null-session fallback), `tools::smbmap` (same), `tools::kerbrute` (extracts domain from `user@DOMAIN` principal for `--domain`, falls back to host when unset / unparsable). Tests: default 586 → **607** (+21), `--all-features` 724 → **741** (+17). **Zero fix iterations** across the entire pipeline — Phase 3 tests passed on first run, Phase 4 and Phase 5 showed identical counts. No new Cargo dependencies. Architecture decision `infra.network-credentials` recorded. New operator docs at `docs/architecture/auth-config.md`. (WORK-146, closes #117)

- **Full DNSSEC chain validation + native AXFR zone-transfer probe (WORK-145, closes #122, #123)** — Closes the DNS story arc from v2.0. `infra::dns_probe::DnsInfraModule` gains two extensions: (1) full DNSSEC chain validation via hickory-resolver's new `dnssec-aws-lc-rs` feature — a second validating-resolver pass with `ResolverOpts::validate = true` triggers the parent-DS → DNSKEY → RRSIG chain walk internally; errors are classified via `classify_dnssec_error` into Critical (bogus chain / bad RRSIG), High (expired signature), Medium (missing DS at parent), and Medium (indeterminate fallback). Success yields a new Info "DNSSEC Chain Validated" finding. (2) Native raw-TCP AXFR probe built on `hickory-proto`'s `Message` + `RecordType::AXFR` types — fans out across every NS in the zone, hand-crafts a DNS query with QTYPE=252, sends with the standard 2-byte TCP length prefix, and classifies the first response (`NoError` + `AA` flag + `ANCOUNT > 0` + SOA-in-answers = Accepted → Critical "AXFR Zone Transfer Allowed" per accepting NS). Rejections are silent (`debug!` only) because every healthy server refuses. 2s per-NS timeout caps the budget. `aws-lc-rs` crypto backend matches the provider rustls already uses (WORK-143) so only one crypto library compiles into the binary. **No new Cargo deps** — hickory-proto is already transitive via hickory-resolver. Tests: `--all-features` 724 → **733** (+9 — DNS extensions are fully behind the `infra` feature gate; default build sees zero delta). 14 active tests + 2 `#[ignore]`-gated live smoke tests (`dnssec_chain_live`, `axfr_probe_live`) behind `SCORCHKIT_DNS_TEST_ZONE=<zone>` env var following the WORK-103b `cve_nvd_live` pattern. Architecture decision `infra.dns-deepening` recorded. Operator docs in `docs/modules/dns-infra.md` (fully rewritten with new finding catalog, two-pass DNSSEC explanation, AXFR classifier rationale). (WORK-145, closes #122 / #123)

- **TLS protocol + cipher-suite enumeration (WORK-143, closes #119 / #120)** — New `src/engine/tls_enum.rs` exposes `TlsVersionId` (SSLv3 / TLSv1.0 / TLSv1.1 / TLSv1.2 / TLSv1.3 with `wire()`, `label()`, `severity_when_accepted()`, `is_legacy()`), `CipherSuiteId(u16)` IANA wrapper with `name()` + `weakness()` classification, `CipherWeakness` enum (Ok / Legacy / Weak / Critical with severity mapping), `ProbeOutcome` enum (Accepted / Rejected / Unknown), plus `probe_tls_version`, `probe_tls_cipher`, `enumerate_tls_versions`, and `enumerate_weak_ciphers`. Implementation splits by rustls capability: TLSv1.2 / TLSv1.3 probes go through a rustls handshake with a deliberately permissive cert verifier (`NoCertVerifier`) scoped to one protocol version; SSLv3 / TLSv1.0 / TLSv1.1 and all cipher-acceptance probes use a hand-crafted raw-socket ClientHello whose server response is classified by inspecting the first record byte (`0x16` = ServerHello → Accepted, `0x15` = Alert → Rejected, else Unknown). rustls 0.23 refuses to speak pre-TLS1.2 and ships no weak cipher suites, so the raw-socket path is the only viable route without a new TLS stack dependency. TLSv1.3 cipher enumeration is explicitly out of scope (RFC 8446 defines only 5 AEAD suites, all modern). Cipher catalog is a ~38-entry static table keyed on IANA IDs covering every known Critical (NULL / anon / EXPORT / DES) / Weak (RC4 / 3DES / MD5-MAC) / Legacy (CBC-mode AES) suite plus a small set of Ok baselines. `infra::TlsInfraModule` gains two new config fields: `enum_protocols: bool` (default `true` — runs five forced-version probes per port, ~5s) and `cipher_enum_limit: Option<usize>` (default `None` — opt-in because each probe is a full TCP handshake, ~30s for the full catalog). Findings aggregate per severity tier per port (one Critical / High / Medium finding, full list in evidence) with CWE-326 for deprecated protocols and CWE-327 for weak ciphers. Prelude re-exports the new public types. Removed the "TLS protocol-range enumeration" and "Cipher-suite enumeration" entries from `engine::tls_probe` and `infra::tls_probe` out-of-scope notes. Tests: default 586 → **608** (+22), `--all-features` 724 → **746** (+22), plus 2 `#[ignore]`-gated live smoke tests (`tls_version_enum_live`, `tls_cipher_enum_live`) following the WORK-103b `cve_nvd_live` pattern via `SCORCHKIT_TLS_ENUM_HOST=host:port`. Architecture decision `engine.tls-enumeration` recorded. New architecture section in `docs/architecture/engine.md` (`engine::tls_enum`). Full operator docs in `docs/modules/tls-infra.md`. (WORK-143, closes #119 / #120)

- **Multi-backend CVE aggregation — `CveBackendKind::Composite` + `MultiCveLookup` (WORK-144, closes #124)** — Closes the v2.0 CVE arc. New `infra::cve_multi::MultiCveLookup` wraps `Vec<Box<dyn CveLookup>>`, implements the `CveLookup` trait itself, and fans `query(cpe)` out to each sub-backend sequentially (matching the per-fingerprint pattern from WORK-103's `CveMatchModule` — avoids surprising rate-limit interactions; concurrent fan-out remains a v2 enhancement). Per-sub-backend errors are isolated via `warn!` + empty-Vec contribution so one broken credential doesn't abort the scan. Merged records are deduplicated by canonical CVE ID via `canonical_cve_key(record)`: prefer `record.id` if it starts with `CVE-`, else search `record.aliases` for a `CVE-` entry, else fall back to the raw `id`. On dedup collision the record with the higher `cvss_score` wins (`None < Some(0.0)`); equal scores keep first-seen. New additive `aliases: Vec<String>` field on `CveRecord` (with `#[serde(default)]` for back-compat with existing storage/MCP JSON) — populated from OSV's `aliases[]` response, empty for NVD/Mock. New `CveBackendKind::Composite` variant + `CompositeConfig` peer sub-block (`[cve.composite] sources = [...]`) preserves the existing `backend = "nvd"/"osv"` TOML schema; flat `CompositeSource` enum (Nvd/Osv/Mock) structurally prevents nested Composite at the type level. Empty sources list errors at factory construction. Tests: default 586 → **591** (+5 unconditional — config/cve + engine/cve aliases), `--all-features` 724 → **743** (+19 — includes 15 new `cve_multi` tests covering pure dedup helpers, cross-backend overlap collapse, per-source error isolation, concurrent fan-out against fixture mocks). Zero fix iterations in validation. Architecture decision `cve.backend.composite` recorded. Operator-facing setup documented in `docs/architecture/cve-backends.md`. (WORK-144, closes #124)

- **API spec consumers wired into 5 remaining scanners (WORK-108b)** — Closes the architectural follow-up from WORK-108. Each scanner now reads `engine::api_spec::read_api_spec` and runs its module-specific tests against discovered endpoints: `scanner::csrf` flags state-changing endpoints (POST/PUT/PATCH/DELETE) for CSRF review, `scanner::idor` surfaces ID-shaped parameter names via `param_looks_like_id` heuristic, `scanner::graphql` adds spec endpoints matching `graphql`/`gql` to its existing introspection/depth-abuse/batch/field-suggestion/mutation-enum probe set, `scanner::auth` sends an unauthenticated request per endpoint and flags 200-with-content responses as "may not require auth", `scanner::ratelimit` sends 10 rapid GETs per endpoint (capped at first 10) and flags absence of 429/503. The architectural seam between Vespasian's discovered API surface and existing scanners is now fully wired — runtime-discovered endpoints fuel six scanner families end-to-end. (WORK-108b)

- **Container/Cloud tool batch (3 wrappers)** — `dockle` (container image linting; complements `hadolint` for Dockerfile by inspecting the built image — CIS Docker bench, image-history secrets), `kubescape` (Kubernetes manifest scan against NSA / MITRE / ArmoBest / CIS frameworks), `scoutsuite` (multi-cloud config audit across AWS / GCP / Azure / AliCloud / OCI; complements `prowler`'s AWS-deep coverage). All three are `CodeModule` wrappers under `sast_tools/`. Module total: 115 → **118**. Tests: default 630 → **636** (+6). Lays groundwork for the v2.2 cloud-security-posture arc. (WORK-114)

- **DAST polish tool batch (6 wrappers)** — `commix` (advanced command-injection exploitation; complements built-in `cmdi`), `xsstrike` (advanced XSS scanner; alt to `dalfox`), `whatweb` (deep tech fingerprinting via WhatWeb's plugin database; complements built-in `tech`), `wapiti` (full web vuln scanner; alt to ZAP), `linkfinder` (JS endpoint extraction; complements built-in `js_analysis`), `eyewitness` (visual recon — captures screenshots; surfaces a finding pointing at the EyeWitness HTML report). All follow the canonical `tools/` `ScanModule` pattern; registered in `tools::register_modules()` + `cli::doctor::tool_specs()`. DAST tool count: 33 → **39**. Module total: 109 → **115**. Tests: default 617 → **630** (+13). (WORK-112)

- **SAST expansion batch (6 wrappers)** — Adds `cargo-audit` (Rust SCA via RustSec advisory DB), `cargo-deny` (Rust license + advisory policy), `tflint` (Terraform linter — complements `checkov`), `kics` (broader IaC across Terraform / CloudFormation / K8s / Docker / Helm / Ansible / Pulumi / OpenAPI / gRPC), `slither` (Solidity static analyzer for reentrancy / locked-ether / suicidal contracts), `brakeman` (Ruby on Rails SAST). All follow the existing `sast_tools/` `CodeModule` pattern: `requires_external_tool() = true`, JSON / JSON-Lines parsers, registered in `sast_tools::register_modules()` + `cli::doctor::tool_specs()`. SAST tool count: 12 → **18**. Module total: 103 → **109**. Tests: default 605 → **617** (+12). (WORK-113)

- **API spec shared-data primitive (Vespasian → injection bridge)** — New `engine::api_spec` module defines `ApiSpec` + `ApiEndpoint` types, `SHARED_KEY_API_SPEC` constant, and `publish_api_spec` / `read_api_spec` helpers — mirrors the `service_fingerprint` pattern. `tools::vespasian` now publishes its parsed OpenAPI spec via this primitive; `scanner::injection` consumes it and runs SQLi probes against each discovered endpoint's parameters (with a sentinel `?param=1&...` URL builder). New `docs/architecture/api-spec-shared-data.md` documents the producer / consumer contract for the remaining 5 scanners (csrf, idor, graphql, auth, ratelimit) which will be wired in WORK-108b. Tests: default 599 → **605** (+6). (WORK-108)

- **Vespasian wrapper — API endpoint discovery** — New `src/tools/vespasian.rs` wraps Praetorian's [Vespasian](https://github.com/praetorian-inc/vespasian) (Apache-2.0, Go). Headless-browser crawl + OpenAPI 3.0 / GraphQL SDL / WSDL spec synthesis. Surfaces a summary Info finding (endpoint count + spec title) plus per-endpoint Info findings capped at 50 per scan to keep reports readable. Generated spec is left at a temp path for downstream consumption by the planned WORK-108 spec consumer. Tests: default 594 → **599** (+5). Module total: 102 → **103**. (WORK-107)

- **Tutorials package — 8 step-by-step operator guides** — New `docs/tutorials/` directory with task-oriented walkthroughs spanning new operators → contributors → DevSecOps. Closes the gap between "look at all these capabilities" and "here's what to do on Tuesday morning." Files: `01-first-scan.md` (install + doctor + single scan + read report), `02-cve-correlation.md` (NVD / OSV setup + infra scan), `03-unified-assess.md` (DAST + SAST + Infra in one command), `04-claude-code-workflow.md` (`/scan`, `/code`, `/analyze`, `/diff` conversationally), `05-tls-and-dns-hygiene.md` (probe your own domain), `06-extending-with-custom-modules.md` (implement `ScanModule` from scratch using `examples/custom_scanner`), `07-extending-cve-backends.md` (add a third `CveLookup` backend), `08-ci-cd-integration.md` (GitHub Actions + GitLab CI recipes with SARIF upload). Plus `docs/tutorials/README.md` index and a Tutorials section in the public `README.md`. No code changes — pure docs. (WORK-115)

- **Network/infra tool wrapper batch (7 tools)** — Adds `masscan` (high-speed CIDR port sweep), `naabu` (ProjectDiscovery port scanner), `smbmap` (SMB share enumeration with anonymous null-session detection), `nxc` (NetExec / former CrackMapExec, SMB host info + null-session check), `kerbrute` (Kerberos pre-auth user enumeration with built-in 10-name default list), `ssh-audit` (SSH server hardening check producing per-algorithm weak-cipher findings), and `onesixtyone` (SNMP scanner with built-in 5-entry community-string list). All seven follow the standard `tools/` wrapper pattern: `requires_external_tool() = true`, JSON / text parsers, registered in `tools::register_modules()` and `cli::doctor::tool_specs()`. New `tempfile = "3"` runtime dep (was dev-dep only) for kerbrute / onesixtyone temp-file generation. Module total: 95 → **102**. Tests: default 542 → **594** (+52). Lib clippy clean. (WORK-111)

- **DNS infra modules — wildcard / DNSSEC / CAA / NS (`DnsInfraModule`)** — Eighth v2.0 arc pipeline. **Closes the v2.0 `InfraCategory` enum coverage** — every declared category now has at least one production module. New `src/infra/dns_probe.rs::DnsInfraModule` runs four native async DNS probes via `hickory-resolver` (new `infra`-gated dep): wildcard A/AAAA detection (random 16-hex-char label per scan, 64 bits of UUID-derived entropy so no collision with real subdomains), DNSSEC presence check (`DNSKEY` at apex), CAA presence check, and NS enumeration. Findings tagged `module_id = "dns_infra"` with severities Medium/Medium/Low/Info respectively. AXFR zone transfer stays with the existing `dnsrecon`/`dnsx` tool wrappers (native impl would need `hickory-client`). Tests: default 559 → 559 unchanged, mcp 701 → 701 unchanged, infra 668 → **675** (+7 unit tests covering target extraction, wildcard label shape + uniqueness, module metadata). Lib clippy clean. Semgrep clean. Operator docs at `docs/modules/dns-infra.md`. (WORK-110)

- **TLS infra modules — STARTTLS + implicit-TLS probes (`TlsInfraModule`)** — Seventh v2.0 arc pipeline. Fills the empty `InfraCategory::TlsInfra`. New `src/infra/tls_probe.rs::TlsInfraModule` probes non-HTTP TLS services: SMTPS (465), LDAPS (636), IMAPS (993), POP3S (995) via implicit TLS, plus SMTP (25 & 587), IMAP (143), POP3 (110) via protocol-specific STARTTLS upgrade. Each port is connected, upgraded (if STARTTLS), handshaken through rustls, and the peer cert runs through the same four checks the DAST `ssl` module does: expired, self-signed, weak signature, subject/SAN mismatch. Handshake failures surface as Info findings (port closed / service doesn't speak TLS), not defects — operators see the probe coverage without noise. Extract of shared cert-analysis helpers into new `src/engine/tls_probe.rs` (`CertInfo`, `TlsMode`, `StarttlsProtocol`, `probe_tls`, `check_certificate`, `parse_certificate`); `scanner::ssl` now delegates to these so DAST and infra produce identical finding shapes. STARTTLS preamble verified via ephemeral `TcpListener` tests that script the wire format for SMTP/IMAP/POP3 without needing a real TLS server. Tests: default 559 → 559 unchanged, mcp 701 → 701 unchanged, infra 651 → **668** (+17 net — 10 `engine::tls_probe` including 3 STARTTLS-preamble integration tests, 7 `infra::tls_probe`; 3 `scanner::ssl` private-helper tests superseded by their shared-helper equivalents). Lib clippy clean, semgrep clean on new files. New operator docs at `docs/modules/tls-infra.md`. RDP-TLS (X.224 negotiation) and TLS protocol-range enumeration are explicit follow-ups. (WORK-109)

- **OSV sibling backend — `OsvCveLookup`** — Sixth v2.0 arc pipeline. Second production `CveLookup` impl (gated `infra`) talks to [OSV.dev](https://osv.dev) v1 query API behind the same trait shipped in WORK-103. Where NVD shines for system-software CPEs, OSV is the right backend for language-package CVEs across npm, PyPI, Maven, Go modules, crates.io, RubyGems, NuGet, and Packagist. New pure `infra::cpe_purl::cpe_to_package(cpe)` translator with embedded ≥30-entry static mapping table covers high-value language-ecosystem CPEs; unmapped CPEs return `Ok(empty)` with one `warn!` per CPE so operators see what they're missing without scan failure. New `engine::cve::cvss_v3_base_score(vector)` faithfully implements the [CVSS v3.1 base-score formula](https://www.first.org/cvss/v3.1/specification-document) so OSV's vector-string severities map cleanly onto the existing `severity_from_cvss` bands. New `CveBackendKind::Osv` variant + `OsvConfig` sub-block (`base_url`, `cache_dir`, `cache_ttl_secs`, `max_rps`); OSV is keyless so no `api_key` field. Conservative 10 RPS default limiter (well under OSV's documented ~25 QPS fair-use cap). Per-backend cache directory at `<cache>/scorchkit/cve-osv/` keeps OSV cache files separate from NVD's `<cache>/scorchkit/cve/` so a wholesale flush of one backend doesn't take out the other. End-to-end integration tests against `httpmock` (4 tests including unmapped-CPE short-circuit + 1 `#[ignore]`-gated live smoke against real api.osv.dev). 32 new lib tests (651 with `--features infra`, was 619) — covers CVSS computer (7), CPE translator (11), OSV parser (4), config (3), factory dispatch (1), default cache dir + quota (2). Architecture decision `cve.backend.osv` recorded. New backend docs at `docs/modules/cve-osv.md`. (WORK-103c)

- **Real CVE backend — NVD 2.0 client (`NvdCveLookup`)** — Fifth v2.0 arc pipeline; the deferred follow-up to WORK-103. New `infra::cve_nvd::NvdCveLookup` (gated `infra`) implements `CveLookup` against the NIST NVD 2.0 CPE search API: separate `reqwest::Client` from the scan client (so pen-test proxy/User-Agent/insecure-TLS settings never leak into vendor calls), `governor::RateLimiter` sized to NVD's published quotas (5 req/30s anonymous, 50 req/30s with API key), and a content-addressed file-system TTL cache (`infra::cve_cache::FsCache`, sha256-keyed, JSON envelope, negative caching). New `[cve]` config block with `backend = "disabled" | "mock" | "nvd"` discriminant + `[cve.nvd]` sub-block (`api_key`, `base_url`, `cache_dir`, `cache_ttl_secs`). `SCORCHKIT_NVD_API_KEY` env var beats config. New `infra::cve_lookup::build_cve_lookup(&AppConfig)` factory. `Engine::infra_scan` (which `full_assessment` already calls) consults the factory and appends `CveMatchModule` automatically when a backend is configured. Bad API keys (401/403) are flagged in-process and subsequent calls drop to anonymous, so a broken credential doesn't burn the per-fingerprint loop. End-to-end integration tests against `httpmock` (3 tests, +1 `#[ignore]`-gated live smoke). 17 new lib tests (562 with `--features infra`, was 545). New `httpmock = "0.8"` dev-dep. `dep:sha2` added to the `infra` feature. New backend docs at `docs/modules/cve-nvd.md`. Architecture decision `cve.backend.production` recorded. (WORK-103b)

- **Unified `scorchkit assess` command — DAST + SAST + Infra composition** — Fourth v2.0 arc pipeline. New CLI subcommand `scorchkit assess [--url <url>] [--code <path>] [--infra <target>]` (feature-gated on `infra`) runs the three orchestrators concurrently via `tokio::join!` and merges results into a single `ScanResult`. At least one flag is required; any individual domain failing is logged at `warn` and skipped so partial results still return. New `Engine::full_assessment(url, code_path, infra_target)` facade method with the same semantics and a `no_run` doctest. Private `absorb_outcome` helper keeps the three-way merge clippy-clean. 1 new CLI integration test. (#104)

- **CVE correlation foundation — `CveLookup` trait + `CveMatchModule`** — Third v2.0 arc pipeline. New `CveRecord` struct (id, cvss_score, severity, description, references, cpe), async `CveLookup` trait (`query(&str) -> Result<Vec<CveRecord>>`), pure `severity_from_cvss` mapping using standard CVSS v3.x bands, fixture-backed `MockCveLookup` for tests/examples, and `CveMatchModule` (`InfraModule`, category `CveMatch`). The module reads `Vec<ServiceFingerprint>` from `shared_data` (published in WORK-102), iterates fingerprints with a CPE, queries the injected lookup sequentially, and emits findings tagged with CVE IDs + CVSS scores. `CveMatchModule` is intentionally NOT in `register_modules()` — it requires construction-time lookup injection. Real NVD/OSV client is deferred to WORK-103b. 15 new tests (506 default, 541 with `--features infra`). Architecture decision `engine.cve-lookup` recorded. (#103)

- **Service fingerprinting + nmap InfraModule** — Second v2.0 arc pipeline. New `ServiceFingerprint` struct (port, protocol, product, version, CPE) with pure `parse_nmap_xml_fingerprints(xml)` parser and `build_cpe(vendor, product, version)` helper in `src/engine/service_fingerprint.rs`. New `infra::NmapModule` (gated) runs `nmap -sV` + publishes fingerprints to `shared_data` under `"infra.service_fingerprints"` for downstream CVE correlation (WORK-103). The existing DAST `tools::NmapModule` was refactored to reuse the shared parser — behavior preserved, duplicate XML logic removed. Helper pair `publish_fingerprints` / `read_fingerprints` encapsulates JSON encoding through `SharedData`. 14 new tests (488 default → 498 default, +10; 512 infra → 526 infra, +14). Architecture decision `engine.service-fingerprint` recorded. (#102)

- **Infrastructure scanning foundation (v2.0 arc start)** — Third module family parallel to `ScanModule` (DAST) and `CodeModule` (SAST). New `InfraModule` trait, `InfraCategory` enum (`PortScan`, `Fingerprint`, `CveMatch`, `TlsInfra`, `Dns`), `InfraTarget` enum (`Ip`, `Cidr`, `Host`, `Endpoint`, `Multi`), `InfraContext` struct, `InfraOrchestrator` mirroring the DAST/SAST orchestrators (event bus + audit log + hook integration), and a built-in `TcpProbeModule` for privilege-free TCP-connect reachability checks. New `infra` Cargo feature flag (default off) + `ipnet` optional dep for CIDR parsing. New CLI subcommand `scorchkit infra <target>` (gated). New `Engine::infra_scan(target)` facade method (gated). Synthetic `Target::from_infra(raw)` constructor (`infra://` URL scheme) so existing reporting/storage/AI layers consume infra `ScanResult`s unchanged. 25+ new tests (488 → 488 default; 488 → 512 with `--features infra`). Architecture decision `engine.infra-foundation` recorded. WORK-102 will migrate the existing nmap wrapper into this family. (#101)

- **Built-in audit log handler** — First production consumer of the event bus. New `AuditLogHandler` in `src/engine/audit_log.rs` implements `EventHandler` and appends every published `ScanEvent` to a configurable file as JSON Lines (one event per line, flushed after every write). Opt-in via `[audit_log]` in `scorchkit.toml` (`enabled: bool`, `path: Option<PathBuf>`). Orchestrator and CodeOrchestrator wire the handler via `subscribe_handler` before the first lifecycle event fires, so no events are lost. `ScanEvent` now derives `Serialize` (variant and field names are part of the JSONL wire format; renaming is a breaking change for consumers). File-open failures are logged at `warn` and do not abort the scan — audit logging is best-effort observability. 6 new tests (479 → 485), +1 doctest. Architecture decision `engine.audit-log` recorded. (#100)

### Changed
- **Cloud support boundary** — Production cloud scans now expose five bounded external-tool adapters.
  Twelve native AWS, GCP, and Azure SDK modules are private and test-only until their authentication
  and service transports can enforce ScorchKit's address policy.
- **Agent and SDK boundary** — Replaced Claude-owned workflow instructions with an agent-neutral,
  Codex-first adapter. Public scanner contexts expose policy-owned HTTP access and each family
  orchestrator supports explicit custom-module registration. The standalone DAST and SAST examples
  compile against this contract.
- **CLI consistency** — Profile validation now fails before effects across every scanner family,
  unified assessment forwards the chosen profile, infrastructure commands include configured CVE
  correlation, and one report emitter owns JSON, HTML, SARIF, PDF, terminal, and default output.
- **`cargo deny check` passes cleanly** — `deny.toml` updated to allow `MPL-2.0` (required by `colored` and the `scraper` family, standard industry practice for MIT-licensed Rust projects) and to ignore four pre-existing advisories with inline `reason` + `# JUSTIFICATION` rationale: `RUSTSEC-2023-0071` (rsa via unused sqlx-mysql), `RUSTSEC-2025-0057` (fxhash unmaintained, no safe upgrade), `RUSTSEC-2025-0119` (number_prefix unmaintained, no safe upgrade), `RUSTSEC-2026-0097` (rand 0.9 unsoundness only triggered by custom logger, unreachable in ScorchKit). Zero Rust code changes; zero Cargo.lock changes; 479-test baseline preserved. Architecture decision `security.license-policy` recorded. (#99)

### Added
- **Event bus v2b.1 — custom module events + event filtering** — Extends the event bus shipped in #97 with `ScanEvent::Custom { kind, data }` (modules publish domain-specific events with an owned `serde_json::Value` payload; dotted-namespace kind convention) and `subscribe_filtered(bus, handler, predicate)` (filters events on the subscriber's task before dispatch — zero cost for other subscribers). `HookEventHandler` now explicitly ignores `Custom` events (no standard mapping to hook points; write a native `EventHandler` for custom dispatch). Module doc gains a `# Custom events` example. Prelude re-exports `subscribe_filtered`. 7 new tests (472 → 479). (#98)

- **Event bus v2 — in-process pub/sub for scan lifecycle events** — New `src/engine/events.rs` module with `ScanEvent` enum (7 variants: `ScanStarted`, `ModuleStarted`, `ModuleCompleted`, `ModuleSkipped`, `ModuleError`, `FindingProduced`, `ScanCompleted`), `EventBus` wrapping `tokio::sync::broadcast`, async `EventHandler` trait, and `subscribe_handler` task helper. Multi-subscriber fanout, fire-and-forget publish, lagged-receiver handling. `EventBus` now lives in both `ScanContext.events` and `CodeContext.events`. `Orchestrator` and `CodeOrchestrator` emit events at every lifecycle point across `run()`, `run_with_checkpoint()`, `run_phased()`, and `run_module_batch()`. New `HookEventHandler` adapter bridges events to the existing `HookRunner` script API, buffering per-module findings so `PostModule` hooks still receive the full findings array. Existing synchronous `HookRunner` invocation retained for the post-module finding-modification path. Prelude re-exports `EventBus`, `EventHandler`, `ScanEvent`, `subscribe_handler`. 9 new tests (472 total, was 463). (#97)

- **Claude Code command suite** — 11 slash commands for conversational security testing inside Claude Code: `/scan`, `/analyze`, `/diff`, `/doctor`, `/modules`, `/report`, `/tutorial`, `/project`, `/finding`, `/schedule`, `/coder`. Each command guides users through ScorchKit capabilities with interactive prompts, CLI execution, and result interpretation. (#84)
- **Release infrastructure** — `/release` command publishes to `git@github.com:Ignibyte/scorchkit.git` with quality gates, version bumping, `.releaseignore` exclusion filtering, `.release/` overlay for open-source config, and mandatory leak checks for private content. (#84)
- **MCP server config template** — `.claude/mcp.json` for Claude Code MCP integration. (#84)
- **Open-source CLAUDE.md** — Clean project documentation without internal development references. (#84)

- **SAST integration** — Static Application Security Testing as a parallel system to DAST. New `CodeModule` trait, `CodeContext`, `CodeCategory` enum (Sast, Sca, Secrets, Iac, Container), and `CodeOrchestrator` for concurrent code analysis. CLI `code <path>` subcommand with `--language`, `--modules`, `--skip`, `--profile` flags. Three tool wrappers: Semgrep (multi-language SAST), OSV-Scanner (dependency SCA), Gitleaks (secret detection with redacted evidence). `Target::from_path()` enables all existing reporting/storage/AI to work with code findings. `run_tool_lenient()` for tools that exit non-zero when findings exist. 28 new tests. (#85)

- **Hook system v1** — Script-based lifecycle hooks for scan extensibility. Configure `[hooks]` in config.toml with `pre_scan`, `post_module`, `post_scan` script arrays. JSON stdin/stdout protocol. Configurable timeout (default 30s), fail-open by default. Works with both DAST and SAST orchestrators. Enables CI/CD integration, SIEM export, Slack/Jira notifications, and finding enrichment without modifying ScorchKit. (#86)
- **`/code` Claude Code command** — SAST code scanning via slash command with formatting guidelines. (#90)

- **SAST tool wrappers: Bandit, Gosec, Checkov, Grype** — Four new SAST tool wrappers expanding code scanning coverage. Bandit (Python SAST, language-filtered), Gosec (Go SAST, language-filtered), Checkov (IaC scanning for Terraform/CloudFormation/Kubernetes/Dockerfile), Grype (container image and dependency vulnerability scanning). All use `run_tool_lenient()` for non-zero exit handling. Bandit maps tool-native confidence to Finding confidence. Grype extracts fix versions for actionable remediation. 8 new tests. (#87)

- **Built-in dependency auditor** — First built-in SAST module (`src/sast/dep_audit.rs`). Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, and `go.sum` to detect dependency health issues without external tools. Checks: duplicate package versions (supply chain risk), unpinned dependencies (reproducibility risk), and known-risky/compromised packages (11 curated entries covering event-stream, ua-parser-js, colors, faker, node-ipc, and PyPI typosquats). Works out of the box — no cargo-audit, OSV-Scanner, or Grype needed. 8 new tests. (#88)

- **Engine facade and prelude** — `ScorchKit` is now usable as a library crate (`cargo add scorchkit`). New `Engine` facade struct with `scan(url)`, `scan_with_profile(url, profile)`, `code_scan(path)`, and `code_scan_language(path, lang)` methods. New `prelude` module re-exports ~15 core types (`use scorchkit::prelude::*`). Crate-root `pub use` re-exports for `scorchkit::Finding`, `scorchkit::Severity`, etc. Public `build_http_client()` for custom HTTP client construction. Crate-level `//!` documentation with quick-start examples. 3 new tests. (#89)

- **SAST wrappers batch 2: Hadolint, ESLint-security, PHPStan** — Three more SAST tool wrappers completing v1.1 expansion. Hadolint (Dockerfile linting, IaC category), ESLint with security plugin (JavaScript/TypeScript, language-filtered), PHPStan (PHP static analysis, language-filtered). SAST system now has 11 modules total (1 built-in + 10 tool wrappers). 6 new tests. (#90)

- **Combined DAST+SAST scanning** — New `--code <path>` flag on the `run` command runs DAST and SAST concurrently, merging findings into a single report: `scorchkit run https://example.com --code ./src`. SAST failure is non-fatal (DAST results always returned). New `ScanResult::merge()` method for combining results. New `Engine::full_scan(url, code_path)` in the library facade. 2 new tests. (#91)

- **MCP code scanning tools** — Two new MCP tools exposing SAST via the MCP server: `scan_code` (run SAST on a filesystem path with optional language/module filtering) and `list_code_modules` (list all 11 SAST modules with categories, language support, and tool requirements). Also fixes pre-existing `update_finding_status` missing argument bug in MCP tools and test files. (#92)

- **DAST+SAST cross-domain correlation** — 6 new attack chain correlation rules matching DAST findings with SAST findings: confirmed SQL injection (code + runtime), hardcoded secrets + runtime exposure, vulnerable dependency + exploitable endpoint, IaC misconfiguration + runtime misconfig, auth bypass (code + runtime), supply chain risk (risky package + missing CSP). Extends the existing rule-based `correlate_attack_chains()` system. New `is_sast_module()` helper for module classification. 6 new tests. (#93)

- **Snyk CLI integration** — Two new SAST tool wrappers: `snyk-test` (dependency SCA via `snyk test --json`, `CodeCategory::Sca`) and `snyk-code` (SAST via `snyk code test --json`, `CodeCategory::Sast`). Free tier compatible — no paid license needed. Snyk auto-detects project language. SAST system now has 13 modules total (1 built-in + 12 tool wrappers). Completes v1.2. 4 new tests. (#94)

- **Plugin SDK: plugin author guide + example crates** — Third-party Rust developers can now write native `ScanModule` and `CodeModule` implementations. New `docs/plugin-sdk.md` comprehensive guide covering both trait contracts, the Finding builder, confidence values, context types, inter-module data sharing, language filtering, error handling, testing patterns, and design principles. New `examples/custom_scanner/` (DAST) and `examples/custom_code_scanner/` (SAST) working example crates with tests. First v1.3 feature. (#95)

- **Custom rule templates: YAML response pattern rules** — New `rule-engine` built-in scanner module loads YAML rules from a configured `rules_dir` and runs them against targets. Each rule specifies request config (method/path/headers/body) and response matchers (status, body regex, header regex). Matchers use AND semantics. New `regex` and `serde_yaml` dependencies. 3 example rules in `rules/examples/` + plugin guide in `rules/README.md`. Complements the existing TOML command plugin system. 10 new tests. (#96)

### Changed
- **coder.md module counts** — Updated from 41 to 77 modules (10 recon + 35 scanner + 32 tools). Fixed "waf" module classification (scanner, not recon). (#84)

## [1.0.0] - 2026-04-04

### Added
- **Finding confidence scores** — Every finding now carries a `confidence: f64` (0.0–1.0) indicating false-positive likelihood. 6 tiers from 0.4 (static analysis) to 0.9 (definitive checks). All 225 Finding::new call sites across 77 modules set explicit confidence. New `--min-confidence` CLI flag filters findings below threshold. Confidence displayed in terminal, HTML, SARIF (as `rank`), and PDF reports. Storage layer persists via new `003_add_confidence.sql` migration. Backwards-compatible: old JSON reports without confidence deserialize with default 0.5. 8 new tests. (#82)
- **Scan resume/checkpoint** — New `--resume <checkpoint-file>` CLI flag to resume interrupted scans. After each module completes, a checkpoint JSON file is saved with scan state (completed modules, findings, config hash). On resume, completed modules are skipped. Checkpoint auto-deleted on scan completion. All scans now checkpoint by default. `src/runner/checkpoint.rs` with `ScanCheckpoint` struct, `save/load/remove` functions. 6 new tests. (#84)
- **Inter-module data sharing** — New `SharedData` store in `ScanContext` enables modules to share discovered data. Crawler publishes URLs, forms, and parameters. Tech module publishes detected technologies. Subdomain module publishes discovered subdomains. Injection and XSS scanners consume shared URLs for expanded attack surface. New `Orchestrator::run_phased()` runs recon modules first, then scanners. Thread-safe via `RwLock`. 5 new tests. (#83)
- **Multi-target scanning** — New `--targets-file <path>` CLI flag on the `run` command accepts a file with one target per line. Supports `#` comments and blank lines. Targets are scanned sequentially with per-target progress display. Individual target failures are logged but don't abort the batch. Summary printed at end showing total scanned and any errors. Mutually exclusive with the positional `<target>` argument. `parse_targets_file()` in `engine/target.rs`. 3 new tests. (#81)
- **Custom wordlists configuration** — New `[wordlists]` section in `config.toml` with per-purpose paths: `directory` (dir brute-force), `subdomain` (DNS enumeration), `vhost` (virtual host discovery), `params` (parameter fuzzing). Built-in modules (subdomain, vhost, discovery) check config first, fall back to hardcoded defaults. Tool wrappers (ffuf, gobuster) pass configured wordlist path to external tools. `load_wordlist()` helper reads files with comment/blank-line support. 4 new tests. (#85)
- **Path Traversal / LFI scanner** (`path_traversal`) — Detects directory traversal and local file inclusion via 24 payloads covering depth variations (1-8 levels), URL encoding, double encoding, null byte bypasses, backslash (Windows), UTF-8 overlong encoding, and filter bypass techniques. Matches 12 file content indicators for Linux (`/etc/passwd`, `/etc/shadow`) and Windows (`win.ini`, `boot.ini`, hosts). CWE-22, OWASP A01:2021. `src/scanner/path_traversal.rs` with 7 tests (#70)
- **SSTI scanner** (`ssti`) — Detects server-side template injection across 8 template engines (Jinja2, Twig, Freemarker, ERB, Mako, Velocity, Smarty, Pebble) via 10 safe mathematical expression payloads. Boundary-aware response matching avoids false positives from CSS/pixel values. Engine identification from error messages (19 fingerprints). Tests query params, form fields, and HTTP headers (User-Agent, Referer). CWE-1336, OWASP A03:2021. `src/scanner/ssti.rs` with 7 tests (#70)
- **CRLF injection scanner** (`crlf`) — Detects HTTP response splitting via 7 payload variants: standard `%0d%0a`, double-encoded, unicode, bare LF/CR, Set-Cookie injection, and tab-prefixed. Checks response headers for injected canary headers. CWE-113, OWASP A03:2021. `src/scanner/crlf.rs` with 5 tests (#72)
- **Host header injection scanner** (`host_header`) — Detects host header poisoning via 5 override headers (X-Forwarded-Host, X-Host, X-Forwarded-Server, X-Original-URL, X-Rewrite-URL). Checks response body for reflected canary and HTML attributes (href, src, action) for cache poisoning. CWE-644, OWASP A03:2021/A05:2021. `src/scanner/host_header.rs` with 5 tests (#72)
- **NoSQL injection scanner** (`nosql`) — Detects MongoDB/CouchDB/Redis injection via 12 payloads: `$gt`, `$ne`, `$regex`, `$exists` operators, bracket notation, `$where` JavaScript injection, boolean-based blind. Error-based detection (21 patterns), 500 status detection, response size differential. JSON body injection for auth bypass. CWE-943, OWASP A03:2021. `src/scanner/nosql.rs` with 5 tests (#73)
- **LDAP injection scanner** (`ldap`) — Detects LDAP filter injection via 11 payloads: wildcard, filter-closing, OR injection, null byte, escaped metacharacters. Error-based detection (24 patterns) covering PHP, Java, Python, Active Directory LDAP implementations. CWE-90, OWASP A03:2021. `src/scanner/ldap.rs` with 5 tests (#73)
- **HTTP request smuggling scanner** (`smuggling`) — Heuristic-based CL.TE/TE.CL/TE.TE risk detection via proxy indicator analysis (17 CDN/proxy headers), `Transfer-Encoding` obfuscation variant testing (9 variants), and `Content-Length` handling inconsistency checks. Reports risk indicators with evidence strength-based severity since `reqwest` normalizes TE headers. CWE-444, OWASP A05:2021. `src/scanner/smuggling.rs` with 5 tests (#74)
- **Prototype pollution scanner** (`prototype_pollution`) — Detects `__proto__` and `constructor.prototype` injection via 4 JSON body payloads and 3 query parameter payloads. Checks for canary reflection and server errors. CWE-1321, OWASP A08:2021. `src/scanner/prototype_pollution.rs` with 4 tests (#75)
- **Mass assignment scanner** (`mass_assignment`) — Detects over-posting via 12 privileged field injections (`role`, `isAdmin`, `price`, `permissions`, etc.) in JSON POST bodies. Compares against baseline to avoid false positives. CWE-915, OWASP A04:2021. `src/scanner/mass_assignment.rs` with 4 tests (#75)
- **Clickjacking scanner** (`clickjacking`) — Active test for missing frame protection: flags only when BOTH `X-Frame-Options` AND CSP `frame-ancestors` are absent. Only checks HTML pages. CWE-1021, OWASP A05:2021. `src/scanner/clickjacking.rs` with 5 tests (#76)
- **DOM XSS scanner** (`dom_xss`) — Static JavaScript source/sink analysis: 12 DOM sources (`location.hash`, `document.referrer`, etc.) and 15 sinks (`innerHTML`, `eval`, `document.write`, etc.). Flags source+sink combinations and orphan critical sinks. CWE-79, OWASP A07:2021. `src/scanner/dom_xss.rs` with 5 tests (#76)
- **JS file analysis recon** (`js_analysis`) — Extracts secrets (17 patterns: AWS keys, Stripe, GitHub/GitLab tokens, private keys), API endpoints (13 patterns), and source map references from inline and external JavaScript files. CWE-540/CWE-615. `src/recon/js_analysis.rs` with 6 tests (#77)
- **CNAME takeover + cert transparency recon** (`cname_takeover`) — Detects dangling CNAME records via 16 service fingerprints (GitHub Pages, Heroku, S3, Shopify, etc.) and enumerates subdomains via crt.sh certificate transparency logs. CWE-923/CWE-200. `src/recon/cname_takeover.rs` with 4 tests (#78)
- **Virtual host discovery recon** (`vhost`) — Brute-forces Host header with 36 common prefixes (admin, api, staging, etc.) and detects unique vhosts via response differential analysis. `src/recon/vhost.rs` with 2 tests (#78)
- **Cloud metadata + bucket enumeration recon** (`cloud`) — Detects cloud providers from 17 response header indicators (AWS, GCP, Azure, Cloudflare, etc.) and enumerates S3 buckets with 19 domain-derived name suffixes. CWE-200/CWE-284. `src/recon/cloud.rs` with 5 tests (#79)
- Total scanner modules: 35 built-in (was 24). Total recon modules: 10 (was 6).
- Total tests: 419 default (was 345), 555 MCP (was 481)

## [0.29.0] - 2026-03-30

### Changed
- **Final test coverage sweep** — Added 72 new tests across 30 files (#69). Clears entire test backlog.
  - Scanner unit tests: ssl (3), misconfig (3), ratelimit (3), redirect (3), api_schema (3), waf (3)
  - Tool wrapper parser tests: 22 tools × 2 tests (nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan, interactsh)
  - MCP integration tests: project_status (2), plan_scan (2), analyze_findings (2)
  - Attack chain correlation tests: sqli, ssrf, idor, credential compromise (4)
  - Total: 409→481 tests (MCP), 283→345 tests (default)
- **Test coverage expansion** — Added 88 new tests across 14 files (#68). Scanner coverage 37%→62%, recon 17%→100%, MCP scheduling 0→8 tests.
  - OWASP scanner unit tests: xss (6), ssrf (6), injection (8), cmdi (3), csrf (3), jwt (12), idor (8), sensitive (4)
  - Recon module unit tests: headers (7), tech (5), discovery (9), crawler (6), subdomain (3)
  - MCP scheduling integration tests: `schedule_scan` (4), `run_due_scans` (4)
  - Total: 319→409 tests (MCP), 201→283 tests (default)
- **Clippy zero-warnings cleanup** — Resolved all 185 clippy pedantic/style warnings across 64 files (#67). Zero-warning builds on both default and `--features mcp` configurations.
  - 35 `doc_markdown` backtick fixes in doc comments
  - 23 `manual_let_else` refactors (if-let → let...else)
  - 21 tool wrapper `parse_*_output()` signatures simplified (`Result<Vec<Finding>>` → `Vec<Finding>`)
  - 30 `# Errors` doc sections added to `Result`-returning functions
  - ~76 mixed idiom fixes (or_fun_call, map_or_else, format_push_string, must_use, const_fn, etc.)
  - 4 helper function extractions for too_many_lines (crawler, injection, xss, html)

### Added
- **Deep tool validation** (`doctor --deep`) — Version checks, min-version enforcement, nuclei template freshness, remediation hints for 33 external tools. `src/cli/doctor.rs` with `ToolSpec`, `Version` comparison, 8 new tests (#48)
- **Project init with target fingerprinting** (`init <url>`) — Single HTTP probe detects server, tech stack, CMS, WAF. Recommends scan profile based on detected tech + available tools. Generates tailored `scorchkit.toml`. Optional `--project` flag creates DB project. `src/cli/init.rs` with 10 new tests (#49)
- **Project intelligence layer** — Per-module effectiveness tracking stored in `Project.settings` JSONB (no new migrations). `ModuleStats` per module: runs, findings, severity breakdown, effectiveness score. Updated after each scan. CLI: `project intelligence <name>`. AI planner enhanced with optional historical effectiveness context. `src/storage/intelligence.rs` with 11 new tests (#50)
- **Autonomous scan agent** (`agent <target>`) — 7-phase loop: setup → recon → AI plan → vulnerability scan → AI analyze → persist → report. Calls internal functions directly (Orchestrator, ScanPlanner, AiAnalyst). Graceful AI fallback — plan failure falls back to profile, analysis failure is non-fatal. `src/agent/runner.rs` with 3 new tests (#51)
- 32 new tests total across 4 features

## [0.28.0] - 2026-03-30

### Added
- **Agent SDK support** — `src/agent/` module for autonomous pentest operations via Claude Agent SDK
- **PTES-based agent system prompt** — 7-phase pentest methodology (pre-engagement through remediation) with built-in safety constraints: scope enforcement, no exploitation, evidence preservation, rate limiting
- **AgentConfig** — authorized targets, max scan depth, project persistence, safety constraints. Builder pattern with `with_depth()`, `with_project()`, `with_database_url()`
- **Manifest generator** — `generate_manifest()` produces JSON config for Claude Agent SDK clients (Python/TypeScript) with MCP server connection, system prompt, and safety rules
- 5 new unit tests + 1 doctest

## [0.27.0] - 2026-03-30

### Added
- **Plugin system for user-defined scan modules** — `src/runner/plugin.rs` with TOML-based plugin definitions. Users create `.toml` files defining custom scan modules with command, args (`{target}` placeholder substitution), output format (lines/json_lines/json), and default severity. `PluginModule` implements `ScanModule` trait seamlessly
- **Plugin loader** — `load_plugins()` discovers `.toml` files from configurable `plugins_dir`, validates and registers them alongside built-in modules
- **Orchestrator integration** — plugins auto-loaded in `register_default_modules()` when `plugins_dir` is set in config
- **`plugins_dir`** config option in `ScanConfig` for specifying the plugin directory
- 6 new unit tests (TOML parsing, metadata, arg substitution, line/JSON parsing, empty dir)

## [0.26.0] - 2026-03-30

### Added
- **HTTP evidence capture** — `src/engine/evidence.rs` with `HttpEvidence` struct for capturing full HTTP request/response pairs. Attached to findings via `.with_http_evidence()` builder. Response bodies auto-truncated at 10KB
- **Webhook notifications** — `src/runner/hooks.rs` with `ScanEvent` enum (`ScanStarted`, `ScanCompleted`, `FindingDiscovered`) and `WebhookNotifier`. Async fire-and-forget delivery via `tokio::spawn`. Config via `[[webhooks]]` array with URL + events filter
- **`WebhookConfig`** in `AppConfig` for configuring notification endpoints
- 6 new unit tests (3 evidence + 3 webhook)

## [0.25.0] - 2026-03-30

### Added
- **enum4linux SMB enumeration wrapper** — `src/tools/enum4linux.rs` for share listing, user enumeration via RID cycling, group discovery, and password policy extraction
- **Compliance framework mapping** — `src/engine/compliance.rs` with OWASP/CWE to NIST 800-53, PCI-DSS 4.0, SOC2, HIPAA control mapping. 10 OWASP categories + 13 CWEs mapped
- **Finding `.with_compliance()` builder** — attach compliance framework references to findings
- **Enhanced scope management** — `src/engine/scope.rs` with `ScopeRule` enum supporting exact domain, wildcard (`*.example.com`), and CIDR (`192.168.1.0/24`) matching
- 9 new unit tests (2 enum4linux + 3 compliance + 4 scope)
- ScorchKit now has 63 modules (31 built-in + 32 external tool wrappers)

## [0.24.0] - 2026-03-30

### Added
- **MCP prompt templates** — 5 pentest workflow starting points: `full-web-assessment`, `investigate-finding`, `remediation-plan`, `compare-scans`, `executive-summary`. Exposed via MCP prompts capability (`list_prompts`, `get_prompt`)
- **MCP `correlate_findings` tool** — Rule-based attack chain detection that groups related findings into compound vulnerabilities (e.g., XSS + missing CSP = session hijacking). 6 built-in correlation rules with severity escalation and remediation priority
- **`CorrelateFindingsParams`** type with `JsonSchema` derive
- 9 new tests (5 prompt unit tests + 3 integration tests + 1 correlation test)
- MCP server now exposes 19 tools + 5 prompts

## [0.23.0] - 2026-03-30

### Added
- **Trufflehog secret scanning wrapper** — `src/tools/trufflehog.rs` for detecting leaked API keys, credentials, and tokens in filesystems and git repos
- **Prowler cloud security wrapper** — `src/tools/prowler.rs` for AWS/multi-cloud infrastructure misconfiguration scanning
- **Trivy vulnerability scanning wrapper** — `src/tools/trivy.rs` for container image and dependency vulnerability detection with CVSS severity mapping
- **DNSx DNS toolkit wrapper** — `src/tools/dnsx.rs` for fast DNS resolution, wildcard detection, and record queries
- **Gobuster directory scanner wrapper** — `src/tools/gobuster.rs` for directory and vhost brute-forcing with status-based severity
- **dnsrecon DNS enumeration wrapper** — `src/tools/dnsrecon.rs` for comprehensive DNS enumeration including zone transfer detection
- 12 new unit tests (2 per wrapper for output parsing + empty handling)
- ScorchKit now has 62 modules (31 built-in + 31 external tool wrappers)

## [0.22.0] - 2026-03-30

### Added
- **MCP `auto_scan` composite tool** — One-shot full scan engagement: parse target, apply profile, run modules, optionally persist results to a project with finding deduplication
- **MCP `target_intelligence` composite tool** — Recon-only consolidated briefing: runs all Recon-category modules (headers, tech detection, discovery, subdomain, crawling, DNS) without active vulnerability scanning
- **MCP `scan_progress` status tool** — Post-hoc scan status check: latest scan record with timing, modules, finding count for a project
- 3 new parameter types (`AutoScanParams`, `TargetIntelligenceParams`, `ScanProgressParams`) with `JsonSchema` derives
- 3 new integration tests for parameter deserialization
- MCP server now exposes 18 tools (was 15)

## [0.21.0] - 2026-03-29

### Added
- **Katana web crawler wrapper** — `src/tools/katana.rs` for JS-rendered endpoint discovery via headless browsing
- **Gau passive URL discovery wrapper** — `src/tools/gau.rs` for historical URL collection from Wayback Machine, Common Crawl
- **ParamSpider parameter mining wrapper** — `src/tools/paramspider.rs` for discovering URLs with injectable query parameters
- 6 new unit tests (2 per wrapper for output parsing + empty handling)
- ScorchKit now has 56 modules (31 built-in + 25 external tool wrappers)

## [0.20.0] - 2026-03-29

### Added
- **REST API security testing module** — `src/scanner/api.rs` implementing OWASP API Top 10: mass assignment, excessive data exposure, shadow API discovery, auth endpoint rate limiting, content negotiation confusion
- **DNS & email security recon module** — `src/recon/dns.rs` using DNS-over-HTTPS (Cloudflare `DoH` JSON API): SPF record analysis with permissiveness detection, DMARC policy enforcement check, MX record discovery
- 6 new unit tests (3 API + 3 DNS)
- ScorchKit now has 53 modules (31 built-in + 22 external tool wrappers) and 7 recon modules

## [0.19.0] - 2026-03-29

### Added
- **Professional PDF pentest report generation** — `src/report/pdf.rs` with `--format pdf` CLI flag
- **6-section professional layout** — cover page, executive summary with risk rating, scope & methodology, risk matrix, detailed findings with evidence/remediation/OWASP/CWE, appendix with module list
- **Print-optimized CSS** — A4 page size, `@page` rules with page numbers, page breaks per section, professional color scheme
- **`weasyprint` integration** — HTML-to-PDF conversion via subprocess with stdin piping (no temp files)
- **`OutputFormat::Pdf`** variant in CLI args with dispatch in runner
- 8 new unit tests for HTML template structure, severity counts, finding details, print CSS, risk matrix, risk rating, categories, HTML escaping
- ScorchKit now supports 5 output formats: terminal, json, html, sarif, pdf

## [0.18.0] - 2026-03-29

### Added
- **Subdomain takeover detection module** — `src/scanner/subtakeover.rs` probing 15 common subdomains against 8 cloud provider fingerprints (GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, Pantheon, Tumblr)
- **Access control testing module** — `src/scanner/acl.rs` testing admin path discovery (20 paths), HTTP method override bypass, path traversal auth bypass (8 variants), and forced browsing to sequential API resource IDs
- 7 new unit tests (4 subtakeover + 3 ACL)
- ScorchKit now has 51 modules (29 built-in + 22 external tool wrappers)

## [0.17.0] - 2026-03-29

### Added
- **CORS deep analysis module** — `src/scanner/cors.rs` testing subdomain wildcards, internal network origin bypass, preflight cache abuse, method allowlist analysis, sensitive header exposure
- **CSP bypass detection module** — `src/scanner/csp.rs` testing missing critical directives (`base-uri`, `object-src`, `frame-ancestors`), permissive `script-src` (`data:`, `blob:`, `https:`), `report-uri` information leaks, wildcard `default-src`
- First merged pipeline — two modules (#16 + #17) in one pipeline
- 12 new unit tests (5 CORS + 7 CSP)
- ScorchKit now has 49 modules (27 built-in + 22 external tool wrappers)

## [0.16.0] - 2026-03-29

### Added
- **GraphQL deep security testing module** — `src/scanner/graphql.rs` implementing `GraphQLModule`
- **GraphQL endpoint discovery** — probes 10 common paths (`/graphql`, `/api/graphql`, `/gql`, etc.) via `{ __typename }` query
- **Introspection detection** — tests if full schema introspection is enabled, counts exposed types
- **Query depth abuse** — sends 15-level nested queries to detect missing depth limits
- **Batch query abuse** — tests batch query support (25 queries in one request) for DoS potential
- **Field suggestion leaks** — detects "Did you mean" information disclosure on misspelled fields
- **Mutation enumeration** — discovers exposed mutations via targeted introspection
- 8 new unit tests for query building, response analysis, and endpoint detection
- ScorchKit now has 46 modules (25 built-in + 22 external tool wrappers) — milestone: 100 default tests

## [0.15.0] - 2026-03-29

### Added
- **WebSocket security testing module** — `src/scanner/websocket.rs` implementing `WebSocketModule`
- **WS endpoint discovery** — probes 19 common WebSocket paths (`/ws`, `/socket.io`, `/cable`, `/hub`, `/signalr`, `/graphql`, etc.)
- **CSWSH detection** — Cross-Site WebSocket Hijacking via spoofed Origin header validation
- **Unencrypted WS detection** — flags `ws://` endpoints when HTTPS is available
- **Unauthenticated WS access** — detects WebSocket endpoints accepting connections without credentials
- **`tokio-tungstenite`** — new async WebSocket client dependency (MIT/Apache-2.0, `rustls-tls-native-roots` feature)
- 6 new unit tests for URL conversion, path generation, upgrade response detection
- ScorchKit now has 45 modules (23 built-in + 22 external tool wrappers)

## [0.14.0] - 2026-03-29

### Added
- **File upload vulnerability testing module** — `src/scanner/upload.rs` implementing `UploadModule`
- **Upload form discovery** — HTML parsing for `<input type="file">` with action URL resolution and hidden field extraction
- **9 upload bypass payloads** — PHP, JSP, double extension (.php.jpg), content-type mismatch, polyglot GIF+PHP, null byte filename, path traversal, SVG XSS, HTML upload
- **Heuristic acceptance detection** — status code + body keyword analysis to determine if uploads were accepted
- 8 new unit tests for form discovery, payload generation, acceptance heuristic
- ScorchKit now has 44 modules (22 built-in + 22 external tool wrappers)

### Changed
- `reqwest` dependency now includes `multipart` feature for file upload submission

## [0.13.0] - 2026-03-29

### Added
- **Authentication & session management testing module** — `src/scanner/auth.rs` implementing `AuthSessionModule`
- **Session ID entropy analysis** — Shannon entropy scoring to detect predictable session IDs (< 3.0 bits/char threshold)
- **Session fixation detection** — compares pre-auth vs post-auth session cookies to detect unchanged session IDs
- **Logout invalidation testing** — probes common logout paths then verifies session is actually invalidated
- **Session expiry analysis** — flags excessive `Max-Age` (> 24h) and far-future `Expires` dates
- **Multiple session cookie detection** — identifies fragmented session management (> 1 session cookie)
- **Credential-gated tests** — fixation and logout require `AuthConfig` credentials; passive checks run regardless
- 11 new unit tests for entropy, fixation, expiry, cookie parsing, credential detection
- ScorchKit now has 43 modules (21 built-in + 22 external tool wrappers)

## [0.12.0] - 2026-03-29

### Added
- **Interactsh OOB callback integration** — detect blind SSRF, XXE, RCE, and SQLi via out-of-band callbacks
- **`src/engine/oob.rs`** — shared OOB infrastructure: `InteractshSession` (subprocess lifecycle), `OobInteraction` (callback data), `BlindPayload`/`BlindCategory` (payload templates), correlation matching
- **`src/tools/interactsh.rs`** — `InteractshModule` implementing `ScanModule` with `requires_external_tool("interactsh-client")`
- 4 blind vulnerability categories with targeted payloads: SSRF (URL injection), XXE (entity injection), RCE (command injection via nslookup/curl/backtick), SQLi (DNS exfiltration via LOAD_FILE)
- Correlation via subdomain prefix: `{correlation_id}.{base_domain}` matches callbacks to originating payloads
- 10 new unit tests for interaction parsing, URL generation, correlation matching, payload generation
- ScorchKit now has 42 modules (20 built-in + 22 external tool wrappers)

## [0.11.0] - 2026-03-29

### Changed
- **Expanded all 20 MCP tool descriptions** — upgraded from terse one-liners to 2-4 sentence guidance blocks with when-to-use, key parameters, output format, and next-step recommendations
- **Expanded all parameter descriptions in `types.rs`** — `///` doc comments on `JsonSchema` fields now include valid values, examples, and decision guidance (schemars converts these to JSON Schema `description` fields)
- Claude now receives richer context for each tool call: what the tool does, when to choose it over alternatives, which parameters matter, and what to do with the results

## [0.10.0] - 2026-03-29

### Added
- **Rich MCP system instructions** — comprehensive pentest methodology delivered to Claude on connection
- **7-step engagement workflow** — PTES-adapted: project setup, recon, AI planning, targeted scan, analysis, triage, reporting
- **Tool reference** — all 20 MCP tools documented by category with decision guidance in instructions
- **Scan profile guide** — quick/standard/thorough selection criteria for Claude
- **Finding interpretation framework** — severity levels, lifecycle states, prioritization strategy
- **Safety constraints** — scope enforcement, authorization checks, user-directed triage
- **`src/mcp/instructions.rs`** — `pub const INSTRUCTIONS` (~4.5KB) referenced by `ServerInfo`
- 5 new tests (4 unit for instruction content validation + 1 integration)

### Changed
- `ServerInfo.instructions` upgraded from 2-line placeholder to comprehensive methodology guide
- MCP server now teaches Claude the complete pentest workflow on connection

## [0.9.0] - 2026-03-29

### Added
- **MCP resources** — browsable read-only resources for project data via MCP protocol
- **Resource URI scheme** — `scorchkit://projects`, `scorchkit://projects/{id}`, `.../scans`, `.../findings` with hierarchical paths
- **5 resource templates** — parameterized URI patterns for project, scan, and finding resources
- **Dynamic resource list** — `list_resources` returns projects collection + per-project resources from database
- **`src/mcp/resources.rs`** — resource business logic with `do_list_resources()`, `do_list_resource_templates()`, `do_read_resource()`
- **URI parser** — `parse_resource_uri()` with `ResourceKind` enum for type-safe dispatch
- 21 new tests (10 unit tests for URI parsing/templates + 11 integration tests for resource operations)

### Changed
- MCP server capabilities now include `resources` alongside `tools`
- `ServerHandler` impl overrides `list_resources`, `list_resource_templates`, `read_resource`

## [0.8.0] - 2026-03-29

### Added
- **Scan scheduling** — `scorchkit schedule create/list/show/enable/disable/delete` for recurring scans per project
- **`schedule run-due`** — explicitly triggers all overdue schedules (wire into system cron for automation)
- **`ScanSchedule` model** — project_id, target_url, profile, cron_expression, enabled, last_run, next_run
- **`storage/schedules.rs`** — CRUD + `find_due_schedules()` + `mark_schedule_run()` + `compute_next_run()`
- **`croner` crate** — lightweight cron expression parsing (5/6/7-field support)
- **Migration `002_scan_schedules.sql`** — `scan_schedules` table with partial index on `next_run WHERE enabled`
- **`schedule-scan` MCP tool** — create recurring scan schedules via MCP (19th tool)
- **`run-due-scans` MCP tool** — trigger due scan execution via MCP (20th tool, was 19)
- 8 new tests (6 storage-gated + 1 mcp-gated + 2 CLI integration)

### Changed
- `Commands` enum now includes `Schedule` subcommand (storage feature-gated)
- MCP server exposes 19 tools (was 17)
- New `croner` dependency added to `storage` feature

## [0.7.0] - 2026-03-29

### Added
- **AI-guided scan planning** — `scorchkit run <url> --plan` runs recon first, then Claude decides which modules to use
- **`ScanPlanner`** — two-phase flow: recon modules gather target intelligence, Claude analyzes findings + module catalog to build a targeted `ScanPlan`
- **`ScanPlan` types** — `ModuleRecommendation` (module_id, priority, rationale), `SkippedModule` (module_id, reason), `PlanValidation`
- **`validate_plan()`** — validates Claude's module recommendations against registered modules, catches hallucinated IDs
- **`plan-scan` MCP tool** — returns structured plan JSON without executing (plan-then-execute workflow)
- **`build_module_catalog()`** — serializes all 41 modules into a compact catalog for Claude's planning prompt
- **`parse_plan_response()`** — multi-tier JSON extractor with empty-plan fallback for graceful degradation
- **Graceful fallback** — if planning fails for any reason, scan continues with standard profile
- 14 new tests (12 default + 1 mcp-gated + 1 CLI integration)

### Changed
- `Commands::Run` now accepts `--plan` flag for AI-guided scanning
- MCP server exposes 17 tools (was 16)
- `run_scan()` restructured to support pre-orchestrator AI planning phase

## [0.6.0] - 2026-03-29

### Added
- **Posture metrics dashboard** — `scorchkit project status <name>` shows security posture at a glance
- **`TrendDirection` enum** — computed trend (Improving/Declining/Stable) from resolved vs active finding ratio
- **Severity breakdown** — finding counts grouped by severity, ordered critical to info
- **Status breakdown** — finding counts grouped by lifecycle status
- **Regression detection** — identifies findings marked remediated/verified that reappeared in the latest scan
- **Top unresolved findings** — top 10 active findings ranked by severity priority
- **`project-status` MCP tool** — returns posture metrics as typed JSON for AI consumption
- **`PostureMetrics` types** — `ScanSummary`, `FindingSummary`, `SeverityCount`, `StatusCount`, `RegressionFinding`, `UnresolvedFinding`
- **`build_posture_metrics()`** — aggregate SQL queries computing all metrics on-the-fly (no new migrations)
- 14 new tests (13 storage-gated + 1 mcp-gated + 1 cli integration)

### Changed
- `ProjectCommands` now includes `Status` subcommand
- MCP server exposes 16 tools (was 15)

## [0.5.0] - 2026-03-28

### Added
- **Structured AI analysis** — typed JSON responses for all 4 analysis modes (summary, prioritize, remediate, filter)
- **17 structured types** — `SummaryAnalysis`, `PrioritizedAnalysis`, `RemediationAnalysis`, `FilterAnalysis` with shared enums (`ExploitabilityRating`, `EffortLevel`, `FindingClassification`)
- **`StructuredAnalysis` enum** — wraps mode-specific types with `Raw` fallback for graceful degradation
- **Multi-tier JSON extractor** — parses Claude responses via direct parse, code fence extraction, balanced block detection, or raw fallback
- **Project history context** — `--project` flag on `analyze` injects scan trends and finding lifecycle stats into AI prompts
- **`analyze-findings` MCP tool** — AI-powered project finding analysis with structured JSON output
- **`ProjectContext` type** — scan history and finding trend data for context-aware analysis
- **`storage::context::build_project_context()`** — aggregates project stats from PostgreSQL
- 23 new tests (8 inline unit + 14 integration + 1 mcp-feature-gated)

### Changed
- `AiAnalysis` struct upgraded from raw text (`content: String`) to typed enum (`StructuredAnalysis`)
- `AnalysisFocus` now derives `Serialize, Deserialize` with snake_case
- `AnalysisFocus::from_str()` renamed to `parse()` to avoid shadowing `FromStr` trait
- AI prompts now request JSON output with documented schemas
- `print_analysis()` renders structured output per mode (risk scores, ranked lists, effort badges, classification tables)

## [0.4.0] - 2026-03-28

### Added
- **MCP server** — `scorchkit serve` starts an MCP server on stdio transport (requires `mcp` feature)
- **15 MCP tools** — list-modules, check-tools, scan, project-create, project-list, project-show, project-delete, project-scan, project-findings, finding-show, finding-update-status, target-add, target-list, target-remove, db-migrate
- **`mcp` Cargo feature** — feature-gated MCP server (implies `storage`), built on `rmcp` v1.3 crate
- **`ScorchKitServer`** — MCP server struct with `ServerHandler` impl and `#[tool_router]` dispatch
- **Parameter types** — `schemars` v1.0 JSON Schema generation for all tool inputs
- 17 new integration tests — one per MCP tool plus server infrastructure tests

## [0.3.0] - 2026-03-28

### Added
- **Project model CLI commands** — `scorchkit project create/list/show/delete` for managing security assessment projects
- **Target management** — `scorchkit project target add/remove/list` for managing project targets
- **Finding management** — `scorchkit finding list/show/status` for querying and updating vulnerability lifecycle
- **Database migration command** — `scorchkit db migrate` for schema initialization
- **Scan persistence** — `scorchkit run <url> --project <name>` persists scan records and findings to PostgreSQL
- **Database URL resolution** — `--database-url` CLI flag > `config.toml` > `DATABASE_URL` env var precedence
- **`connect_from_config()`** — shared DB connection helper with auto-migration support
- **`get_project_by_name()`** — lookup projects by name (users never need to type UUIDs)
- **`list_findings()`** — unfiltered project finding query
- All new commands feature-gated behind `storage` Cargo feature — default build unaffected

## [0.2.0] - 2026-03-28

### Added
- **PostgreSQL storage layer** (`src/storage/`) — persistent project, scan, and finding storage via `sqlx`
- **Project model** — create, list, get, update, delete projects with associated targets
- **Scan records** — store scan execution history linked to projects
- **Finding deduplication** — SHA-256 fingerprint (module_id + title + affected_target) deduplicates findings across scans
- **Vulnerability lifecycle tracking** — `VulnStatus` enum: New → Acknowledged → FalsePositive → Remediated → Verified
- **`storage` Cargo feature flag** — opt-in PostgreSQL support, default CLI build unaffected
- **`DatabaseConfig`** in `AppConfig` — configurable connection URL, pool size, auto-migration
- **Database migration** (`migrations/001_initial.sql`) — projects, project_targets, scan_records, tracked_findings tables with indexes
- **`Database` error variant** in `ScorchError` — clean error propagation from storage layer
- Pipeline enforcement system — CONSTITUTION.md, 8 hooks, 12 slash commands, pipeline templates
- `.semgrep.yml` — 8 Rust security rules
- `deny.toml` — license compliance and dependency advisory configuration
- `rustfmt.toml` — code formatting configuration

## [0.1.0] - 2026-03-25

### Added
- Initial release: 41 scan modules (20 built-in + 21 external tool wrappers)
- Claude AI integration for finding analysis
- 4 output formats: terminal, JSON, HTML, SARIF
- Scan diffing, profiles, proxy support, authenticated scanning
