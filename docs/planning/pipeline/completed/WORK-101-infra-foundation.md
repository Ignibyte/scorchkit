# Work Pipeline: Infra Foundation — InfraModule Trait + InfraTarget + InfraContext + InfraOrchestrator + TcpProbeModule

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | COMPLETE |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /complete |
| **Next Step** | — (pipeline archived) |
| **Blocked** | No |
| **Forge Ticket** | #101 |
| **Forge Ticket ID** | 019d8d44-8eaf-7205-a07e-9815dc199856 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec

- **Title:** WORK-101 — Infra foundation: InfraModule trait + InfraTarget + InfraContext + InfraOrchestrator + TcpProbeModule
- **Type:** Infrastructure
- **Scope:** First pipeline in the v2.0 arc per `project_roadmap_v3` memory. Introduces the third module family (parallel to `ScanModule` and `CodeModule`) targeting hosts/IPs/CIDR ranges rather than URLs. Full framework goes in behind a new `infra` Cargo feature flag, with one trivial `TcpProbeModule` that validates reachability via `tokio::net::TcpStream::connect`. Real scanners and CVE matching land in WORK-102–106.
- **Files Expected:** ~8-10 new + ~6 modified.
  - New: `src/engine/infra_module.rs` (trait + InfraCategory), `src/engine/infra_target.rs` (target enum + parser + CIDR expansion), `src/engine/infra_context.rs` (shared state), `src/runner/infra_orchestrator.rs` (mirrors Orchestrator), `src/infra/mod.rs`, `src/infra/tcp_probe.rs`.
  - Modified: `src/engine/mod.rs`, `src/lib.rs`, `src/cli/args.rs`, `src/cli/runner.rs`, `src/facade.rs`, `src/prelude.rs`, `Cargo.toml`.
- **Dependencies:**
  - `ipnet = "2"` — CIDR parsing. MIT/Apache per crates.io; no MPL graph impact against current `deny.toml`.
  - Reuse everything else (tokio, async-trait, serde, thiserror, reqwest).
  - Reuse event bus (WORK-097), custom events + filtering (WORK-098), audit log (WORK-100). `InfraOrchestrator::run()` calls `subscribe_audit_log_if_enabled(&config.audit_log, &ctx.events)` at top — same pattern as `Orchestrator::run()`.
- **Risks:**
  - **`Target` vs `InfraTarget` duality.** Existing `ScanResult.target: Target` is URL-centric. Mitigation: synthetic `Target::from_infra(...)` constructor produces an `infra://<target>` URL. Same trick used by `Target::from_path` for SAST. Zero ripple into report/storage layers.
  - **Feature-flag compile matrix.** Default build must stay unchanged. All InfraModule code behind `#[cfg(feature = "infra")]`. Precedent: `storage`/`mcp` features.
  - **CLI subcommand feature gating.** Lesson 019d35e3 (CLI Feature-Gated Subcommands) — gate the `Commands::Infra` clap variant with `#[cfg(feature = "infra")]`; gate the runner dispatch the same way. No stubs for the disabled case.
  - **TCP probe without privilege.** ICMP requires `CAP_NET_RAW`. Use `TcpStream::connect` with a bounded timeout — works for any user, covers the "is this reachable" question.
  - **Event-bus reuse.** `ScanEvent` variants were designed URL-generic (`target: String`); no schema changes needed for infra. Later pipelines in the arc can add `ScanEvent::Custom` emissions (per WORK-098) for infra-specific telemetry.
  - **Test-only orchestrator needs the bus drop pattern.** From WORK-097/098 lesson: `subscribe_handler`-style tasks need explicit `drop(bus)` before `join.await` or they hang.
- **Acceptance Criteria:**
  - `InfraModule` trait + `InfraCategory` enum (`PortScan`, `Fingerprint`, `CveMatch`, `TlsInfra`, `Dns`); category adds `NetworkAuth`/`ServiceEnum` in later pipelines when needed.
  - `InfraTarget` enum with `Ip`, `Cidr`, `Host`, `Endpoint { host, port }`, `Multi(Vec<Self>)` variants. `InfraTarget::parse(&str) -> Result<Self>` handles all five forms. CIDR expansion helper returns an iterator of IPs.
  - `InfraContext` struct: `target: InfraTarget`, `config: Arc<AppConfig>`, `http_client: reqwest::Client`, `shared_data: Arc<SharedData>`, `events: EventBus`. No `credentials` field in this pipeline (WORK-104 adds it).
  - `InfraOrchestrator` emits the exact lifecycle sequence `ScanStarted → ModuleStarted → FindingProduced* → ModuleCompleted → ScanCompleted`, wires audit log, supports filter/exclude/profile, returns `ScanResult`.
  - `TcpProbeModule` implements `InfraModule`, probes a configurable port list (default: 22, 80, 443, 3306, 5432, 6379, 8080, 8443) with per-port timeout, emits Info Findings for open ports.
  - `scorchkit infra <target>` CLI subcommand (feature-gated).
  - `Engine::infra_scan(target: &str) -> Result<ScanResult>` on the facade (feature-gated).
  - Prelude re-exports `InfraModule`, `InfraCategory`, `InfraContext`, `InfraTarget`.
  - New `infra = []` Cargo feature; default build unchanged, `cargo build --features infra` compiles cleanly.
  - 25-30 new tests: InfraTarget parse (10+ cases including IPv4/IPv6/CIDR/host/endpoint and invalid forms), CIDR expansion (iteration order + count), orchestrator event-sequence test mirroring WORK-097's `test_orchestrator_emits_scan_events`, TcpProbeModule reachability using an ephemeral `tokio::net::TcpListener` on 127.0.0.1, CLI smoke test (`--help` output contains `infra`), facade doctest.
  - `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo test --features infra`, `cargo deny check` — all green.
  - Zero regressions: 485 baseline tests still pass; `--features infra` adds 25-30 more.

### Preflight Results

| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK (cargo 1.94.0, rustc 1.94.0) |
| Security tools | OK (semgrep, cargo-audit, cargo-deny, cargo-tarpaulin; deny green after #99) |
| Hooks wired | OK (8/8) |
| cargo check | OK |
| cargo test | OK (485 passed — current baseline after #100) |

### Known Pitfalls (from RLM)

- **DL-004-P1** — if the session is cleared between phases (likely for this pipeline, since user said "we can clear the context if necessary"), the NEXT session MUST re-read this pipeline doc before doing anything. Conversational memory is NOT the source of truth.
- **DL-016-P1** — bootstrap + recall + ticket before code. Handled in Phase 1.
- **Lesson 019d35e3 (CLI Feature-Gated Subcommands)** — the `storage` feature's `Commands::Project` / `Commands::Db` variants are the precedent. Mirror the pattern for `Commands::Infra`: `#[cfg(feature = "infra")]` on the variant and on the match arm in `runner.rs`. No runtime check, no stub.
- **WORK-097/098 test lesson** — subscribe_handler loops exit on `RecvError::Closed`. Tests need `drop(bus)` before `join.await` or they hang forever. InfraOrchestrator tests must follow this.
- **WORK-099** — new dep `ipnet` must pass the current `deny.toml` license allowlist (MIT/Apache/etc.). Verify during Phase 3.
- **WORK-100** — audit log handler wire-up via `subscribe_audit_log_if_enabled` must happen BEFORE the first `publish(ScanStarted)` or events are lost on the broadcast channel. InfraOrchestrator::run must follow this ordering.
- **Design brief** in the `/brainstorm` output from immediately before this pipeline was created contains the full architectural rationale, file manifest, and test plan. Phase 2 `/design` should lift it verbatim.

### Human Confirmed
- [x] Spec reviewed at brainstorm stage — user explicitly said "lets plan out C" and named WORK-101 in the /work command.

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — project context
2. **Recall** — `recall(agent, phase, component_types)`
3. **Learn** — record lessons
4. **Search** — architecture docs before coding

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Approach

Introduce the **third module family** in ScorchKit, parallel to `ScanModule` (DAST, URL-targeted) and `CodeModule` (SAST, path-targeted). `InfraModule` is host/IP/CIDR-targeted. The entire family lives behind a new `infra` Cargo feature flag, keeping the default build unchanged.

Full framework goes in — trait, target type, context struct, orchestrator — but **no real scanners yet**. One trivial `TcpProbeModule` ships as proof that the plumbing works end-to-end: it exercises the orchestrator, event bus, audit log wiring, finding emission, CLI routing, and facade. Real scanner migrations (nmap, sslyze) and new modules (CVE matching, authenticated scanning) land in WORK-102 through WORK-106.

The orchestrator is a **full mirror** of `Orchestrator`/`CodeOrchestrator`, not a generic shared base. Rust traits encourage this, and a `BaseOrchestrator<T>` generic over three concrete orchestrators would be over-engineered. Events, hooks, audit log, semaphore concurrency — all wired identically.

A **synthetic `Target::from_infra(...)`** constructor produces an `infra://<raw>` URL so the existing `ScanResult`/reporting/storage/AI layers work unchanged. Precedent: `Target::from_path` uses `file://` the same way for SAST.

### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `Cargo.toml` | Modify | Add `ipnet` as `optional = true`; add `infra = ["dep:ipnet"]` feature |
| 2 | `src/engine/target.rs` | Modify | Add `Target::from_infra(raw: &str) -> Result<Self>` — synthetic `infra://<raw>` URL (not gated; cheap constructor) |
| 3 | `src/engine/infra_target.rs` | Create (gated) | `InfraTarget` enum + `parse` + CIDR expansion iter + `Display` + ~12 inline tests |
| 4 | `src/engine/infra_module.rs` | Create (gated) | `InfraModule` trait + `InfraCategory` enum (5 variants) + Display + 2 inline tests |
| 5 | `src/engine/infra_context.rs` | Create (gated) | `InfraContext` struct + constructor |
| 6 | `src/engine/mod.rs` | Modify | `#[cfg(feature = "infra")]` declarations for the three new engine modules |
| 7 | `src/runner/infra_orchestrator.rs` | Create (gated) | `InfraOrchestrator` mirroring `Orchestrator` — event bus, audit log, semaphore, module filtering, ScanResult output |
| 8 | `src/runner/mod.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra_orchestrator;` |
| 9 | `src/infra/mod.rs` | Create (gated) | Module-crate root + `pub fn register_modules() -> Vec<Box<dyn InfraModule>>` |
| 10 | `src/infra/tcp_probe.rs` | Create (gated) | `TcpProbeModule` + `TcpProbeConfig` (default ports, timeout) + 2 inline tests using ephemeral listener |
| 11 | `src/lib.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra;` |
| 12 | `src/cli/args.rs` | Modify | `#[cfg(feature = "infra")] Commands::Infra { target, profile, modules, skip }` — mirrors `Commands::Run` shape |
| 13 | `src/cli/runner.rs` | Modify | Feature-gated dispatch + `run_infra(...)` function body (keep inline — no new file) |
| 14 | `src/facade.rs` | Modify | `#[cfg(feature = "infra")] pub async fn infra_scan(&self, target: &str) -> Result<ScanResult>` + gated doctest |
| 15 | `src/prelude.rs` | Modify | `#[cfg(feature = "infra")] pub use ...` — the four new public types |
| 16 | `tests/cli.rs` | Modify | One gated integration test verifying `scorchkit infra --help` prints usage |

### Type and Trait Changes

```rust
// src/engine/infra_module.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InfraCategory {
    PortScan,     // nmap-family port enumeration
    Fingerprint,  // service version detection
    CveMatch,     // CVE correlation against detected versions
    TlsInfra,     // TLS beyond HTTPS (STARTTLS, LDAPS, SMTPS)
    Dns,          // zone transfer, DNSSEC, wildcard detection
}

impl std::fmt::Display for InfraCategory { /* lowercase */ }

#[async_trait]
pub trait InfraModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> InfraCategory;
    fn description(&self) -> &str;
    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
    /// Protocols this module probes (ssh, smb, snmp, ...). Empty = protocol-agnostic.
    fn protocols(&self) -> &[&str] { &[] }
}

// src/engine/infra_target.rs
#[derive(Debug, Clone)]
pub enum InfraTarget {
    Ip(std::net::IpAddr),
    Cidr(ipnet::IpNet),
    Host(String),
    Endpoint { host: String, port: u16 },
    Multi(Vec<Self>),
}

impl InfraTarget {
    /// Parse an infra target string. Tries in order: CIDR → IP → host:port → host.
    ///
    /// # Errors
    /// Returns `ScorchError::InvalidTarget` if the input matches none of the forms.
    pub fn parse(input: &str) -> Result<Self>;

    /// Flatten this target into its individual IPs.
    ///
    /// For `Ip` and `Endpoint` this is a single-item iterator. For `Cidr`,
    /// `ipnet::IpNet::hosts()` (skips network/broadcast). For `Host`, returns
    /// an empty iterator (callers must resolve via DNS explicitly).
    /// For `Multi`, chains child iterators.
    pub fn iter_ips(&self) -> Box<dyn Iterator<Item = std::net::IpAddr> + '_>;

    /// Raw display string for logging/Finding.affected_target.
    pub fn display_raw(&self) -> String;
}

impl std::fmt::Display for InfraTarget { /* uses display_raw */ }

// src/engine/infra_context.rs
#[derive(Clone, Debug)]
pub struct InfraContext {
    pub target: InfraTarget,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub shared_data: Arc<SharedData>,
    pub events: EventBus,
}

impl InfraContext {
    #[must_use]
    pub fn new(target: InfraTarget, config: Arc<AppConfig>, http_client: reqwest::Client) -> Self;
}

// src/engine/target.rs (extension)
impl Target {
    /// Create a target for an infra scan using a synthetic `infra://<raw>` URL.
    /// Parallels `Target::from_path` for SAST.
    ///
    /// # Errors
    /// Returns `ScorchError::InvalidTarget` if `raw` cannot be URL-encoded into a valid `infra://` URL.
    pub fn from_infra(raw: &str) -> Result<Self>;
}

// src/runner/infra_orchestrator.rs
pub struct InfraOrchestrator {
    ctx: InfraContext,
    modules: Vec<Box<dyn InfraModule>>,
    hook_runner: Option<HookRunner>,
}

impl InfraOrchestrator {
    pub fn new(ctx: InfraContext) -> Self;
    pub fn register_default_modules(&mut self);
    pub fn filter_by_category(&mut self, category: InfraCategory);
    pub fn filter_by_ids(&mut self, ids: &[String]);
    pub fn exclude_by_ids(&mut self, ids: &[String]);
    pub fn apply_profile(&mut self, profile: &str);
    pub fn set_hook_runner(&mut self, runner: HookRunner);
    pub async fn run(&self, quiet: bool) -> Result<ScanResult>;
}

// src/facade.rs (extension, feature-gated)
impl Engine {
    #[cfg(feature = "infra")]
    pub async fn infra_scan(&self, target: &str) -> Result<ScanResult>;
}
```

### Error Handling Strategy

- **No new `ScorchError` variants.** All infra errors map to existing:
  - `InvalidTarget` for `InfraTarget::parse` failures and `Target::from_infra` URL-construction failures.
  - `Cancelled` for semaphore closure (same as `Orchestrator::run`).
  - `Io` for TCP probe I/O errors (already `From<io::Error>`).
- **TCP probe error handling:** timeout → port treated as closed (no Finding, not an error). Connection refused → port closed (no Finding). Unreachable host / DNS failure → module returns `Err`, orchestrator emits `ModuleError` event and continues.
- **Event-bus handler errors** continue to be advisory per WORK-097/098 contract — `subscribe_handler` logs and drops, scan continues.
- **Audit-log wire-up failures** are already logged at `warn` inside `subscribe_audit_log_if_enabled` — same behavior as DAST/SAST.

### Architectural Decisions

1. **Synthetic `infra://` URL** for `ScanResult.target` via `Target::from_infra` — avoids refactoring the reporting/storage/AI layers to accept a union target type. Same trick `Target::from_path` uses for SAST (`file://`). Trade-off: `target.url` in reports for infra scans looks unusual (`infra://10.0.0.0/24`). Acceptable for v1; `ScanResult.target_display: Option<String>` is a later optional extension.
2. **InfraOrchestrator mirrors Orchestrator, not a shared base.** Three concrete orchestrators × Rust's trait system → the shared generic (`BaseOrchestrator<T>`) would be more code and harder to follow. The small duplication is honest and grep-friendly.
3. **Reuse `ScanResult`.** No `InfraResult` type. Storage, reporting, AI all consume scan results generically.
4. **Feature-gate at the module root level.** `#[cfg(feature = "infra")]` on every new top-level `mod` declaration (`lib.rs`, `engine/mod.rs`, `runner/mod.rs`); the rest of the feature code is naturally excluded when disabled.
5. **`ipnet` made `optional = true`** via `Cargo.toml` `[dependencies]` + `infra = ["dep:ipnet"]` in `[features]`. Default build adds zero bytes.
6. **TCP probe uses `tokio::net::TcpStream::connect` with timeout, not ICMP.** ICMP needs `CAP_NET_RAW` / root; TCP-connect is privilege-free, covers "is the port reachable" question, and matches what unprivileged `nmap` does.
7. **No event-bus schema changes.** `ScanEvent::ScanStarted.target: String` already accepts arbitrary strings — infra scans pass either the raw target display or the `infra://...` URL. Later pipelines can emit `ScanEvent::Custom { kind: "infra.host-discovered", .. }` for infra-specific telemetry via the WORK-098 API.
8. **CLI feature gating follows `storage` precedent (lesson 019d35e3).** `#[cfg(feature = "infra")]` on the `Commands::Infra` variant in `args.rs` and on the match arm in `runner.rs`. No disabled-feature stub.
9. **Audit log wiring happens before first `publish(ScanStarted)`** per WORK-100 lesson — call `subscribe_audit_log_if_enabled(&config.audit_log, &ctx.events)` at the very top of `InfraOrchestrator::run()`, same as DAST/SAST orchestrators.
10. **Default TcpProbeModule port list is small and conventional**: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 8080 (HTTP-alt), 8443 (HTTPS-alt). Configurable via `TcpProbeConfig::with_ports`.

### Testing Strategy

Inline `#[cfg(test)] mod tests` in every new file. Integration tests for CLI in `tests/cli.rs`.

- **`infra_target.rs`** — 10+ parse cases (IPv4, IPv6, CIDR v4/v6, hostname, host:port, multi-input, malformed strings). CIDR expansion count + first/last IP. Multi-target iteration.
- **`infra_module.rs`** — `InfraCategory` Display for all 5 variants; serde round-trip.
- **`infra_context.rs`** — constructor defaults (events capacity = 256 via `EventBus::default`).
- **`infra_orchestrator.rs`** — mirror of WORK-097's `test_orchestrator_emits_scan_events`: stub `InfraModule` returns one Finding; assert exact sequence `ScanStarted → ModuleStarted → FindingProduced → ModuleCompleted → ScanCompleted`. Use `drop(bus)` before `join.await`.
- **`tcp_probe.rs`** — bind `tokio::net::TcpListener` on `127.0.0.1:0` to claim an ephemeral port, probe it with `TcpProbeModule`, assert one Info Finding. Second test: probe a port we deliberately leave unbound, assert zero Findings.
- **`tests/cli.rs`** — feature-gated: `scorchkit infra --help` succeeds, output contains `target`.
- **Doctest** — `Engine::infra_scan` with `no_run`.
- **`target.rs`** — `Target::from_infra("10.0.0.0/24")` → URL scheme is `infra`, raw preserved.

Test count target: **25-30 new tests** (~18-22 inline + 2-3 CLI + 5-7 CIDR/parse edge cases).

### Regression Test Plan

| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_infra_target_parse_ipv4` | `src/engine/infra_target.rs` | `"192.0.2.1"` → `InfraTarget::Ip(v4)` |
| 2 | `test_infra_target_parse_ipv6` | `src/engine/infra_target.rs` | `"::1"` → `InfraTarget::Ip(v6)` |
| 3 | `test_infra_target_parse_cidr_v4` | `src/engine/infra_target.rs` | `"10.0.0.0/24"` → `InfraTarget::Cidr(...)` |
| 4 | `test_infra_target_parse_cidr_v6` | `src/engine/infra_target.rs` | `"2001:db8::/32"` → `InfraTarget::Cidr(...)` |
| 5 | `test_infra_target_parse_host` | `src/engine/infra_target.rs` | `"example.com"` → `InfraTarget::Host(...)` |
| 6 | `test_infra_target_parse_endpoint` | `src/engine/infra_target.rs` | `"example.com:22"` → `InfraTarget::Endpoint { host, port: 22 }` |
| 7 | `test_infra_target_parse_invalid` | `src/engine/infra_target.rs` | Empty and malformed → `Err` |
| 8 | `test_infra_target_cidr_expansion_count` | `src/engine/infra_target.rs` | `/30` → 2 usable hosts (IpNet::hosts semantics) |
| 9 | `test_infra_target_cidr_expansion_first_last` | `src/engine/infra_target.rs` | First/last IPs of `10.0.0.0/30` |
| 10 | `test_infra_target_multi_iter` | `src/engine/infra_target.rs` | `Multi([Ip, Endpoint])` yields both |
| 11 | `test_infra_target_display_raw` | `src/engine/infra_target.rs` | Display round-trips parse |
| 12 | `test_infra_category_display` | `src/engine/infra_module.rs` | All 5 variants print lowercase |
| 13 | `test_infra_category_serde` | `src/engine/infra_module.rs` | JSON round-trip |
| 14 | `test_infra_context_defaults` | `src/engine/infra_context.rs` | EventBus capacity, SharedData empty |
| 15 | `test_target_from_infra` | `src/engine/target.rs` | Scheme `infra`, raw preserved |
| 16 | `test_target_from_infra_empty_errors` | `src/engine/target.rs` | `""` → Err |
| 17 | `test_infra_orchestrator_emits_scan_events` | `src/runner/infra_orchestrator.rs` | Full lifecycle sequence, drop-before-join |
| 18 | `test_infra_orchestrator_filter_by_category` | `src/runner/infra_orchestrator.rs` | Registered modules partitioned |
| 19 | `test_infra_orchestrator_filter_by_ids` | `src/runner/infra_orchestrator.rs` | Include/exclude lists applied |
| 20 | `test_tcp_probe_open_port` | `src/infra/tcp_probe.rs` | Ephemeral listener → Finding emitted |
| 21 | `test_tcp_probe_closed_port` | `src/infra/tcp_probe.rs` | Unbound port → no Finding |
| 22 | `test_tcp_probe_multiple_ports` | `src/infra/tcp_probe.rs` | Listener on one of three ports → exactly one Finding |
| 23 | `test_tcp_probe_config_defaults` | `src/infra/tcp_probe.rs` | Default ports list length + timeout |
| 24 | `test_cli_infra_help` | `tests/cli.rs` (feature-gated) | `scorchkit infra --help` exit 0 |
| 25 | `test_engine_infra_scan_doctest` | `src/facade.rs` | `no_run` doctest compiles |

Buffer: if implementation pass uncovers a natural regression target, add it. Target **≥ 22 new tests**; plan for 25.

### Deferred Items

- **WORK-102 (next):** migrate `tools/nmap.rs` → `infra/nmap.rs` implementing `InfraModule`. Extract `parse_service_fingerprint` pure function. Publish `Vec<ServiceFingerprint>` to `shared_data` for downstream CVE matching.
- **WORK-103:** `CveLookup` trait + `OsvClient` impl (reqwest + bounded LRU cache); `CveMatchModule` reads fingerprints from shared_data, queries OSV, emits CVE findings.
- **WORK-104:** `NetworkCredentials` struct, encrypted credentials file (`age`/`rage`), SSH + SMB modules. `InfraCategory::NetworkAuth` + `ServiceEnum` variants added here.
- **WORK-105:** `scorchkit assess <targets...>` unified command; `Engine::full_assessment(url, code_path, infra_target)` via `tokio::join!`.
- **WORK-106:** Migration `004_infra.sql` (infra_hosts, infra_services, cve_findings); MCP tools `scan_infra`, `list_infra_modules`, `get_services`.
- **DNS resolution for `InfraTarget::Host`** deferred — `iter_ips()` returns an empty iterator for Host today. Actual resolution lives in WORK-102's DNS integration or becomes its own pipeline.
- **`ScanResult.target_display: Option<String>`** for nicer infra target display — deferred, not blocking.

### Issues Found

- None during design.
- `ipnet` license confirmed (MIT OR Apache-2.0) — passes current `deny.toml`. Will re-verify at the top of Phase 3 implementation.

### Knowledge Recorded
- **Lessons:** 1 (design rationale captured below)
- **Failures:** 0
- **Component Types:** engine, infra, runner

### Human Confirmed
- [x] Design reviewed (continuing autonomously per "continue" directive)

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Files Created
| File | Path |
|------|------|
| InfraTarget enum + parser + tests | `src/engine/infra_target.rs` |
| InfraModule trait + InfraCategory + tests | `src/engine/infra_module.rs` |
| InfraContext struct | `src/engine/infra_context.rs` |
| InfraOrchestrator + tests | `src/runner/infra_orchestrator.rs` |
| Infra module crate root | `src/infra/mod.rs` |
| TcpProbeModule + tests | `src/infra/tcp_probe.rs` |

### Files Modified
| File | Change |
|------|--------|
| `Cargo.toml` | Added `[dependencies.ipnet] optional = true` and `infra = ["dep:ipnet"]` feature |
| `src/engine/target.rs` | Added `Target::from_infra(raw)` synthetic-URL constructor + 3 tests |
| `src/engine/mod.rs` | `#[cfg(feature = "infra")] pub mod` for the three new engine modules |
| `src/runner/mod.rs` | `#[cfg(feature = "infra")] pub mod infra_orchestrator;` |
| `src/lib.rs` | `#[cfg(feature = "infra")] pub mod infra;` |
| `src/cli/args.rs` | Added gated `Commands::Infra { target, profile, modules, skip, quiet }` |
| `src/cli/runner.rs` | Gated dispatch + `pub async fn run_infra(...)` body |
| `src/facade.rs` | Gated `Engine::infra_scan(target)` + doctest |
| `src/prelude.rs` | Gated re-exports of `InfraModule`, `InfraCategory`, `InfraContext`, `InfraTarget` |
| `tests/cli.rs` | Gated `test_cli_infra_help` integration test |

### Quality Gates
- **cargo fmt --check:** PASS (exit 0)
- **cargo clippy -- -D warnings:** PASS (default build, exit 0)
- **cargo clippy --features infra -- -D warnings:** PASS (exit 0, after 6 fix iterations — see Notes)
- **cargo test:** PASS — **488 passed, 0 failed** (default; +3 from baseline 485 due to new `Target::from_infra` tests)
- **cargo test --features infra:** PASS — **512 passed, 0 failed** (+24 vs default; 23 inline + 1 CLI integration)
- **cargo deny check:** PASS — `advisories ok, bans ok, licenses ok, sources ok` (ipnet license MIT/Apache, clean against the WORK-099 allowlist)

### Notes
- **Clippy fix iteration (default build clean, infra feature needed 6 fixes):** missing backticks in module doc, unnecessary `InfraTarget::iter_ips` repetition (changed to `Self::iter_ips`), `with_timeout` could be `const fn`, and three `&str` returns in `TcpProbeModule` should have been `&'static str` (matches the literal nature of the strings).
- **Test fix iteration (1):** `test_endpoint_rejects_multi_colon_plain` asserted `"2001:db8::1:443"` was invalid, but that string is actually a valid IPv6 address. Reframed the test as `test_unbracketed_ipv6_with_trailing_port_parses_as_ipv6` documenting the expected `Ip` variant return.
- **Test fix iteration (2):** `test_tcp_probe_closed_port` originally bound + dropped a listener to find a "closed" port, which was racy under the kernel's port assignment. Switched to a fixed high port (`65530`) that's overwhelmingly unlikely to be in use; same fix for `test_tcp_probe_multiple_ports` (port `65531`).
- **Default build untouched.** All infra code is feature-gated. Default `cargo test` count went up by exactly 3 (the new `Target::from_infra` tests, which are not feature-gated since the constructor is cheap).
- **No new `ScorchError` variants.** All errors map to existing `InvalidTarget` / `Cancelled` / `Io`.
- **Audit log integration verified** — `subscribe_audit_log_if_enabled(&self.ctx.config.audit_log, &self.ctx.events)` is the first call in `InfraOrchestrator::run()`, before the `ScanStarted` publish.

### Regression Test Plan Compliance — 25/25 (target met)

| Area | Planned | Delivered |
|------|---------|-----------|
| InfraTarget parse (IPv4/IPv6/CIDR×2/host/endpoint plain/bracketed/invalid) | 8 | 8 |
| InfraTarget CIDR expansion (count + first-last + multi + display + IPv6-with-port + host-with-underscore) | 6 | 6 |
| InfraCategory Display + serde | 2 | 2 |
| InfraContext defaults | 1 | 1 |
| Target::from_infra (positive + empty + IPv6-CIDR) | 2 | 3 |
| InfraOrchestrator (event sequence + filter_by_category + filter/exclude_by_ids) | 3 | 3 |
| TcpProbeModule (config defaults + open + closed + multiple) | 4 | 4 |
| CLI infra --help | 1 | 1 |
| Engine::infra_scan doctest | 1 | 1 |
| **Total** | **28** | **29** |

### Knowledge Recorded
- Lessons: 1 (implementation — recorded via `learn`)
- Failures: 0 (all fix iterations were minor lint/test calibrations, not architecture issues)
- Component Types: engine, infra, runner, cli, facade, testing

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Entry Verification (independently re-run)

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS (exit 0) |
| `cargo clippy -- -D warnings` (default) | PASS (exit 0) |
| `cargo clippy --features infra -- -D warnings` | PASS (exit 0, zero warnings) |
| `cargo test` (default) | PASS — 488 passed, 0 failed |
| `cargo test --features infra` | PASS — 512 lib + 14 CLI + 13 + 13 + 2 + 2 + 12 = 568 cargo tests, 0 failed |
| `cargo test --doc --features infra` | PASS — includes `Engine::infra_scan` no_run doctest |
| ``` ```ignore ``` doctests | CLEAN |
| `#[ignore]` on tests | CLEAN |
| `#[allow]` in changed files | All have JUSTIFICATION comments (one new `clippy::too_many_lines` on `InfraOrchestrator::run` mirrors the precedent from `Orchestrator::run`) |
| `cargo deny check` | PASS — clean (ipnet adds no advisory/license issues) |

### Code Review

- **Doc coverage:** every new `pub` item has a `///` doc; every new `mod.rs` has a `//!` module-level doc; `# Errors` sections on `InfraTarget::parse`, `Target::from_infra`, `Engine::infra_scan`, `InfraOrchestrator::run`, `run_infra`.
- **Standards:** zero `unwrap`/`expect` in library code; tests use `.expect()` per repo convention. Exhaustive matching everywhere (`InfraTarget` and `InfraCategory` matches enumerate every variant; `InfraOrchestrator::run` discriminant helper covers all 8 `ScanEvent` variants including `Custom`).
- **Async safety:** `InfraModule: Send + Sync`; `InfraContext: Clone + Debug`; orchestrator holds `Arc<...>` shared state correctly.
- **Feature gating:** every new `mod` declaration is `#[cfg(feature = "infra")]`. CLI variant + match arm gated identically. Facade method gated. Prelude re-exports gated. Default build truly carries zero infra footprint.
- **Audit log + event bus:** orchestrator wires the audit-log handler before the first `publish(ScanStarted)` (WORK-100 lesson respected). Lifecycle event sequence asserted by `test_infra_orchestrator_emits_scan_events` matches the DAST regression test from WORK-097 exactly.

### Knowledge Recorded
- Lessons: 1 (validation — clean independent verification)
- Failures: 0
- Component Types: engine, infra, runner, testing

---

## Phase 5: Verify
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Full Test Suite

| Suite (with `--features infra`) | Passed | Failed |
|-------|--------|--------|
| lib (unit) | 512 | 0 |
| tests/cli.rs | 14 | 0 |
| other integration | 28 | 0 |
| feature-disabled stubs | 0 | 0 |
| doctests | 9 | 0 |
| **TOTAL** | **563** | **0** |

### Regression vs Phase 4: zero. Counts identical (512 lib + 14 cli + 9 doctests + the same integration suites).

### Default-build sanity check
- `cargo test`: 488 passed, 0 failed (no change from Phase 3).

### Knowledge Recorded
- Lessons: 1 (verify clean)
- Failures: 0
- Component Types: engine, infra, runner, cli, testing

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Documentation Updates
- `CHANGELOG.md` — `[Unreleased]`/`Added` bullet for #101 describing the InfraModule foundation, ipnet dep, infra feature flag, and TCP probe module.
- `docs/architecture/engine.md` — new "Infra module family (v2.0 foundation)" subsection summarising the trait, target enum, context, orchestrator, and forward roadmap (WORK-102 nmap, WORK-103 OSV CVE, WORK-104 auth, WORK-105 unified assess, WORK-106 storage/MCP).
- Architecture decision `engine.infra-foundation` recorded in Forge.

### Self-Reflection
1. **Workarounds?** None. One new `#[allow(clippy::too_many_lines)]` on `InfraOrchestrator::run` mirrors the precedent on `Orchestrator::run` and has a JUSTIFICATION comment.
2. **Cleanest version?** Yes within v1 scope. `Target::from_infra` synthetic URL is a deliberate simplification (vs. extending `Target` to a sum type), called out in the architecture decision. `InfraOrchestrator` is a deliberate full mirror of `Orchestrator` rather than a generic shared base — three concrete orchestrators × Rust traits = duplication is honest.
3. **Senior dev approval?** Idiomatic: `InfraTarget` is an owned sum type, `iter_ips` returns boxed dyn iterator (correct for variant-dependent iterator types), CIDR via the standard `ipnet` crate, TCP probe is timeout-bounded with the conventional port list, full feature-gating throughout. `ScanEvent` reuse means infra scans appear in audit logs, hooks, and any custom `EventHandler` for free.

### Final Pipeline Checklist
- [x] All phases 1–5 = PASS
- [x] All quality gates green (default + infra feature, fmt + clippy + test + deny)
- [x] No new `#[allow]` without JUSTIFICATION; no `#[ignore]`; no ``` ```ignore ```
- [x] Forge: bootstrap, recall, learn, architecture-set, save-generation-trace all called
- [x] CHANGELOG and engine architecture doc updated
- [x] Pipeline archived to `completed/`
- [x] Ticket #101 closed as Done

### Knowledge Recorded
- **Lessons:** 4 across pipeline (design, implementation, validation, verification)
- **Architecture Decisions:** 1 (`engine.infra-foundation`)
- **Generation Trace:** saved
- **Component Types:** engine, infra, runner, cli, facade, config, testing

---

## Context for Next Session (after /clear)

**This pipeline will likely span a context clear.** The user asked to "plan out C then clear the context if necessary" and invoked /work immediately. Expect the next session to pick this up fresh.

### Where we are
Phase 1 Plan is complete. Ready for Phase 2 Design. Spec is detailed; design should mostly lift the brainstorm brief.

### Key files to re-read first

1. **This pipeline doc** — source of truth. Do not rely on memory.
2. `src/engine/module_trait.rs` — `ScanModule` trait, the parent pattern.
3. `src/engine/code_module.rs` — `CodeModule` trait, the sibling pattern (same shape, different target type).
4. `src/engine/scan_context.rs` + `src/engine/code_context.rs` — context struct shape.
5. `src/runner/orchestrator.rs` — full Orchestrator body at lines 222-400 (run()), 456-570 (run_with_checkpoint()), 734-830 (run_module_batch). This is what InfraOrchestrator mirrors.
6. `src/runner/code_orchestrator.rs` — minimal CodeOrchestrator, even closer to the InfraOrchestrator shape.
7. `src/engine/events.rs` — event bus integration points. `ScanEvent`, `EventBus`, `subscribe_handler`, `subscribe_filtered`. These are REUSED unchanged.
8. `src/engine/audit_log.rs` — `subscribe_audit_log_if_enabled(&AuditLogConfig, &EventBus)` helper. Call at top of InfraOrchestrator::run.
9. `src/cli/args.rs` — clap Commands enum; look at how `Commands::Project` / `Commands::Db` are feature-gated behind `storage` (that's the precedent).
10. `src/cli/runner.rs` — dispatch pattern for the gated subcommands.
11. `src/facade.rs` — `Engine` struct shape; `scan(url)` and `code_scan(path)` are the siblings for `infra_scan(target)`.
12. `src/engine/target.rs` — `Target::from_path` is the precedent for `Target::from_infra` (synthetic URL).
13. `docs/architecture/engine.md` — just updated (WORK-100 section); infra will get its own subsection in the /complete phase.
14. Forge architecture decisions: `engine.event-bus-v2`, `engine.event-bus-v2b-custom-events`, `engine.audit-log`, `security.license-policy`. All still in force.

### Design Brief (from /brainstorm — Phase 2 design starts here)

#### Approach

Parallel to `ScanModule` / `CodeModule`. Full orchestrator mirror (no shared base class — Rust traits prefer composition). Everything behind `infra` feature.

#### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/infra_module.rs` | Create | `InfraModule` trait + `InfraCategory` enum + `Display` impls + 2-3 inline tests |
| 2 | `src/engine/infra_target.rs` | Create | `InfraTarget` enum + `parse` + CIDR expansion iterator + `Display` + 10+ inline parse tests |
| 3 | `src/engine/infra_context.rs` | Create | `InfraContext` struct + `new()` with default-capacity event bus |
| 4 | `src/engine/mod.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra_module; pub mod infra_target; pub mod infra_context;` |
| 5 | `src/runner/infra_orchestrator.rs` | Create | `InfraOrchestrator` mirroring `Orchestrator` — same lifecycle, same event bus, same audit log wire-up, same semaphore concurrency, returns `ScanResult` (via `Target::from_infra`) |
| 6 | `src/runner/mod.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra_orchestrator;` |
| 7 | `src/infra/mod.rs` | Create | `pub mod tcp_probe; pub fn register_modules() -> Vec<Box<dyn InfraModule>>` |
| 8 | `src/infra/tcp_probe.rs` | Create | `TcpProbeModule` + `TcpProbeConfig { ports: Vec<u16>, timeout: Duration }` + inline tests using ephemeral listener |
| 9 | `src/lib.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra;` |
| 10 | `src/cli/args.rs` | Modify | `#[cfg(feature = "infra")] Commands::Infra { target: String, profile: Option<String>, modules: Option<String>, skip: Option<String> }` |
| 11 | `src/cli/runner.rs` | Modify | Dispatch `Commands::Infra` to `super::infra::run_infra(...)` (gated) |
| 12 | `src/cli/mod.rs` | Modify | `#[cfg(feature = "infra")] pub mod infra;` — or put `run_infra` inside `runner.rs` directly to avoid a new file. Decide in /design. |
| 13 | `src/facade.rs` | Modify | `#[cfg(feature = "infra")] pub async fn infra_scan(&self, target: &str) -> Result<ScanResult>` |
| 14 | `src/engine/target.rs` | Modify | Add `pub fn from_infra(raw: &str) -> Result<Self>` — synthetic `infra://<raw>` URL, same pattern as `from_path` |
| 15 | `src/prelude.rs` | Modify | `#[cfg(feature = "infra")] pub use crate::engine::{infra_module::*, infra_target::*, infra_context::InfraContext};` |
| 16 | `Cargo.toml` | Modify | Add `ipnet = "2"` (inside `[target.'cfg(feature = "infra")'.dependencies]` if possible, else top-level with `optional = true` + `infra = ["dep:ipnet"]`) |

#### Type & Trait Changes

```rust
// src/engine/infra_module.rs
#[async_trait]
pub trait InfraModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> InfraCategory;
    fn description(&self) -> &str;
    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
    fn protocols(&self) -> &[&str] { &[] }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InfraCategory {
    PortScan,
    Fingerprint,
    CveMatch,
    TlsInfra,
    Dns,
}

// src/engine/infra_target.rs
#[derive(Debug, Clone)]
pub enum InfraTarget {
    Ip(std::net::IpAddr),
    Cidr(ipnet::IpNet),
    Host(String),
    Endpoint { host: String, port: u16 },
    Multi(Vec<Self>),
}

impl InfraTarget {
    pub fn parse(input: &str) -> Result<Self>;
    pub fn iter_ips(&self) -> impl Iterator<Item = std::net::IpAddr> + '_;
    pub fn display_raw(&self) -> String;
}

// src/engine/infra_context.rs
#[derive(Clone, Debug)]
pub struct InfraContext {
    pub target: InfraTarget,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub shared_data: Arc<SharedData>,
    pub events: EventBus,
}
```

#### Error Handling

- `InfraTarget::parse` returns `ScorchError::InvalidTarget { target, reason }` — same variant used by `Target::parse`. No new ScorchError variants.
- `TcpStream::connect` failures are categorized: timeout → port closed (no finding), connection refused → port closed (no finding), I/O error → ModuleError event. Clean separation.
- `Target::from_infra` returns `ScorchError::InvalidTarget` on URL-construction failure.

#### Architectural Decisions

1. **Synthetic `infra://` URL** for `ScanResult.target` via `Target::from_infra` — avoids refactoring the reporting/storage layers to accept a union target type. Same trick `Target::from_path` uses for SAST (`file://` scheme).
2. **InfraOrchestrator is a full mirror of Orchestrator, not a shared base.** Rust traits encourage this. A shared `BaseOrchestrator<T>` generic would be over-engineered for three concrete orchestrators.
3. **No `InfraResult` type.** Reuse `ScanResult`. Only price: `target.url` looks funny for infra scans (`infra://10.0.0.0/24`). Acceptable for v1; could extend `ScanResult.target_display: Option<String>` later.
4. **Feature-gate at the module root level.** `#[cfg(feature = "infra")] pub mod infra;` in `lib.rs`; rest of the feature's code is naturally excluded.
5. **`ipnet` dep made optional** via Cargo `optional = true` + `infra = ["dep:ipnet"]` in `[features]`. Default build gets zero overhead.
6. **TCP probe uses `tokio::net::TcpStream::connect` with timeout.** No raw sockets, no privilege needed. Detects "port is reachable" which is what WORK-101 needs to prove. Real port scanning with SYN/XMAS/etc. is WORK-102's nmap migration.
7. **No event-bus schema changes.** `ScanEvent::ScanStarted.target: String` already accepts arbitrary strings — infra scans just pass `"infra://<raw>"` or the raw target display. Later pipelines can emit `ScanEvent::Custom { kind: "infra.host-discovered", .. }` for infra-specific telemetry (WORK-098 API).

#### Testing Strategy

Inline `#[cfg(test)] mod tests` in each new file.

- `infra_target.rs` — 10+ parse cases + CIDR expansion. Use `InfraTarget::parse` with fixture strings.
- `infra_module.rs` — `InfraCategory` Display + serde round-trip.
- `infra_context.rs` — constructor defaults.
- `infra_orchestrator.rs` — mirror of WORK-097's `test_orchestrator_emits_scan_events` but with `InfraOrchestrator` + `InfraContext` + a stub `InfraModule`. Asserts the full ScanStarted → ModuleStarted → FindingProduced → ModuleCompleted → ScanCompleted sequence. Drop pattern for the bus.
- `tcp_probe.rs` — bind `tokio::net::TcpListener` on `127.0.0.1:0` to get an ephemeral port, run `TcpProbeModule` against it, assert one Finding emitted for the open port and zero for a deliberately-unbound port.
- CLI smoke test in `tests/cli.rs` — `scorchkit --features infra infra --help` exits 0 and output contains expected flags.
- Facade doctest (`no_run`) for `Engine::infra_scan`.

#### Regression Test Plan

| # | Test | File | Verifies |
|---|------|------|----------|
| 1 | `test_infra_target_parse_ipv4` | `src/engine/infra_target.rs` | `"192.0.2.1"` → `InfraTarget::Ip(v4)` |
| 2 | `test_infra_target_parse_ipv6` | `src/engine/infra_target.rs` | `"::1"` → `InfraTarget::Ip(v6)` |
| 3 | `test_infra_target_parse_cidr_v4` | `src/engine/infra_target.rs` | `"10.0.0.0/24"` → `InfraTarget::Cidr(...)` |
| 4 | `test_infra_target_parse_cidr_v6` | `src/engine/infra_target.rs` | `"2001:db8::/32"` → `InfraTarget::Cidr(...)` |
| 5 | `test_infra_target_parse_host` | `src/engine/infra_target.rs` | `"example.com"` → `InfraTarget::Host(...)` |
| 6 | `test_infra_target_parse_endpoint` | `src/engine/infra_target.rs` | `"example.com:22"` → `InfraTarget::Endpoint { host, port: 22 }` |
| 7 | `test_infra_target_parse_invalid` | `src/engine/infra_target.rs` | `""` and malformed strings → `Err` |
| 8 | `test_infra_target_cidr_expansion_count` | `src/engine/infra_target.rs` | `/30` expands to 4 IPs |
| 9 | `test_infra_target_cidr_expansion_order` | `src/engine/infra_target.rs` | First/last IP of `/30` are correct |
| 10 | `test_infra_target_multi` | `src/engine/infra_target.rs` | `Multi(...)` iterates all children |
| 11 | `test_infra_category_display` | `src/engine/infra_module.rs` | Display of all 5 variants |
| 12 | `test_infra_category_serde` | `src/engine/infra_module.rs` | Round-trip via JSON |
| 13 | `test_infra_orchestrator_emits_scan_events` | `src/runner/infra_orchestrator.rs` | Full ScanEvent sequence, drop-before-join pattern |
| 14 | `test_tcp_probe_open_port` | `src/infra/tcp_probe.rs` | Bind listener, probe, assert Finding |
| 15 | `test_tcp_probe_closed_port` | `src/infra/tcp_probe.rs` | Probe unbound port, assert no Finding |
| 16 | `test_target_from_infra` | `src/engine/target.rs` | `Target::from_infra("10.0.0.0/24")` round-trips |
| 17 | `test_cli_infra_help` | `tests/cli.rs` | `scorchkit --features infra infra --help` exits 0 |
| 18 | `test_engine_infra_scan_doctest` | `src/facade.rs` | `Engine::infra_scan` doctest compiles |
| 19-25+ | Additional parse edge cases, target Display, orchestrator concurrency, etc. | various | |

Target: 25-30 new tests total.

#### Deferred (for later pipelines in the arc)

- **WORK-102:** Migrate `tools/nmap.rs` → `infra/nmap.rs` (InfraModule). Extract `parse_service_fingerprint` pure fn. Publish fingerprints to `shared_data`.
- **WORK-103:** `CveLookup` trait + `OsvClient` impl + `CveMatchModule` reading fingerprints + rate-limited OSV queries.
- **WORK-104:** `NetworkCredentials` struct + encrypted credentials file + SSH + SMB modules. `InfraCategory::NetworkAuth` and `ServiceEnum` variants added here.
- **WORK-105:** `scorchkit assess <targets...>` unified command; `Engine::full_assessment(url, code_path, infra_target)` via `tokio::join!`.
- **WORK-106:** Migration `004_infra.sql` (infra_hosts, infra_services, cve_findings tables); MCP tools `scan_infra`, `list_infra_modules`, `get_services`.

### Start implementation with

```bash
# Baseline check
cargo test 2>&1 | strings | grep "^test result:" | head -1
# expected: 485 passed

# Dep addition
# Edit Cargo.toml: add ipnet optional + infra feature

# Incremental build
cargo check --features infra
```

Implementation order (safe incremental):

1. Add `ipnet` optional dep + `infra` feature in `Cargo.toml`
2. `src/engine/target.rs` — add `Target::from_infra` (no feature gate; just a constructor)
3. `src/engine/infra_target.rs` (new, feature-gated)
4. `src/engine/infra_module.rs` (new, feature-gated)
5. `src/engine/infra_context.rs` (new, feature-gated)
6. `src/engine/mod.rs` — wire the three new modules under `#[cfg(feature = "infra")]`
7. `src/runner/infra_orchestrator.rs` (new, feature-gated)
8. `src/runner/mod.rs` — wire under feature
9. `src/infra/tcp_probe.rs` (new, feature-gated)
10. `src/infra/mod.rs` (new, feature-gated) — `register_modules()` returns `vec![Box::new(TcpProbeModule::default())]`
11. `src/lib.rs` — `#[cfg(feature = "infra")] pub mod infra;`
12. `src/cli/args.rs` — add `Commands::Infra` variant (feature-gated)
13. `src/cli/runner.rs` — dispatch (feature-gated)
14. `src/facade.rs` — `Engine::infra_scan` (feature-gated)
15. `src/prelude.rs` — re-exports (feature-gated)
16. Tests throughout
17. `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, `cargo test --features infra`, `cargo deny check`

Each step should leave default build compiling; feature build compiles at step 6+.
