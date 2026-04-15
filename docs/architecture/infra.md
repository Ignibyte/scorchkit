# Infra Architecture

ScorchKit's Infra family is the third module family, parallel to DAST (`ScanModule`, URL-targeted) and SAST (`CodeModule`, path-targeted). Infra modules run against hosts, IP addresses, and CIDR ranges — the layer below the application, where port scanning, service fingerprinting, CVE correlation, non-HTTP TLS, and DNS hygiene live.

All Infra code is feature-gated behind `infra = ["dep:ipnet", "dep:hickory-resolver"]` and absent from the default build. Enable with `cargo build --features infra`.

## Architecture Decision

**Decision:** Parallel `InfraModule` trait, NOT a third variant of `ScanModule::category`.

**Rationale:** The same reasoning that produced `CodeModule` (see [sast.md](sast.md)) applies again. `ScanContext` carries a URL-based `Target` and an HTTP client tuned for web-app probes. Infra modules need an `InfraTarget` sum type (IP / CIDR / host / endpoint / composite), want to reach non-HTTP services, and benefit from protocol-specific filtering. Retrofitting all three input shapes onto one trait would leak concerns in every direction. The three-family pattern is now the stable architecture for any future target shape.

The v2.0 arc (WORK-101 through WORK-110) shipped the foundation and filled every declared `InfraCategory` variant with at least one production module.

## System Overview

```
CLI: scorchkit infra <target>                 scorchkit assess --infra <target>
         │                                             │
         └───────────────┬─────────────────────────────┘
                         │
                  InfraOrchestrator
                         │
                  InfraModule trait
                  InfraContext (InfraTarget)
                         │
           ┌────────┬────┼──────┬──────────┐
           │        │    │      │          │
       tcp_probe  nmap tls_probe dns_probe cve_match
       (PortScan) (FP  (TlsInfra) (Dns)    (CveMatch, injected)
                  →shared_data)
                         │
                    Vec<Finding>
                         │
             ┌───────────┼───────────┐
             │           │           │
          Reports     Storage    AI Analysis
```

## Key Types

### `InfraModule` trait (`engine/infra_module.rs`)

```rust
#[async_trait]
pub trait InfraModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> InfraCategory;
    fn description(&self) -> &str;
    async fn run(&self, ctx: &InfraContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
    fn protocols(&self) -> &[&str] { &[] }          // "ssh", "smb", "snmp", ...
}
```

Shape mirrors `ScanModule` and `CodeModule` exactly. The `protocols()` method is infra-specific — future work in WORK-104 (NetworkAuth) will use it for targeted credential injection.

### `InfraCategory` enum

Five variants in v2.1:

| Variant | Producing modules | Purpose |
|---------|-------------------|---------|
| `PortScan` | `tcp_probe`, `nmap` (when invoked as portscan), `tools::masscan`, `tools::naabu` (DAST-side) | Port enumeration |
| `Fingerprint` | `infra::nmap` | Service version detection — produces `ServiceFingerprint { port, protocol, product, version, cpe }` and publishes `Vec<ServiceFingerprint>` to `shared_data` |
| `CveMatch` | `cve_match::CveMatchModule` (injected by facade) | Reads fingerprints, queries a `CveLookup` backend, emits CVE findings |
| `TlsInfra` | `tls_probe::TlsInfraModule` | SMTPS (465), LDAPS (636), IMAPS (993), POP3S (995) implicit TLS + SMTP (25/587), IMAP (143), POP3 (110) STARTTLS upgrade. Reuses `engine::tls_probe` cert checks so DAST `ssl` and Infra TLS produce identical finding shapes |
| `Dns` | `dns_probe::DnsInfraModule` | Wildcard A/AAAA detection (random 16-hex-char label), DNSSEC `DNSKEY` presence, CAA presence, NS enumeration. AXFR lives with the DAST `dnsrecon` / `dnsx` wrappers |

WORK-104 will add `NetworkAuth` and `ServiceEnum` variants.

### `InfraTarget` (`engine/infra_target.rs`)

```rust
pub enum InfraTarget {
    Ip(IpAddr),                               // "192.0.2.1", "::1"
    Cidr(IpNet),                              // "10.0.0.0/24", "2001:db8::/32"
    Host(String),                             // "example.com"
    Endpoint { host: String, port: u16 },     // "example.com:22", "[2001:db8::1]:443"
    Multi(Vec<Self>),                         // composite (built explicitly, never parsed directly)
}
```

`InfraTarget::parse(&str)` tries CIDR → bare IP → host:port → host in order; first match wins. `iter_ips()` flattens into individual addresses (CIDR via `IpNet::hosts`; `Host` currently returns empty pending DNS resolution in WORK-102).

`Target::from_infra(raw)` wraps the infra target string in a synthetic `infra://` URL so the existing reporting / storage / AI layers consume infra `ScanResult`s unchanged — the same trick `Target::from_path` uses for SAST.

### `InfraContext` (`engine/infra_context.rs`)

```rust
pub struct InfraContext {
    pub target: InfraTarget,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,   // for HTTP-based infra checks + CVE lookups
    pub shared_data: Arc<SharedData>,   // same store as ScanContext / CodeContext
    pub events: EventBus,               // same lifecycle event bus
}
```

Constructor: `InfraContext::new(target, config, http_client)` — fresh `SharedData` and default-capacity `EventBus`. Network credentials field (`NetworkCredentials`) lands in WORK-104.

### `InfraOrchestrator` (`runner/infra_orchestrator.rs`)

Mirrors `Orchestrator` (DAST) and `CodeOrchestrator` (SAST) exactly:

- `new(ctx: InfraContext)` + `register_default_modules()` + `add_module(Box<dyn InfraModule>)`
- Filtering: `filter_by_category`, `filter_by_ids`, `exclude_by_ids`
- `run(show_progress: bool) -> Result<ScanResult>` — semaphore-bounded concurrency (`scan.max_concurrent_modules`)
- Same `ScanEvent` lifecycle sequence (`ScanStarted`, per-module `ModuleStarted` / `ModuleCompleted` / `ModuleError` / `ModuleSkipped`, `FindingProduced`, `ScanCompleted`)
- Calls `subscribe_audit_log_if_enabled(&config.audit_log, &ctx.events)` at the top of `run()` so audit-log subscribers capture infra events too
- Optional `HookRunner` support via `set_hook_runner` — pre/post-scan and per-module scripts work identically to DAST

Returns the existing `ScanResult` type with `Target::from_infra(raw)` as the target.

## Shared-Data Flow

The v2.0 arc threaded fingerprints through `shared_data` to unlock CVE correlation without hard-wiring modules together:

```
infra::nmap (Fingerprint)
    │
    │  parse_nmap_xml_fingerprints(xml) → Vec<ServiceFingerprint>
    │  publish_fingerprints(&ctx.shared_data, &fps)
    │  (key: SHARED_KEY_FINGERPRINTS)
    │
    ▼
infra::cve_match::CveMatchModule (CveMatch)
    │
    │  read_fingerprints(&ctx.shared_data)
    │  → iterate fps with CPE
    │  → CveLookup::query(cpe) for each
    │  → emit Finding per matched CVE
    ▼
ScanResult
```

The same `ServiceFingerprint` type is emitted by the DAST `tools::NmapModule` (via the shared `parse_nmap_xml_fingerprints` helper) — the DAST wrapper layers severity classification and outdated-version checks on top, while the infra wrapper keeps findings at Info and focuses on the publish step.

## Module Registry

```rust
// src/infra/mod.rs
pub fn register_modules() -> Vec<Box<dyn InfraModule>> {
    vec![
        Box::new(tcp_probe::TcpProbeModule::default()),
        Box::new(nmap::NmapModule),
        Box::new(tls_probe::TlsInfraModule::default()),
        Box::new(dns_probe::DnsInfraModule),
    ]
}
```

`CveMatchModule` is intentionally **not** in this list — it requires a construction-time `CveLookup` injection. `Engine::infra_scan` consults `infra::cve_lookup::build_cve_lookup(&AppConfig)` and appends the module via `orchestrator.add_module(...)` when a backend is configured. See [cve-backends.md](cve-backends.md).

## Module Details

### `tcp_probe::TcpProbeModule`

Privilege-free TCP-connect reachability check against a configurable port list (default: 22, 80, 443, 3306, 5432, 6379, 8080, 8443) with bounded timeout. Emits one Info Finding per open port. Was the v1 demonstration module; now serves as the fast no-external-tool baseline.

### `infra::nmap::NmapModule`

Shells out to `nmap -sV` for service-version detection. Uses the shared `parse_nmap_xml_fingerprints` helper (same parser the DAST wrapper uses), publishes `Vec<ServiceFingerprint>` to `shared_data` under `SHARED_KEY_FINGERPRINTS`, and emits one Info Finding per detected service. The DAST and Infra nmap wrappers share the XML parser but produce different finding shapes — infra is the publication path, DAST is the analysis path.

### `tls_probe::TlsInfraModule`

Probes non-HTTP TLS services. Implicit TLS ports: SMTPS 465, LDAPS 636, IMAPS 993, POP3S 995. STARTTLS upgrade ports: SMTP 25 / 587, IMAP 143, POP3 110. RDP-TLS on port 3389 (WORK-148) via the MS-RDPBCGR X.224 Connection Request / Connection Confirm negotiation requesting `PROTOCOL_SSL`. Each port is connected, upgraded (when applicable), handshaken through rustls, and the peer cert runs through the same four checks the DAST `ssl` module does: expired, self-signed, weak signature, subject/SAN mismatch. The shared logic lives in `engine::tls_probe` (`CertInfo`, `TlsMode` — `Implicit` / `Starttls` / `RdpTls`, `StarttlsProtocol`, `probe_tls`, `check_certificate`, `parse_certificate`) — both DAST and Infra call into it so finding shapes are identical.

Handshake failures surface as Info findings (port closed / service doesn't speak TLS; NLA-only RDP host returned `RDP_NEG_FAILURE`), not defects.

**Hardening enumeration (WORK-143):** When `TlsInfraConfig::enum_protocols` is `true` (default), the module additionally calls `engine::tls_enum::enumerate_tls_versions` per port and aggregates results into per-severity findings (SSLv3 / TLSv1.0 → Critical; TLSv1.1 → High; TLSv1.2 / TLSv1.3 → Info summary). When `cipher_enum_limit = Some(N)` is set (opt-in, default `None`), the module also calls `engine::tls_enum::enumerate_weak_ciphers` with the budget and emits per-severity-tier findings for accepted weak suites. Full per-entry lists appear in each finding's `evidence` field to keep the report readable.

### `dns_probe::DnsInfraModule`

Native DNS probes via `hickory-resolver` (with `dnssec-aws-lc-rs` for chain validation) and `hickory-proto` (transitive, used for the native AXFR probe over raw TCP):

- **Wildcard A/AAAA detection** — queries a random 16-hex-char subdomain (64 bits of UUID-derived entropy so no collision with real subdomains). Medium severity if wildcard resolves.
- **DNSSEC — two-pass (WORK-145).** Pass 1: DNSKEY presence at the apex (Medium if missing). Pass 2: validating resolver with `ResolverOpts::validate = true` triggers hickory's parent-DS → DNSKEY → RRSIG chain walk; errors classify via `classify_dnssec_error` into Critical (bogus / bad RRSIG), High (expired signature), Medium (missing DS at parent), or Medium (indeterminate). Success → Info "Chain Validated".
- **CAA** — checks for CAA records. Low severity when absent.
- **NS enumeration** — lists authoritative name servers. Info finding.
- **AXFR zone transfer (WORK-145).** Native raw-TCP probe — hand-crafted `hickory-proto` `Message` with `QTYPE=AXFR`, 2-byte TCP length prefix, first-response classification (`NoError` + `AA` + `ANCOUNT>0` + SOA-in-answers = accepted). Fans out across every NS in the zone, emits one Critical finding per accepting server. Rejections (every healthy server) are silent at `debug!` level. 2s per-NS timeout.

AXFR is now handled natively — the external `tools::dnsrecon` / `tools::dnsx` wrappers remain as alternatives for operators who need full-zone enumeration rather than just acceptance probing.

### `cve_match::CveMatchModule` (injected)

Consumer side of the fingerprint pipeline. Reads fingerprints via `read_fingerprints`, iterates those with a `cpe` set, queries the injected `CveLookup` backend sequentially, and emits one `Finding` per matched CVE with the CVE ID and CVSS score in the title. Per-fingerprint query errors are logged at `warn` and skipped so a single backend hiccup doesn't abort the scan.

Constructed via `CveMatchModule::new(lookup: Box<dyn CveLookup>)`. See [cve-backends.md](cve-backends.md) for the backend ecosystem.

## CLI + Facade

```
scorchkit infra <target> [--profile quick|standard] [--modules a,b,c] [--skip x,y]
scorchkit assess --infra <target> [--url <url>] [--code <path>]
```

Library:

```rust
engine.infra_scan(target: &str).await
engine.full_assessment(url, code_path, infra_target).await    // see assess.md
```

Both facade methods are gated on `#[cfg(feature = "infra")]`.

## Future Work

- **`NetworkAuth` and `ServiceEnum` category variants** — follow-up for native credentialed probe modules (SSH login, SMB mount, SNMP walk). `NetworkCredentials` field on `InfraContext` shipped in WORK-146 — see [auth-config.md](auth-config.md).
- **WORK-106** — Storage migration + MCP tools for infra scans
- DNS resolution for `InfraTarget::Host` in `iter_ips()`
