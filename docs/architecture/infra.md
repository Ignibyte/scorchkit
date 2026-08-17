# Infrastructure scanning

The infrastructure family scans IP addresses, CIDRs, hostnames, and endpoints below the web
application layer. It is enabled by the `infra` Cargo feature and uses its own target, context, module
trait, and orchestrator.

```bash
cargo build --release --features infra
scorchkit infra 192.0.2.10 --profile quick
```

The target must be covered by an engagement with `infra-scan/active-safe` and, because the current
registry includes nmap, `external-tool/active-safe`.

## Registry

| Module | Role |
|---|---|
| `tcp_probe` | bounded TCP-connect reachability |
| `nmap` | external service fingerprinting and shared CPE publication |
| `tls_infra` | implicit TLS, STARTTLS, RDP negotiation, protocol and optional cipher enumeration |
| `dns_infra` | wildcard DNS, DNSSEC, CAA, NS, and AXFR checks |
| `cve_match` | optional injected consumer of service fingerprints |

The registry contains four modules. `Engine::infra_scan` appends `cve_match` when a configured lookup
factory returns a backend, producing a maximum of five.

## Context and construction

```rust
pub struct InfraContext {
    pub target: InfraTarget,
    pub config: Arc<AppConfig>,
    pub shared_data: Arc<SharedData>,
    pub events: EventBus,
    pub credentials: Option<Arc<NetworkCredentials>>,
    // private bounded executor and authorization proof
}
```

Production code obtains a context through `Engine::infra_context`. `InfraContext::new` is
crate-private. Credential resolution occurs only after the engine authorizes the target, capability,
and effect. Tool execution then checks the context's grant again.

`InfraTarget` accepts bare IPv4/IPv6, CIDR, hostname, or `host:port`. Reports represent the target
through a synthetic `infra://` URL so existing finding and report types remain shared.

## Orchestration

`InfraOrchestrator` registers modules, applies ID/category/profile filters, publishes lifecycle
events, and returns the common `ScanResult`. It submits modules through the shared job executor with
bounded concurrency, a batch wall-time budget, caller cancellation, and stable outcomes. All
non-`CveMatch` producers finish before the `CveMatch` consumer batch, even if a consumer was
registered first. See [executor.md](executor.md).

## Shared fingerprint flow

```text
nmap XML
  → parse_nmap_xml_fingerprints
  → Vec<ServiceFingerprint>
  → shared_data[SHARED_KEY_FINGERPRINTS]
  → CveMatchModule
  → CveLookup
  → findings
```

DAST and infrastructure nmap adapters share the XML parser but map results differently. The
infrastructure adapter is the canonical publisher for CVE correlation.

## Native probes

- TCP probing uses a bounded port list and per-connect timeout.
- TLS covers common implicit-TLS ports, SMTP/IMAP/POP3 STARTTLS, and RDP TLS negotiation. Certificate
  checks share the DAST certificate model.
- DNS uses the system resolver for wildcard, DNSSEC, CAA, and NS queries and a bounded raw-TCP AXFR
  probe against authoritative servers.

All native paths use the context-owned `PolicyNetwork`. A derived hostname is authorized before DNS,
and every returned address is authorized before a query or connection. TCP and TLS connect to the
authorized concrete `SocketAddr`, so a second uncontrolled resolution cannot change the destination.
DNS checks also reauthorize random wildcard names and discovered name servers. Mixed answer sets fail
closed before any address is used.

## CVE services

NVD and OSV do not inherit authorization from the scanned host. Their provider URL, resolved
addresses, and existing cache path require separate passive infrastructure grants. See
[CVE backends](cve-backends.md).

## Library use

```rust
let context = engine.infra_context("192.0.2.10")?;
let mut orchestrator = scorchkit::runner::infra_orchestrator::InfraOrchestrator::new(context);
orchestrator.register_default_modules();
orchestrator.apply_profile("quick");
let result = orchestrator.run(false).await?;
```

The `engine` in this example must be constructed with a matching engagement. Direct context
construction is intentionally unavailable.
