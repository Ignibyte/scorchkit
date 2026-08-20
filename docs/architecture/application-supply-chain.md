# Application supply-chain evidence

ScorchKit's application supply-chain pipeline is an ordered, offline composition service. It keeps
declared source dependencies separate from built-artifact inventory, produces or imports one exact
CycloneDX 1.6 document, and passes those same verified bytes to every artifact vulnerability
consumer. It is available through the agent-neutral library facade, CLI, and MCP; Codex is the
preferred host but no engine type depends on an agent vendor.

## Execution model

```text
explicit local target
        |
canonicalize and authorize
        |
        +-- source directory --> OSV Scanner over discovered lockfiles
        |
        +-- Syft or supplied CycloneDX 1.6 SBOM
                     |
              validate + SHA-256
                     |
                owned exact bytes
                  /         \
              Grype        Trivy
                  \         /
           conservative correlation
```

The profile controls the ordered work:

| Profile | Source coverage | SBOM | Artifact consumers |
|---|---|---|---|
| `quick` | OSV Scanner | no | none |
| `standard` | OSV Scanner for source targets | Syft or supplied SBOM | Grype |
| `thorough` | OSV Scanner for source targets | Syft or supplied SBOM | Grype and Trivy |
| `pentest` | Same supply-chain contract as `thorough` | Syft or supplied SBOM | Grype and Trivy |

OSV Scanner only receives bounded, deterministically discovered lockfiles. Syft receives an explicit
`dir:`, `file:`, `oci-archive:`, or `oci-dir:` source. Grype and Trivy receive an owned SBOM path;
they never recatalog the target. Every invocation uses an owned home, cache, configuration,
temporary directory, output path, clean environment, exact accepted exit codes, bounded output,
and an exact pinned tool version. Syft and Trivy return their JSON through the bounded process
channel. ScorchKit writes those accepted bytes to the durable evidence files, so neither tool can
grow a report file outside the configured limit.

## Target boundary

Callers must select one exact local shape:

- `source_directory`
- `directory_artifact`
- `file_artifact`
- `oci_archive`
- `oci_layout`
- `cyclonedx_sbom`

The shape is validated before a run workspace or subprocess is created. ScorchKit does not accept an
image name, registry reference, Docker/containerd/Podman socket, remote URL, or ambient cloud or
registry credential. It does not build the target or run a target package manager. Remote artifact
acquisition requires a future target and authentication design.

## Coverage and evidence

The public assessment has three states:

- `complete`: every phase required by the selected profile completed with valid evidence;
- `incomplete`: an applicable prerequisite such as a tool or provider snapshot was unavailable;
- `degraded`: an attempted producer, consumer, or parser failed.

Each non-complete phase records a typed gap. A missing, stale, or invalid database is never projected
as a clean scan. JSON and stored execution evidence retain the full assessment. SARIF, HTML, PDF,
and terminal reports preserve the same state and gap vocabulary.

The SBOM record includes the exact document SHA-256, producer and version, target identity, and
CycloneDX version. Tool observations preserve supplied PURLs, installed and fixed versions,
advisory IDs and aliases, data sources, tool versions, provider snapshots, and bounded raw reports.
ScorchKit normalizes a supplied valid PURL but never invents one. Cross-tool correlation requires
the same target revision, the same normalized PURL, and at least one common advisory alias; every
original observation remains available after correlation.

## Cache lifecycle

Scans never refresh provider data. The cache root must already exist, be a real directory rather
than a symlink, and grant no group or other permissions on Unix. It is separately authorized as
local state. The default is `.scorchkit/cache/supply-chain`; create it with mode `0700` before use.

```toml
[supply_chain]
cache_root = "/var/lib/scorchkit/supply-chain"
artifact_limit_bytes = 67108864
provider_download_limit_bytes = 1073741824
osv_maximum_age_seconds = 86400
grype_maximum_age_seconds = 432000
trivy_maximum_age_seconds = 86400

[tools]
syft = "/usr/local/bin/syft"
osv_scanner = "/usr/local/bin/osv-scanner"
grype = "/usr/local/bin/grype"
trivy = "/usr/local/bin/trivy"
```

`supply_chain_cache_status` reports `ready`, `missing`, `stale`, or `invalid` independently for OSV,
Grype, and Trivy. Snapshots are immutable directories selected by an atomically replaced current
pointer. Every provider, staging, snapshot, and run-workspace ancestor must be a real directory
under the private cache root. Every artifact digest and the exact inventory are revalidated before
use.

Refresh is a separate policy-owned provider effect. A request supplies every URL, relative path,
digest, snapshot ID, schema version, upstream build time, and maximum age. ScorchKit streams each
object into same-filesystem staging under a hard byte limit, verifies its SHA-256 and structure,
then atomically promotes the completed manifest. Failure leaves the previous current snapshot in
place. A refresh accepts at most 256 unique artifact paths, and the configured download limit caps
the complete refresh as well as each response. The request's maximum age can only shorten the
configured provider lifetime. It cannot extend it. When an upstream build time is supplied,
freshness is measured from that time rather than the download time.

For OSV, each download path is exactly
`cache/osv-scanner/<ecosystem>/all.zip`; every bounded JSON advisory in the archive is validated.
For Grype, the request contains one official Zstandard database archive. ScorchKit imports it with
the pinned Grype binary. Before import, it reads the compressed tar without extracting it, rejects
links and escaping paths, and enforces the expansion and entry limits. After import, it requires a
valid Grype status whose database path remains inside the owned cache, then inventories the result.
Trivy refresh currently fails closed. Its database must be pre-provisioned through a separately
reviewed local-state workflow.

Example OSV refresh request:

```json
{
  "provider": "osv",
  "snapshot_id": "osv-2026-08-20",
  "schema_version": "osv-scanner-offline-v1",
  "downloads": [
    {
      "url": "https://osv-vulnerabilities.storage.googleapis.com/Rust/all.zip",
      "relative_path": "cache/osv-scanner/Rust/all.zip",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "upstream_built_at": "2026-08-20T00:00:00Z",
  "maximum_age_seconds": 86400
}
```

The engagement must authorize the existing cache path for local state and each exact provider URL,
DNS result, and redirect for provider refresh. A request file or MCP argument is context, not
authorization. Supply-chain scans publish the normal scan lifecycle events. Provider refresh also
publishes redacted authorization, subprocess, and cache-promotion events to the configured audit
log.

## Pinned operator toolchain

The delivered contracts target Syft 1.50.0, OSV Scanner 2.3.8, Grype 0.116.1, and native Trivy
0.74.0. `doctor` treats another version as incompatible. The build host uses
`/mnt/fast/scorchkit/supply-chain-cache` with owner-only permissions and stores Cargo work under
`/mnt/fast/scorchkit/cargo-target`. The native Trivy binary replaces the former Docker-socket
wrapper. Trivy 0.74.0 does not support `--skip-check-update`; the adapter instead disables database,
Java database, version, and telemetry updates with the flags that release provides.

Installed Linux amd64 artifacts were verified against their release checksums:

| Artifact | SHA-256 |
|---|---|
| Syft 1.50.0 archive | `bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788` |
| OSV Scanner 2.3.8 binary | `bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc` |
| Grype 0.116.1 archive | `0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458` |
| Trivy 0.74.0 `Linux-64bit` archive | `2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a` |

## Public operations

The CLI exposes `supply-chain scan`, `supply-chain cache-status`, and `supply-chain cache-refresh`.
MCP exposes the matching `supply_chain_scan`, `supply_chain_cache_status`, and
`supply_chain_cache_refresh` tools. Ordinary `code` and MCP `scan_code` execution merge the selected
supply-chain profile into the canonical scan result. Cache status is local state; scans and refresh
remain subject to their concrete engine capabilities and engagement rules.
