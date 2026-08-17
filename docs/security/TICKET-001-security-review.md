# TICKET-001 security review

**Review date:** 2026-08-15  
**Codex Security scan:** `efe30eaf-9b1b-4572-949a-0e8391d48247`  
**Sealed snapshot:** `codex-security-snapshot/v1:sha256:aacce46c8735819a2356f1e2333d90036ce3871a399bce71d35505e02a32a375`

This is the durable remediation summary for the sealed scan. It does not replace or alter the
scanner's canonical report. Runtime reproduction used loopback services, disposable local process
trees, repository fixtures, and a migrated local PostgreSQL database. No third-party target was
scanned.

## Coverage

The scan reviewed 603 changed paths and completed 192/192 semantic review rows without exclusions or
deferrals. It reported eight high-confidence findings: five medium and three low. The fixes below
were reviewed again against the changed source surface.

## Finding dispositions

| # | Finding | Disposition and evidence |
|---:|---|---|
| 1 | `Engine::new` disabled the facade authorization boundary. | Fixed. `Engine::new` loads only a configured engagement and absence denies. Effectful context constructors are crate-private. Facade and family tests prove denial before client, credential, filesystem scan, or process creation. |
| 2 | MCP `scan` executed arbitrary targets without authorization. | Fixed. MCP scan, plan, project, schedule, due-scan, code, infrastructure, and cloud paths use the policy-gated engine. The MCP suite tests no-engagement denial and authorized loopback execution. |
| 3 | Redirects and resolved addresses bypassed engagement scope. | Fixed. `engine::policy_http` checks the direct URL, every redirect, the hostname, and every DNS answer. Native DNS, TLS, TCP, infrastructure, and WebSocket paths use `PolicyNetwork`, authorize derived hostnames before resolution and every answer before use, then connect to the authorized concrete address. Loopback tests cover allowed traffic and denials for redirects, IPv4/IPv6 answers, derived names, mixed answer sets, private and metadata addresses, changed DNS, and WebSocket handshakes. |
| 4 | MCP project scans ignored registered target scope. | Fixed. Project scans require exact canonical membership in the selected project and then apply the engagement and profile. Cross-project target mutation is also constrained and tested. |
| 5 | Due schedules ran targets without engagement authorization. | Fixed. Migration 005 stores the exact engagement snapshot. Execution requires a registered target, valid snapshot, identical current engagement, and current profile authorization. Legacy rows fail closed. |
| 6 | Advisory-lock waiters could exhaust the scheduler pool. | Fixed. A short `FOR UPDATE SKIP LOCKED` transaction claims and advances rows before scan work. One-slot and N-caller tests prove bounded progress, at-most-once occurrences, and no N-squared persistence. |
| 7 | External-tool findings could inject terminal controls. | Fixed. One sink encoder neutralizes C0/C1, ESC, BEL, and bidi controls while structured evidence remains unchanged. Fixtures cover terminal, CLI, agent, AI, project, schedule, finding, and diff presentation. |
| 8 | Timed-out scanners left descendant processes running. | Fixed on supported hosts. The shared executor and Interactsh own Unix process groups and terminate/reap the tree on success, timeout, output overflow, error, stop, and drop. Non-Unix builds fail until Job Object parity exists. |

## Additional corrections

- Forty-five bounded DAST adapters and all 21 SAST adapters now use one typed executor with canonical
  executable resolution, explicit exit policy, nonzero timeout, 8 MiB per-stream limits, owned
  standard input, and process-tree cleanup. Interactsh has a separate session-lifecycle contract.
- Unused outbound webhook delivery was removed because it was a raw network bypass. Its redacted
  configuration shape remains readable for compatibility.
- `scorchkit init <target>` sends no HTTP request. It resolves and pins addresses and writes a quick
  engagement limited to passive and active-safe effects.
- Database, scan proxy/header, authentication, NVD, and webhook debug rendering redacts direct secret
  channels and credential-bearing URLs.
- NVD and OSV constructors require an engagement, authorize their endpoint and existing cache path,
  use the policy-bound HTTP client, and recheck resources for every query.
- WebSocket discovery no longer hands a hostname to `connect_async` after policy HTTP discovery. It
  obtains an authorized concrete stream through `PolicyNetwork` and performs the TLS/WebSocket
  handshake on that stream.
- The 12 AWS, GCP, and Azure SDK modules are private, test-only, and absent from the production
  registry because SDK authentication and service transports do not yet enforce ScorchKit's
  per-address policy. Production cloud scans expose five bounded external-tool adapters.

## Validation evidence

The repaired security and presentation seams have current local evidence:

```text
cargo clippy --all-targets --all-features -- -D warnings
PASS, zero diagnostics

DATABASE_URL=postgresql://chadpeppers@localhost/scorchkit_codex_validation_001 \
cargo test --all-features
PASS: 1,203 library tests, 153 integration tests, and 14 doctests;
4 reasoned live-network ignores; 0 failures

focused cargo-mutants inventory: 42 repaired functions across 14 files
PASS: 162/162 viable mutations caught, 0 missed, 9 unviable; 100% MSI
```

The earlier canonical DIFF gate caught 639/639 viable changed-line mutations at 100% MSI and closed
the 85-file mutation-blind ledger. The later full-repository run was stopped by the repository owner
and remains labeled incomplete with no score. Under the 2026-08-16 scope amendment, a new full run is
scheduled evidence rather than TICKET-001 acceptance. The current non-mutation delivery lanes also
passed: gates 1–14, 78.68% line coverage, Nextest strictness, PostgreSQL integration, and CLI/MCP
contracts. Final feature readiness still requires the pipeline archive and exact-worktree receipt.
The active pipeline notes record the evidence chronologically.
