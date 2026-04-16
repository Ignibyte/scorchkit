# Work Pipeline: Kubescape as CloudModule (K8s cluster posture)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature (third concrete cloud module) |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-15 |
| **Last Updated** | 2026-04-15 |
| **Forge Ticket** | #153 |
| **Forge Ticket ID** | _populated by ticket-create_ |

---

## Phase 1: Plan
**Status:** PASS

### Spec
- **Title:** Kubescape as `CloudModule` — K8s cluster posture
- **Scope:** New `cloud::kubescape::KubescapeCloudModule` (id `"kubescape-cloud"`, `CloudCategory::Kubernetes` × `CloudProvider::Kubernetes`). Drives `kubescape scan --format json` against a live K8s cluster via kubeconfig context. Coexists with `sast_tools::kubescape::KubescapeModule` (id `"kubescape"`, scans on-disk manifests).
- **Files:** `src/cloud/kubescape.rs` (new), `src/cloud/mod.rs`, `docs/modules/cloud-kubescape.md` (new), `docs/architecture/cloud.md`, `CHANGELOG.md`
- **Acceptance:** Tests 641/700+/883+; fmt/clippy clean; arch decision `cloud.module.kubescape` recorded.

## Phase 2: Design
**Status:** PASS (compressed — three-piece anatomy from WORK-151/152)

- `build_kubescape_argv(target, creds) -> Result<Vec<String>>` — pure
  - Validates: `Account/Project/Subscription` → Err with pointers to `prowler-cloud` / `scoutsuite-cloud`
  - `KubeContext(ctx)` → `["scan", "--format", "json", "--kube-context", ctx]` (target overrides config)
  - `All` + `creds.kube_context` set → `["scan", "--format", "json", "--kube-context", <ctx>]`
  - `All` + no `kube_context` → Err with remediation
- `parse_kubescape_json(stdout, target_label) -> Vec<Finding>` — pure, mirrors `sast_tools::kubescape` shape with cloud-tagged finding builder (provider:kubernetes evidence, CWE-1188, OWASP A05, confidence 0.9). Severity: scoreFactor >= 7 → High, >= 4 → Medium, else Low.
- `run(ctx)` — thin glue: build argv → run_tool_lenient (10-min timeout, kubescape is fast) → parse stdout.

## Phase 3-6: Implement / Validate / Verify / Complete (compressed)
**Status:** PASS

- **Files:** Created `src/cloud/kubescape.rs` + `docs/modules/cloud-kubescape.md`. Modified `src/cloud/mod.rs` (register 2→3, flip register test from `_v2` → `_v3`), `docs/architecture/cloud.md`, `CHANGELOG.md`.
- **Tests:** default 641 unchanged; `--features cloud` 691 → 702 (+11); `--all-features` 874 → 885 (+11). All 11 new tests cfg-gated. Full regression plan landed (8 argv + 2 parser + 1 metadata).
- **Quality:** fmt clean; clippy 0 warnings (default + cloud); 1 trivial fix iteration (rustdoc backticks on `ArmoBest`).
- **Knowledge:** architecture decision `cloud.module.kubescape` recorded; generation trace saved; ticket #153 closed Done.
- **Self-reflection:** workarounds none; cleanest version yes (target-overrides-config semantics match kubectl mental model); senior dev approval yes (parity with SAST wrapper severity mapping prevents cross-path divergence).
