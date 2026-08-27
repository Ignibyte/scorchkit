---
title: TICKET-035-extension-catalog
status: done
ticket_number: 035
type: feature
created: 2026-08-26
closed: 2026-08-26
intake: docs/planning/intake/INTAKE-extension-catalog.md
pipeline_spec: docs/planning/pipeline/completed/extension-catalog.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-035
---

# Add a signed extension catalog and lifecycle

## Summary

Add a local-first signed extension catalog and lifecycle around the existing isolated Wasm runtime.
Configured publisher keys verify an exact catalog payload; every catalog release binds its manifest,
module, compatibility, conformance, provenance, and permissions. A durable local approval registry
pins active and rollback releases, blocks revocations before worker startup, and preserves exact
historical provenance without introducing ambient downloads or automatic updates.

## Why

SK-050 established safe digest-bound execution, but users still cannot discover a publisher release,
review permission changes, approve a version, revoke it, or recover to the last approved version
through one engine-owned contract. SK-057 is the final ordered platform backlog item and closes that
supply-chain lifecycle without changing the runtime's policy ceiling.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When catalog metadata or an extension artifact is accepted, ScorchKit shall verify its Ed25519 signature, exact publisher/key binding, payload and artifact digests, provenance, engine compatibility interval, and passing conformance record before it can enter the approval registry. | Canonical payload/signature, tamper, wrong-publisher/key, digest, compatibility, conformance, and Wasm structural/health tests. |
| REQ-002 | When an install or upgrade adds or widens a capability, strongest effect, target kind, endpoint allowance, credential/filesystem/subprocess request, or resource budget, ScorchKit shall return the exact normalized permission difference and require an explicit matching approval before activation. | Complete permission-lattice/diff truth table and preview/approval mismatch tests. |
| REQ-003 | When an extension release is activated or invoked, ScorchKit shall bind the catalog, publisher, manifest, module, compatibility, conformance, and permission identities to one exact immutable release and shall reject moving or changed inputs. | Activation/restart/reopen-race, invocation provenance, duplicate identity, and changed-file tests. |
| REQ-004 | When a trusted catalog revokes a release or publisher key, ScorchKit shall block new activation and invocation before worker selection, preserve historical findings and lifecycle records, expose a bounded reason, and require a separate reviewed replacement approval. | Revoked active/rollback/key, denial-order, historical projection, and replacement tests. |
| REQ-005 | When activation fails compatibility, conformance, structural startup, health, or durable publication, ScorchKit shall leave the previous approved release active; when rollback is explicitly requested, it shall reactivate only an exact still-approved non-revoked release without changing prior evidence identity. | Failure injection, atomic state, explicit rollback, unavailable/corrupt prior release, and provenance continuity tests. |
| REQ-006 | When a catalog is absent or unavailable, ScorchKit shall continue to invoke exact locally approved releases whose retained inputs still match, shall keep built-in application-security modules available, and shall never fetch from an undeclared source. | Offline restart/invocation, missing catalog, built-in parity, and network/subprocess denial tests. |

## Scope

- In: versioned signed local catalog envelope/payload; configured Ed25519 publisher trust; exact
  manifest/module/provenance/conformance identities; bounded permission diff and explicit approval;
  atomic local activation/rollback state; revocation; offline approved-release loading; lifecycle
  audit/projection; CLI inspection, approval, activation, rollback, and status surfaces.
- Out: public catalog hosting, remote discovery/fetch, silent installation or auto-update,
  publisher key enrollment from a catalog, payment/licensing, arbitrary native packages, new guest
  effects, or non-application-security default categories.

## Locked decisions

- Catalog sources and lifecycle roots are exact configured local paths. No URL field or network
  client exists in v1.
- Catalog signatures use Ed25519 over domain-separated raw payload bytes. Trusted key ID and
  publisher identity come only from local configuration and must match the signed payload.
- The lifecycle registry stores immutable release identities and append-preserved transitions;
  activation is one atomic pointer update after complete verification and explicit approval.
- A normalized permission fingerprint covers adapter target/effect claims, declared capabilities,
  effect-specific allowances, and every resource budget. Any install, addition, or widening requires
  approval for the exact diff and candidate release identity.
- Revocation is checked before registration and every invocation. Historical result provenance and
  lifecycle history remain readable; revocation never rewrites scanner evidence.
- Offline operation uses only exact approved local manifest/module bytes. Catalog absence cannot
  disable built-ins and never authorizes discovery or fetching.

## Recon

- Existing `scorchkit.extension-manifest/v1` loading already performs no-follow bounded reads,
  engine compatibility validation, exact module SHA-256 verification, web/API/JSON restriction,
  and retained-byte worker execution.
- The isolated worker imports no WASI, network, filesystem, credential, process, policy, or storage
  handle. Catalog acceptance therefore must end in the same `LoadedExtension` and policy broker,
  not a parallel execution path.
- Current extension configuration names explicit manifest paths and is disabled by default. The
  CLI catalog display performs the same global ID claim across built-ins and dynamic modules.
- Existing finding provenance records extension ID, version, and module digest. SK-057 must add
  catalog/publisher/release identity without changing the immutable scanner evidence layer.
- Release and supply-chain work already established exact-subject signatures, verified-artifact
  single-read, refresh/execution separation, and rollback-before-effect patterns applicable here.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/extension-catalog.spec.md`
- Operator direction: continue the ordered roadmap and deliver completed work to
  `git@github.com:Ignibyte/scorchkit.git`; do not repeat broad mutation work when exact focused
  evidence is sufficient.
- Focused mutation repair: the repository owner directed mutation cleanup alongside the remaining
  roadmap work and then said to proceed. Preserve the completed 399-mutant DIFF baseline and repair
  all and only its 101 exact survivors in 33 functions across five files; do not repeat the broad
  campaign. Evidence is sealed under `scorchkit-mutants-focused-ticket-035`.

## Log

- 2026-08-26: opened.
- 2026-08-26: promoted from `INTAKE-extension-catalog` as SK-057, the sole remaining ordered
  platform backlog item.
- 2026-08-26: the first DIFF delivery gate passed 21/22 lanes and completed a 399-mutant inventory
  at 72.4% MSI (233 ordinary catches, 32 timeout catches, 101 survivors, 33 unviable). Approved the
  exact 101-survivor focused repair scope; every non-mutation lane was green.
- 2026-08-26: exact repair caught all 101 survivors (94 ordinary and seven timeout catches). The
  sealed bundle reconstructs 366/366 viable mutations caught at 100% MSI, and the pre-completion
  focused-repair gate passed all 22 lanes with zero failures or skips.
- 2026-08-26: submitted AAR-035, indexed six lifecycle/mutation failure-prevention pairs, marked
  SK-057 and the ordered roadmap complete, and removed recurring root profiler artifacts.
