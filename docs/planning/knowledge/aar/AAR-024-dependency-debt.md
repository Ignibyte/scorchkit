---
aar: AAR-024-dependency-debt
ticket: TICKET-024
pipeline: dependency-debt
status: submitted
opened: 2026-08-22
submitted: 2026-08-22
effectiveness: 4 - effective
---

# AAR-024 — Retire dependency and advisory debt

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-workspace-gate-scope-001` | Three root dependency upgrades affect every feature-state and package build. | Yes — the plan requires workspace/all-target feature census and canonical gate evidence rather than a default build only. |
| `WORK-099-cargo-deny-hygiene` | The old policy created the exact exceptions this ticket removes. | Yes — its Cargo Audit versus Cargo Deny distinction produced separate lockfile, active-graph, and policy assertions. |
| `docs/architecture/storage.md` | SQLx is intentionally PostgreSQL-only and runtime-queried for portable builds. | Yes — production and test manifests will disable defaults and enumerate only required PostgreSQL features. |
| `SECURITY.md` current support boundary | Native cloud SDKs remain private and test-only. | Yes — unrelated SDK informational advisories remain visible and are not conflated with the named supported-path debt. |

## What happened

- Upgraded `scraper` to 0.27, `indicatif` to 0.18, and every direct SQLx declaration to 0.9.
  `fxhash`, `number_prefix`, and vulnerable `rsa` are absent from the lockfile; MySQL and SQLite
  remain inactive optional package metadata rather than compiled drivers.
- Removed the two obsolete Cargo Deny exceptions and the RSA Cargo Audit suppression from the
  canonical gate and CI. An executable repository contract now pins the maintained versions,
  PostgreSQL-only feature graph, retired package absence, and unignored policy.
- Preserved HTML and progress behavior without source changes. SQLx 0.9 required explicit safety
  wrappers around four test-only generated DDL statements; their identifier alphabet and length
  are directly asserted before construction.
- SQLx 0.9 also exposed a feature-unification regression: its disabled `whoami` dependency selected
  a platform stub, changing `postgresql:///database` peer authentication from the operating-system
  user to `anonymous`. ScorchKit now enables only `whoami/std` with its storage feature, centralizes
  connection parsing, preserves authority/query usernames, and sanitizes both URL and SQLx-option
  parse errors.
- The exact-tree DIFF gate passed 19 applicable lanes at 84.59% line coverage and 100% viable MSI:
  seven mutations caught, zero missed, and two unviable. Strict Nextest started 1,937 cases, and
  PostgreSQL plus CLI/MCP contracts passed.

## Novel findings

- Cargo feature unification is observable runtime behavior. A transitive crate can compile after an
  upgrade yet silently select a no-platform stub when its new owner disables defaults; local
  identity, certificate roots, filesystem discovery, and similar platform adapters need semantic
  tests rather than compile-only proof.
- A package present in `Cargo.lock` is not necessarily active. Dependency policy should separately
  test complete-lockfile advisories, active reverse dependency edges, and enabled features instead
  of treating any optional package record as reachable code.
- Wrapping a third-party configuration parser creates multiple rejection boundaries. Generic URL
  syntax and driver-specific option parsing must each prove stable, credential-safe diagnostics.
- Receipt-producing validation is intentionally exact-tree. Writing the green results into tracked
  notes after sealing them invalidates the receipt just as a source edit would; prepare the evidence
  structure first and reserve exact completion results for the required post-archive rerun.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-transitive-platform-stub-001` | SQLx 0.9's disabled `whoami` defaults selected the platform stub and changed username-less peer-auth DSNs to user `anonymous`. | First FAST all-feature database tests. |
| `BF-scorchkit-optional-lock-activation-assumption-001` | The initial design required optional `sqlx-mysql` package metadata to disappear instead of proving the driver inactive and the vulnerable RSA package absent. | Dependency resolution and active-tree inspection. |
| `BF-scorchkit-layered-config-error-redaction-001` | The first credential-redaction regression covered malformed URL syntax but not a valid URL rejected by SQLx-specific option parsing. | Adversarial security inspection. |
| `BF-scorchkit-validation-note-receipt-drift-001` | Recording validation results after the green DIFF run changed the tracked worktree, so `pass validate` correctly rejected the stale receipt. | First validation transition. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-dependency-lock-activation-separation-001` | For dependency retirement, test lockfile advisory presence, active reverse edges, and enabled features as separate properties. | Optional package metadata can remain locked without becoming compiled or reachable, while Cargo Audit still evaluates the complete lockfile. |
| `PR-scorchkit-transitive-platform-feature-contract-001` | When an upgraded dependency obtains local identity or platform configuration through a transitive crate with defaults off, declare the minimum required platform feature and test the resulting semantic value. | Successful compilation does not distinguish a real platform backend from an `anonymous` or `unknown` stub. |
| `PR-scorchkit-config-parser-error-layering-001` | Exercise each wrapped configuration-parser rejection layer with credential-shaped input and assert that public diagnostics neither echo the input nor lose their compatibility contract. | A generic syntax test cannot prove a later driver-specific option error is redacted. |
| `PR-scorchkit-validation-evidence-before-receipt-001` | Populate tracked validation evidence before the receipt-producing gate; after it is green, transition immediately and put final archival outcomes before the mandatory delivery rerun. | Any tracked note edit invalidates an exact-worktree validation receipt and needlessly repeats expensive mutation work. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 4/5. The recalled workspace-gate, Cargo Audit versus Cargo Deny, and PostgreSQL-only storage
rules led directly to exact dependency and feature contracts, preserved public behavior, and removed
three stale exceptions without lowering policy. The full feature matrix caught a subtle platform
identity regression before delivery, and inspection added the missing SQLx-option redaction proof.
Effectiveness is not scored 5 because manifest patch scope, optional-lockfile assumptions, and
receipt-note sequencing caused avoidable rework, although each failure is now captured as an
executable or reusable prevention rule.
