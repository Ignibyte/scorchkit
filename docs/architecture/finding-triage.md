# Finding triage lifecycle

ScorchKit records validation and disposition decisions beside scanner output instead of rewriting
that output. The canonical `scorchkit.finding-triage/v1` projection is provider-neutral, bounded,
and reconstructed from append-only PostgreSQL children whenever a durable finding crosses the
control, CLI, MCP, or project-report boundary.

## State and authority

The closed state vocabulary is `needs_context`, `likely`, `validated`, `false_positive`,
`accepted_risk`, `fixed`, and `regressed`. Every change records the prior and next state, a trusted
time, a redacted reason, the attributed human or deterministic system actor, exact evidence
identities, and an optional same-finding model-analysis identity. Actor attribution does not grant
authority. User commands require an enabled, unexpired engagement bound to the caller plus the
exact canonical finding target with `local_state` and `active_safe` grants before any transaction
begins.

The original finding and evidence remain unchanged. Model analysis can be cited as provenance, but
cannot act as the transition actor. A direct legacy status input maps through one closed adapter:

| Legacy input | Canonical state | Compatibility projection |
|---|---|---|
| `new` | `needs_context` | `new` |
| `acknowledged` | `validated` | `acknowledged` |
| `false_positive` | `false_positive` | `false_positive` |
| `wont_fix`, `accepted_risk` | `accepted_risk` | `accepted_risk` |
| `remediated`, `verified` | `fixed` | `verified` |

Every distinct correction is allowed so legacy headless clients do not lose their direct status
semantics. `regressed` is valid only after `fixed`; normal rediscovery appends it deterministically.

## Durable records

Migration 013 adds an indexed `triage_state` projection and seeds one system-owned initial
transition for every existing finding. The ordered history is authoritative. Reads rebuild it and
require its final state to match both `triage_state` and the legacy `status` projection.

```text
tracked_findings
  ├── finding_triage_transitions       ordered authoritative state history
  ├── finding_correlation_decisions    evidence-owned explanations
  └── finding_suppressions             project-scoped exact selectors
```

Each child stores a canonical raw document plus duplicated identity, schema, actor, scope, state,
and time columns. Public reads validate all duplicates, canonical serialization, parent/project
ownership, ordering, collection ceilings, and referenced evidence. Any missing, malformed, or
divergent child fails the complete finding projection.

Finding writes remain serialized by the existing identity lock. Rediscovery of a fixed stable
identity appends `regressed`. If proof changes materially behind another disposition, the ingest
transaction appends `needs_context`. Evidence collection timestamps alone do not count as material
proof changes.

## Correlation and suppression

A correlation decision retains every contributing stable finding identity, scanner identity,
evidence identity, normalized facet, actor, explanation, and creation time. Contributors must be
unique, include the parent, belong to one project, and own every cited evidence record. A single
finding and single scanner are insufficient to claim cross-source correlation.

Suppressions are visibility metadata, never deletion or filtering at the canonical read boundary.
The four exact shapes are finding, rule, target, and rule-target inside one project. Rule and target
values are safe digests derived from the canonical finding. Every suppression has a reason and at
least one future expiry or review boundary. It is active only before every supplied boundary and
only for an exact matching subject; inactive history remains visible. Reads validate the complete
bounded project suppression ledger before selecting matches from canonical scopes, so a corrupted
duplicated selector cannot hide a malformed child.

## Public projection

`FindingViewV1.triage` returns the current state, complete ordered transitions, correlation
decisions, all matching suppression history, exact derived subject identities, and the currently
active suppression identities. CLI and MCP legacy status commands route through
`ControlCommandV1::TransitionFinding`; their finding reads use the same control projection.
`ProjectReportViewV1` adds per-state counts and the count of findings with an active suppression.

Scan-time terminal, JSON, HTML, PDF, and SARIF reports continue to represent immutable scan results
and labeled analysis. They do not invent durable triage before persistence. Durable triage reporting
is the canonical project report returned by the control service.

## Source layout

```text
crates/scorchkit-core/src/triage.rs       domain records, identities, matching, mappings
migrations/013_finding_triage.sql         legacy seed and append-only tables
src/storage/triage.rs                     transactional writes and canonical reconstruction
src/storage/findings.rs                   ingest reconciliation and legacy adapter
crates/scorchkit-control                  commands and public DTOs
src/control/service.rs                    policy and application-service composition
src/cli/finding.rs, src/mcp/tools.rs       compatibility adapters
tests/finding_triage.rs                    durable cross-surface contract
```
