# Source-to-runtime correlation

ScorchKit correlates canonical finding-v2 observations into versioned application attack paths. The
correlator is deterministic and provider-neutral. It does not run a scanner, send a request, change
a finding, or treat agent analysis as scanner proof.

## Boundary

```text
immutable finding-v2 records
  source location + code flow + scanner rule
  runtime location + redacted HTTP evidence + runtime probe
  package/artifact identity + explicit correlation keys
                         |
                         v
              normalized correlation facets
                         |
                         v
       attack path + state + gaps + evidence references
                         |
             +-----------+-----------+
             |                       |
             v                       v
   inert focused selection      append-only verification
   rules/probes/requests/tests   attempts and transitions
             |                       |
             +-----------+-----------+
                         v
                  storage / MCP / reports
```

The core owns facets, path identity, proof requirements, state transitions, coverage, and selector
minimization. PostgreSQL, MCP, CLI, reports, and agent hosts are adapters around those contracts.

## Correlation facets

Facets are normalized typed values. They include application, deployment or revision, HTTP route,
method, parameter, component, weakness, and explicit scanner-supplied identities. The correlator
derives them only from canonical finding locations, scanner provenance, redacted HTTP evidence,
and explicit finding-v2 correlation keys. Titles, descriptions, remediation text, and agent
analysis are never correlation inputs.

A shared weakness by itself creates only a suspected candidate. Reachability requires a precise
shared application facet such as a route, operation, parameter, component, or application identity.
Reproduced requires all of the following:

- a static finding with an ordered source-to-sink flow;
- a runtime finding with redacted HTTP request/response proof;
- a shared weakness identity;
- a shared precise application facet;
- compatible deployment or source-revision provenance.

Runtime proof is bound to the provenance on its own evidence record. Append-preserved HTTP evidence
from an older revision cannot reproduce a current path merely because the durable finding identity
is unchanged; it remains a typed unbound-proof gap until comparable evidence exists.

Missing or conflicting inputs become typed gaps. They do not disappear, lower scanner confidence,
or turn an incomplete verification into a clean result.

## Identity and ordering

The path schema and identity schema are versioned separately. Identity inputs are length-prefixed
before SHA-256 hashing. Member finding identities, evidence identities, shared facets, selectors,
gaps, and transitions have deterministic sorting and deduplication rules. Unordered JSON maps and
delimiter-joined strings are not identity inputs.

The correlator is project-scoped and resource-bounded. It rejects an oversized finding set,
per-finding detail inventory, source/runtime pair cross-product, or path fan-out instead of
allocating or correlating without a ceiling. Duplicate path identities do not consume the path
ceiling, and method-only coincidence cannot create a candidate. It never links findings from
different projects because the project adapter supplies exactly one project inventory.

## State machine

| Current state | Evidence or attempt | Next state | Reason |
|---|---|---|---|
| none | deterministic candidate | suspected, reachable, or reproduced | Initial state is the strongest state directly supported by typed evidence. |
| suspected | later comparable runtime proof | reachable or reproduced | New evidence can strengthen a candidate. |
| reachable | comparable HTTP reproduction | reproduced | Runtime proof now reaches the same deployed source hypothesis. |
| reproduced | complete comparable negative verification | mitigated | The same focused conditions no longer reproduce. |
| reproduced | incomplete, failed, or non-comparable negative | reproduced | Absence without coverage is not mitigation. |
| mitigated | later comparable reproduction | regressed | Prior proof and mitigation remain in history. |
| any | duplicate or older attempt | unchanged or rejected | Transitions are ordered and idempotent. |

Each transition records its own identity, prior and next state, path confidence, attempt identity,
coverage, evidence identities, and observation time. Finding confidence remains unchanged.

## Focused verification selection

Every path can derive an inert `scorchkit.focused-verification/v1` selection:

- exact static scanner rule IDs, rule digests, and configuration identities;
- exact runtime probe or template IDs, digests, and collection identities;
- redacted request method, normalized route, parameter identity, and authentication persona label;
- explicit test IDs supplied as correlation metadata.

Selection identity excludes credential values, request bodies, response bodies, secret headers, and
free-form agent text. Correlation never authorizes or executes the selection. A later workflow must
bind it to an engagement and the normal ScorchKit policy/execution boundary.

## Persistence and public projections

PostgreSQL stores one canonical current path per project/path identity and append-preserves each
transition in a child table inside the same identity-locked transaction. MCP and reports expose the
same path schema, state, shared facets, member and evidence references, gaps, transition history,
and focused selection.

The existing title/module attack-chain engines remain compatibility-only. Their output is labeled
legacy and unverified and cannot promote canonical path state.
