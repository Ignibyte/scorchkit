# Application-security evidence contract

ScorchKit represents every application-security finding with two layers. `Finding` remains the
source-compatible facade used by existing scanners and callers. Its canonical `appsec` companion is
the versioned `scorchkit.finding/v2` record used for identity, correlation, persistence, and report
projection. Core owns both layers; adapters, storage, reports, CLI, MCP, and agents only consume or
enrich them.

## Trust boundary

Scanner observations and agent interpretation are different data classes:

- an observation identifies the weakness, affected location, scanner provenance, and correlation
  keys;
- evidence records preserve redacted scanner output or HTTP request/response material and have
  their own deterministic identities;
- agent analyses name their provider/model and reference the finding or evidence they interpret.

An agent analysis never mutates scanner evidence and is never used as a scanner fingerprint. Raw
provider responses remain provider-layer audit material. The finding contract contains only the
explicit, labeled analysis that a trusted consumer elects to attach.

## Typed locations

Locations are tagged as source, runtime, package, artifact, or legacy. Source locations carry a
path and optional region. Runtime locations carry a URI and optional route/parameter identity.
Package and artifact locations carry their ecosystem/name/version/manifest or URI/digest identity.
The legacy variant preserves input that cannot be classified without inventing precision.

Old finding JSON is upgraded when read. The original facade fields remain available and serializable
so saved reports and external callers are not forced into an all-at-once migration.

## Stable identity and correlation

Identity inputs are length-prefixed and SHA-256 hashed. Sorted explicit correlation keys are the
strongest weakness key. Otherwise ScorchKit uses CWE when available, then scanner rule identity,
then the normalized legacy module/title key. The canonical typed location is always part of finding
identity. Evidence, descriptions, confidence, timestamps, and agent output are excluded.

This makes equivalent observations from different scanners converge when they share a standards
identifier or an explicit correlation key at the same location, while different locations remain
separate. Evidence identity includes its schema, kind, provenance, redaction state, and content, so
repeat observations deduplicate but distinct evidence remains available.

## Redaction

Sensitive request/response headers, URL query values, and keyed form/JSON-like body values are
replaced before they enter the durable evidence contract. ScorchKit retains the names of parameters,
the HTTP method, normalized route, response status, truncation state, and an operator-supplied
authentication persona identifier. Persona identity is a label, never a credential.

Redaction is repeated when evidence is attached or legacy JSON is upgraded. Reports and storage
therefore consume already-redacted domain data rather than independently guessing which fields are
safe.

## Storage and reports

`tracked_findings` stores the stable v2 identity, schema, correlation keys, and the latest
compatibility snapshot. `finding_evidence` is an append-preserving child table keyed by tracked
finding and evidence identity. Finding upsert and evidence insertion share one transaction.

JSON serializes the canonical v2 companion alongside legacy fields. SARIF uses stable identity in
`partialFingerprints`, converts typed locations into the closest SARIF location form, and places
redacted evidence, provenance, correlation keys, and labeled analysis in namespaced properties.
Raw evidence is never a fingerprint.

## Producer migration

Semgrep supplies a source region and rule provenance. Nuclei supplies a runtime location and
template provenance. Other adapters receive a conservative typed or legacy location through
`Finding::new` and can migrate independently without changing execution or authorization behavior.
