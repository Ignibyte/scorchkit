# Isolated WebAssembly extensions

ScorchKit supports explicitly registered third-party application-security modules through
`scorchkit.extension-manifest/v1`. This is separate from trusted Rust modules and legacy TOML
command wrappers: third-party code runs only as digest-bound `wasm32-unknown-unknown` in a distinct
owned worker process.

## Trust boundary

An isolated extension imports nothing. It receives no WASI filesystem, socket, environment,
clock, random, process, credential, policy, engagement, or storage handle. Its only interface is
the versioned `scorchkit.extension-protocol/v1` turn ABI:

```text
engine invocation -> guest turn -> effect request or typed output
                                     |
                              parent policy broker
                                     |
                         typed allow/deny result -> guest
```

The worker uses Wasmi structural limits, one linear memory, one bounded table, checked pointers,
fuel, bounded stack, and a required ABI export set. The parent adds wall time, framed byte limits,
effect and artifact counts, and Unix process-group or Windows Job Object ownership. Cancellation,
timeout, malformed output, worker failure, or owner drop terminates the complete worker tree.

## Registration and authority

Registration is disabled by default and names exact manifests; ScorchKit never scans a directory:

```toml
[extensions]
manifests = ["/approved/extensions/header-check/manifest.json"]
```

The active engagement must authorize both the canonical manifest and adjacent `.wasm` path for
`local-state/passive` and `extension-execute/passive`. Execution separately requires the target's
exact `dast-scan`, `external-tool`, and `extension-execute` grant at the manifest's strongest
effect. Manifest capabilities are ceilings on requests, not grants.

Loading uses no-follow regular-file handles, bounded reads, an engine compatibility interval, and
the exact lowercase SHA-256 of the retained module bytes. Duplicate IDs fail the whole configured
registry. The v1 host accepts only web/API target kinds and JSON output. The worker receives those
retained bytes and never reopens a host path.

## Signed local catalogs

`scorchkit.extension-catalog-envelope/v1` adds publisher authentication and lifecycle context
around the same manifest/worker route. It is local-only: configuration names exact catalog files,
locally trusted Ed25519 keys, and one private lifecycle root. Neither the envelope nor payload has
a transport or fetch field.

```toml
[extensions]
manifests = []
catalogs = ["/approved/scorchkit/publisher/catalog.json"]
lifecycle_root = "/var/lib/scorchkit/extensions"

[[extensions.trust_keys]]
key_id = "publisher.release-key-2026"
publisher_id = "publisher.example"
public_key_base64 = "<base64 of exactly 32 Ed25519 public-key bytes>"
```

The envelope contains `schema_version`, `key_id`, `payload_sha256`, `payload_base64`, and
`signature_base64`. ScorchKit verifies Ed25519 over the exact decoded payload bytes prefixed by
`scorchkit.extension-catalog-signature/v1\0`; it never reserializes JSON for verification. The
configured key ID must bind the signed publisher ID. Payload validation also requires a nonzero
monotonic sequence and a current half-open validity interval.

Every signed release binds all of these identities:

- catalog, publisher, signing key, payload digest, sequence, and release ID;
- one adjacent regular manifest filename and the exact manifest and module SHA-256 values;
- extension ID, semantic version, and the manifest's engine compatibility interval;
- normalized target kinds, strongest effect, declared capabilities, exact HTTP-origin allowances,
  and every invocation budget;
- source/revision/build provenance and a passing conformance suite/report identity.

Catalog-relative manifest names cannot be nested. Manifest-relative modules retain the existing
single adjacent `.wasm` rule. Catalog, manifest, and module reads are bounded, reject symlinks, are
authorized as local state plus extension execution, and retain the bytes that were verified.
Invalid present catalogs fail closed. A missing configured catalog is offline, not an update or
revocation signal.

## Approval, activation, and rollback

The CLI exposes only explicit local lifecycle operations:

```bash
scorchkit --config operator.toml catalog inspect \
  /approved/scorchkit/publisher/catalog.json publisher.release-42
scorchkit --config operator.toml catalog approve \
  /approved/scorchkit/publisher/catalog.json publisher.release-42 \
  --payload-sha256 <inspect-payload-sha256> \
  --permission-diff-sha256 <inspect-permission-diff-sha256>
scorchkit --config operator.toml catalog activate <approval-sha256>
scorchkit --config operator.toml catalog rollback publisher.extension <prior-approval-sha256>
scorchkit --config operator.toml catalog status
```

`inspect` verifies the complete signed subject and prints an exact normalized difference from the
active release. Additions to target kinds, capabilities, HTTP origins, or budgets and increases in
the strongest effect or any budget are marked as widening. `approve` repeats verification,
requires both hashes printed by `inspect`, and creates a content-addressed immutable approval that
binds the candidate and difference digest. Catalog sequences lower than a previously accepted
sequence cannot enter approval state, and one accepted sequence cannot later name different signed
payload bytes.

The lifecycle root is created with private owner-only directory permissions where the platform
supports them. Approval files use exclusive creation and private file permissions. A private
cross-process lock serializes approval, activation, and rollback. State records the highest
accepted sequence and its exact payload per catalog, exact active approval pointers, and bounded
append-preserved transitions whose links must reconstruct those pointers. Activation and rollback
accept only approvals already committed in that history, reopen and compare every approved
artifact, perform Wasm import/export/instantiation/ABI health validation, then publish the state
through a same-directory write-sync-rename and parent sync. Failure leaves the previous pointer
unchanged. Rollback never infers a version: it requires the extension ID and exact prior approval
digest.

An active release can restart and execute while its catalog file is absent, provided its approval,
manifest, and module still match. If an applicable configured catalog is present, ScorchKit
requires a valid non-regressed signed sequence and checks release and signing-key revocations at
registration and again immediately before worker startup. A rotated locally trusted publisher key
can therefore revoke the key bound to an older approval. Revocation blocks execution but does not
delete approvals, transitions, or prior findings.

## Effects and output

V1 can broker credential-free, no-redirect HTTP `GET` or `HEAD` through an effect-specific
policy-owned client and can return host-attached, digest-bound bytes by opaque input ID. Filesystem,
credential, and subprocess requests have typed protocol forms but are denied as unsupported. The
parent awaits audit-event publication to every registered durable sink before an allowed effect
begins, and allowed plus denied requests both consume the effect budget.

Guest findings are proposals. Root composition validates target scope, severity, confidence,
nested sizes, artifact hashes and references, then recursively redacts evidence and builds
provenance from the registered extension ID, version, module digest, parser outcome, and engine
invocation ID. Catalog-managed findings additionally record the exact approval, catalog,
publisher, key, payload, release, permission, build, and conformance identities. Normal engine
findings then use the existing report, control/MCP, event, and storage paths. The guest cannot
claim first-party trust or mutate durable state.

For catalog-managed HTTP effects, the signed origin list is an additional ceiling: a request must
match one exact canonical `scheme://host[:port]` origin before normal engagement, scope, DNS,
redirect, and effect authorization. A catalog declaration never grants an effect.

## SDK

The portable SDK is the `guest-sdk` feature of `scorchkit-extension`; it deliberately omits the
host manifest's core and policy dependencies. Implement `GuestExtension`, then export the safe ABI:

```rust,ignore
use scorchkit_extension::{export_extension, GuestExtension};

#[derive(Default)]
struct MyExtension;

impl GuestExtension for MyExtension {
    fn turn(&mut self, input: scorchkit_extension::ExtensionTurnInputV1)
        -> scorchkit_extension::ExtensionTurnOutputV1
    {
        // Return one effect request, completion, or safe failure.
        todo!()
    }
}

export_extension!(MyExtension);
```

The complete example is `examples/custom_wasm_extension`. Verify the actual guest target with:

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/custom_wasm_extension/Cargo.toml \
  --target wasm32-unknown-unknown
```

Remote catalog distribution, discovery, automatic update, catalog-enrolled trust roots, native
packages, licensing, and new guest effects are unsupported in v1.
