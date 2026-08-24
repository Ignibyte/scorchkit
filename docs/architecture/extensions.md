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

## Effects and output

V1 can broker credential-free, no-redirect HTTP `GET` or `HEAD` through an effect-specific
policy-owned client and can return host-attached, digest-bound bytes by opaque input ID. Filesystem,
credential, and subprocess requests have typed protocol forms but are denied as unsupported. The
parent awaits audit-event publication to every registered durable sink before an allowed effect
begins, and allowed plus denied requests both consume the effect budget.

Guest findings are proposals. Root composition validates target scope, severity, confidence,
nested sizes, artifact hashes and references, then recursively redacts evidence and builds
provenance from the registered extension ID, version, module digest, parser outcome, and engine
invocation ID. Normal engine findings then use the existing report, control/MCP, event, and storage
paths. The guest cannot claim first-party trust or mutate durable state.

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

Catalog signing, distribution, upgrades, rollback, and revocation remain future SK-057 work.
