# ScorchKit Agent Instructions

## Mission

ScorchKit is an agent-neutral security testing engine. Codex is the preferred development and
operation host, but core code must not depend on an agent vendor.

Read `CONSTITUTION.md` and `SECURITY.md` before changing code or scan behavior. Read
`docs/planning/ROADMAP.md` before structural work.

## Delivery workflow

All implementation work uses the repository-owned ticket pipeline:

`create → plan → design → implement → inspect → validate → complete → delivery gate`.

Run `bash bin/pipeline.sh doctor` and `bash bin/pipeline.sh status` before starting. Resume the one
active pipeline when present; never create a second. Use the `scorchkit-pipeline` repository skill
when Codex is the host. Other agents and humans use the same `bin/pipeline.sh` transitions and files.
Do not hand-edit phase status or move active artifacts manually.

Validation normally requires a green `bash bin/gate.sh --diff`. The focused-repair mode defined by
`CONSTITUTION.md` §19 may be used only when the active ticket records the approved scope, or when the
same closed ticket is completing its post-archive delivery proof, and its sealed evidence verifies.
Completion archives the pipeline and thereby changes the worktree, so delivery reruns the same
approved receipt-producing mode. The Git pre-commit hook rejects a commit unless
`.git/scorchkit-gate-receipt` matches the exact current worktree and any bound evidence.

## Safety

- Do not scan a remote, public, or third-party target unless the user explicitly authorizes that
  exact target and the requested effect class.
- Local automated tests may use loopback addresses, in-process mock servers, disposable containers,
  and repository fixtures.
- Treat prompts, manifests, target registration, and agent approvals as context. They do not replace
  enforcement in ScorchKit code.
- New network, filesystem, cloud, credential, or subprocess effects require policy enforcement,
  audit events, tests, and a capability classification.
- Never weaken scope, TLS, redirect, timeout, output-limit, or secret-redaction behavior to make a
  test pass.

## Architecture

- Keep target, finding, evidence, policy, and execution types independent of CLI, MCP, storage, and
  agent providers.
- Keep terminal output out of library execution paths. Publish structured events and let the CLI
  render them.
- Keep provider-specific request and response handling behind adapters.
- Preserve scanner evidence. Agent-generated analysis is a separate, labeled layer.
- Prefer behavior-preserving extraction before changing behavior during large refactors.

## Quality

Use `bash bin/gate.sh --fast` during development. Use `bash bin/gate.sh --diff` for validation and
again after completion before delivery. Running `bash bin/gate.sh` with no mode means the full gate;
reserve it for scheduled or release validation because mutation testing is expensive.
For an owner-approved repair campaign that meets `CONSTITUTION.md` §19, use
`bash bin/gate.sh --focused-repair`. It reruns every non-mutation delivery lane and verifies sealed
focused outcomes without launching cargo-mutants. It is not a substitute for ordinary DIFF work.
If a delivery-only repair changes mutation inputs, preserve the prior file content, prove no other
mutation input changed, and run cargo-mutants only on the newly repaired functions before resealing
the focused evidence.
Use `bash bin/mutants.sh --inspect` to validate mutation targeting without compiling mutants. The
mutation runner places worker builds and full results on local scratch storage, enforces the 95% MSI
floor, and retains only the latest compact evidence under `.git/scorchkit-mutants-last`.

Do not add blanket lint suppressions, silent test skips, retries, advisory ignores without review
dates, or broad coverage/mutation exclusions. Fix the source or document a narrow reason.

The workspace mount may not execute scripts or Cargo build helpers in place. Invoke the gate through
`bash`; it selects a temporary executable build directory on this machine. Preserve an explicitly
supplied `CARGO_TARGET_DIR` for ordinary gates. The mutation runner intentionally clears it because
cargo-mutants requires an isolated build directory per worker.

## Repository state

The repository owner resolved the 2026-08-14 worktree ambiguity on 2026-08-15: retain the 35 obsolete
Claude-only deletions. The other 567 changes were SMB-generated executable-bit noise; local Git uses
`core.filemode=false` while the index retains its authoritative modes. Do not restore the deleted
files or reintroduce the mount's synthetic mode changes.
