# 01 — Your first authorized scan

**Goal:** build ScorchKit, create a target-bound engagement, scan a loopback web server, and inspect
the report.

**Time:** about 30 minutes for a first build.

**You will need:** Linux or macOS, a current stable Rust toolchain, Python 3 for the disposable local
server, and two terminals.

Only scan systems you own or have written permission to test. This tutorial stays on loopback.

## 1. Build

```bash
git clone https://github.com/chadpeppers/scorchkit.git
cd scorchkit
cargo build --release
```

The binary is `target/release/scorchkit`. Check the compiled command surface and installed optional
tools:

```bash
target/release/scorchkit --help
target/release/scorchkit doctor
target/release/scorchkit modules --check-tools
```

Missing external tools are reported as unavailable. The quick profile does not require them.

## 2. Start a disposable target

In the first terminal:

```bash
mkdir -p /tmp/scorchkit-first-scan
cd /tmp/scorchkit-first-scan
python3 -m http.server 8080 --bind 127.0.0.1
```

This server exposes only the temporary directory on loopback.

## 3. Create the engagement

In the repository terminal, preserve the binary path and switch to the temporary directory:

```bash
SCORCHKIT_BIN="$PWD/target/release/scorchkit"
cd /tmp/scorchkit-first-scan
"$SCORCHKIT_BIN" init http://127.0.0.1:8080
```

`init` parses the URL, resolves and pins the target address, and writes `scorchkit.toml`. It does not
send an HTTP request. Review the generated `[engagement]` block before continuing. It grants only
passive and active-safe effects for the exact loopback target.

## 4. Run the quick profile

```bash
"$SCORCHKIT_BIN" run http://127.0.0.1:8080 --profile quick
```

The terminal report identifies the module, severity, affected target, evidence, remediation, and
confidence for each finding. The default output also saves a JSON report under the configured
`report.output_dir`.

To request another format:

```bash
"$SCORCHKIT_BIN" --output html run http://127.0.0.1:8080 --profile quick
"$SCORCHKIT_BIN" --output sarif run http://127.0.0.1:8080 --profile quick
```

## 5. Narrow the run

```bash
"$SCORCHKIT_BIN" run http://127.0.0.1:8080 --profile quick --modules headers,tech
"$SCORCHKIT_BIN" run http://127.0.0.1:8080 --profile quick --min-confidence 0.8
```

Do not switch to `standard`, `thorough`, or `pentest` merely because the commands exist. Those
profiles require broader effect grants and should fail closed against the generated quick
engagement.

## 6. Stop the target

Press `Ctrl-C` in the server terminal. The generated engagement remains useful only while the same
loopback target and pinned addresses remain valid.

## Next

- [Unified assessment](03-unified-assess.md)
- [Agent workflow](04-agent-workflow.md)
- [CI/CD integration](08-ci-cd-integration.md)

## Troubleshooting

| Symptom | Check |
|---|---|
| `no engagement authorization is configured` | Run targeted `init` in the directory where the scan command will run, or pass `--config`. |
| DNS or target policy denial | Compare the exact target and resolved addresses with the generated scope rules. |
| Connection refused | Confirm the loopback server is still running on port 8080. |
| Tool skipped | The quick profile remains usable; inspect optional tools with `doctor --deep`. |
