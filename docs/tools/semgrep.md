# Semgrep

Semgrep is ScorchKit's fast, multi-language source analyzer. ScorchKit runs the local CLI with a
repository-owned rule pack. It does not use `--config auto`, a registry name, a URL, or an
unpinned configuration.

## Install

```bash
pipx install semgrep
semgrep --version
```

Run `scorchkit doctor` after installation.

## Rule provenance

The default pack is embedded in the ScorchKit binary from
`rules/semgrep/scorchkit-appsec.yml`. Every finding records
`scorchkit-semgrep-appsec/v1@sha256:<digest>` as its configuration identity.

An operator can replace the embedded pack with one local file:

```toml
[sast.semgrep]
local_rule_file = "/absolute/path/to/application-rules.yml"
local_rule_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Both values are required together. ScorchKit rejects relative paths, non-files, files larger than
2 MiB, uppercase or malformed digests, digest mismatches, invalid YAML, empty `rules` sequences,
and rule packs containing Semgrep network `validators`. Rejection happens before Semgrep starts.

## Execution and findings

The wrapper runs the equivalent of:

```text
semgrep scan --config <owned-local-file> --json --dataflow-traces --quiet \
  --metrics=off --disable-version-check <source-root>
```

The owned rule file is removed after the scan. The process has a five-minute timeout and the shared
8 MiB stdout/stderr limits.

Each valid result retains the rule ID, source region, scanner version, target revision when
available, pack identity, redacted structured result, and any Semgrep taint source, intermediate,
and sink locations. Scanner errors, partial records, invalid JSON, and malformed data-flow traces
fail the module instead of producing a clean result.

Semgrep severity maps as follows:

| Semgrep | ScorchKit |
|---|---|
| `ERROR` | High |
| `WARNING` | Medium |
| `INFO` | Low |
| other | Info |

## Selection

```bash
scorchkit code /path/to/source --profile standard --modules semgrep
```

Semgrep is a fast analyzer. It is eligible for `standard`, `thorough`, and `pentest` code
profiles. The embedded pack is deliberately small and high-signal. Use a reviewed digest-pinned
local pack when an application needs framework-specific or organization-specific rules.

Semgrep Community Edition does not replace the deeper CodeQL or Psalm adapters. Those run
separately in deep profiles and preserve their own provenance and flows.
