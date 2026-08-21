# Configuration

`AppConfig` is the serialized input to the policy-gated engine. Every section has operational
defaults, but the absence of `[engagement]` is intentional: configuration can load and read-only
commands can run, while every scan family fails closed.

## Discovery order

`AppConfig::load` uses one file:

1. an explicit `--config <path>`, which must exist and be a regular file;
2. `scorchkit.toml` in the current directory;
3. legacy `config.toml` in the current directory;
4. in-memory defaults when none exists.

An explicit missing path is an error. ScorchKit does not silently replace a mistyped configuration
with defaults.

## Safe generation

```bash
scorchkit init https://owned.example
```

This sends no HTTP request. It parses the target, performs a five-second DNS lookup, pins every
current address, and writes a quick-profile `scorchkit.toml`. The generated engagement grants only
`dast-scan`, `external-tool`, `passive`, and `active-safe`. The quick profile itself does not execute
external tools.

Running `scorchkit init` without a target writes the legacy default `config.toml`. It has no
engagement and therefore authorizes no scan.

## Top-level sections

| Section | Purpose |
|---|---|
| `engagement` | authoritative target, capability, effect, deny, expiry, and enabled state |
| `scan` | timeout, concurrency, user agent, redirect limit, rate limit, profile, proxy, headers, and legacy display scope |
| `auth` | web bearer, cookie, basic, or custom-header credentials |
| `dast` | bounded ZAP phase, persona, schema, process, and artifact settings |
| `tools` | external executable overrides |
| `sast` | reproducible static-analysis settings, including pinned local Semgrep rules |
| `supply_chain` | offline SBOM/SCA cache root, artifact limits, and provider snapshot ages |
| `ai` | optional provider adapter |
| `report` | artifact directory and evidence/remediation inclusion |
| `database` | connection URL, pool size, and migration behavior |
| `wordlists` | optional discovery and enumeration files |
| `hooks` | bounded local lifecycle processes |
| `audit_log` | local JSONL event sink |
| `cve` | disabled, mock, NVD, OSV, or composite lookup |
| `network_credentials` | SSH, SMB, SNMP, and Kerberos inputs |
| `cloud` | AWS, GCP, Azure, and Kubernetes credential hints |
| `webhooks` | compatibility-only shape; outbound delivery is disabled |

Secret-bearing structs use redacted `Debug` implementations. TOML serialization is not redaction and
must be protected like any other credentials file.

## Generated quick engagement

The generated shape is equivalent to:

```toml
[engagement]
name = "quick scan: owned.example"
enabled = true

[engagement.policy]
capabilities = ["dast-scan", "external-tool"]
effects = ["passive", "active-safe"]

[[engagement.policy.allowed_scope]]
kind = "exact"
value = "owned.example"

# One exact entry is also written for each DNS answer observed at init time.
[[engagement.policy.allowed_scope]]
kind = "exact"
value = "192.0.2.10"

[scan]
profile = "quick"
```

The real file also contains a generated UUID and every default section. A later DNS change is denied
until the operator regenerates or deliberately changes the engagement.

## AI

```toml
[ai]
enabled = true
provider = "codex"
# binary = "codex"
# model = "your-approved-model"
auto_analyze = false
```

`provider = "claude"` selects the compatibility adapter. `max_budget_usd` applies only to that
adapter. Legacy `claude_binary` remains readable but should not appear in new files.

## Static analysis

The embedded Semgrep pack needs no configuration. A reviewed local replacement must use an absolute
path and exact lowercase SHA-256 digest:

```toml
[sast.semgrep]
local_rule_file = "/absolute/path/to/application-rules.yml"
local_rule_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

The two fields are an atomic pair. ScorchKit validates the path, size, YAML structure, prohibited
network validators, and digest before starting Semgrep. There is no configuration form for
`--config auto`, registry names, or URLs.

## Application supply chain

Application supply-chain scans require an existing private cache root. The root is separately
authorized as local state, must not be a symlink, and on Unix must grant no group or other
permissions. ScorchKit does not create it implicitly because creation would combine authorization
and filesystem effects.

```toml
[supply_chain]
cache_root = ".scorchkit/cache/supply-chain"
artifact_limit_bytes = 67108864
provider_download_limit_bytes = 1073741824
osv_maximum_age_seconds = 86400
grype_maximum_age_seconds = 432000
trivy_maximum_age_seconds = 86400

[tools]
syft = "syft"
osv_scanner = "osv-scanner"
grype = "grype"
trivy = "trivy"
```

Scans are offline. Provider refresh is a separate policy-owned operation and scanners cannot change
their databases during a scan. The configured provider ages are absolute policy caps. A refresh
request may choose a shorter lifetime but cannot make a snapshot valid beyond these values. See
[Application supply-chain evidence](application-supply-chain.md) for the cache layout, refresh
contract, explicit target kinds, and pinned tool versions.

## Application DAST

The DAST service uses explicit persona IDs. Configuration stores environment-variable names only;
credentials remain outside TOML and are resolved after the complete request grant matrix passes.

```toml
[dast]
persona_limit_count = 16
schema_limit_bytes = 8388608
schema_limit_count = 16
output_limit_bytes = 8388608
artifact_limit_bytes = 536870912
artifact_limit_files = 20000
timeout_seconds = 1800
spider_minutes = 5
client_spider_minutes = 10
active_scan_minutes = 20
client_spider_depth = 10
client_spider_children = 100
browser_id = "chrome-headless"

[dast.personas.user]
kind = "browser"
login_url = "https://app.example.test/login"
username_env = "SCORCHKIT_USER_NAME"
password_env = "SCORCHKIT_USER_PASSWORD"

[dast.personas.user.verification]
url = "https://app.example.test/account"
expected_status = 200
logged_in_regex = "Account"
logged_out_regex = "Sign in"
max_logged_out = 0

[tools]
zap = "/mnt/fast/scorchkit/tools/zap/2.17.0/zap.sh"
chromedriver = "/mnt/fast/scorchkit/tools/chromedriver/151.0.7922.137/chromedriver"
```

Header personas use `kind = "header"`, `header_name`, `value_env`, and the same verification
block. Firefox browser personas instead configure `tools.geckodriver`. The selected driver must
match the installed browser major and is never downloaded during a scan. The public request
contains persona IDs, never these environment values. See
[Authenticated application DAST](application-dast.md).

## Trusted Nuclei

Nuclei requires one explicit signed local collection. It never selects or updates ambient
community templates.

~~~toml
[tools]
nuclei = "/mnt/fast/scorchkit/tools/nuclei/v3.11.1/nuclei"

[nuclei]
collection_manifest = "/opt/scorchkit/nuclei/approved/collection.json"
manifest_limit_bytes = 1048576
certificate_limit_bytes = 65536
template_limit_bytes = 1048576
template_limit_count = 256
output_limit_bytes = 8388608
artifact_limit_bytes = 67108864
artifact_limit_files = 1024
timeout_seconds = 600
rate_limit_per_second = 20
concurrency = 4
request_timeout_seconds = 10
~~~

The manifest, certificate, and templates need an engagement-authorized path prefix with
local-state/passive. The target needs exact DAST and external-tool grants at the collection's
strongest effect. See [Trusted Nuclei application probes](trusted-nuclei.md).

## CVE providers

NVD and OSV are separate effect targets. Before either backend is constructed, the engagement must
allow its canonical provider URL and resolved addresses under `infra-scan/passive`, and allow the
existing cache directory through a `path_prefix` scope rule. The cache directory must already exist
so authorization cannot be used to create an arbitrary path.

## Adding a field

1. Add it to the narrow owning struct.
2. Define an explicit safe default.
3. Add serialization and compatibility tests.
4. Add redacted `Debug` behavior when it can carry a secret or credential-bearing URL.
5. If it enables an effect, add capability classification, authorization, audit, negative tests, and
   documentation before wiring the effect.
