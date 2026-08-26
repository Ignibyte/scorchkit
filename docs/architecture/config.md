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
| `mcp` | optional authenticated remote transport, bounds, and principal bindings |
| `control_api` | opt-in authenticated loopback control listener, binding, and resource bounds |
| `wordlists` | optional discovery and enumeration files |
| `hooks` | typed bounded local run processors and legacy hook compatibility |
| `audit_log` | local JSONL event sink |
| `cve` | disabled, mock, NVD, OSV, or composite lookup |
| `network_credentials` | SSH, SMB, SNMP, and Kerberos inputs |
| `cloud` | AWS, GCP, Azure, and Kubernetes credential hints |
| `webhooks` | durable event destination, filters, credential reference, and queue/worker bounds |

Secret-bearing structs use redacted `Debug` implementations. TOML serialization is not redaction and
must be protected like any other credentials file.

## Typed local run processors

`[[hooks.processors]]` requires a complete versioned contract: unique ID, executable path,
supported phase and matching schemas, declared capabilities, required/optional failure behavior,
order below 50000, and exact nonzero time/input/output budgets. The supported local phases are
`preprocessing`, `enrichment`, and `reporting`; notification uses durable webhooks rather than a
foreground executable.

```toml
[hooks]
timeout_seconds = 30
fail_open = true

[[hooks.processors]]
schema = "scorchkit.run-processor/v1"
id = "select.modules"
path = "/opt/scorchkit/processors/select-modules"
phase = "preprocessing"
input_schema = "scorchkit.run-preprocess-input/v1"
output_schema = "scorchkit.run-preprocess-proposal/v1"
capabilities = ["dast-scan", "external-tool"]
failure_mode = "required"
order = 10

[hooks.processors.budget]
timeout_millis = 1000
max_input_bytes = 65536
max_output_bytes = 65536
```

Explicit processor IDs cannot use the reserved `legacy.` prefix, IDs and `(phase, order)` slots
must be unique, and at most 64 explicit plus legacy processors may be configured. The legacy
`pre_scan`, `post_module`, and `post_scan` arrays remain readable. Their global `timeout_seconds`
must be 1–300 and `fail_open` maps to optional rather than required failure behavior. Legacy output
is adapted to a validated proposal and cannot expand authority or replace scanner findings. See
[Typed run processors and legacy lifecycle hooks](hooks.md).

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

## Authenticated remote MCP

Local `scorchkit serve` does not require this section. Remote operation is selected explicitly with
`scorchkit serve --remote` and fails before binding unless the complete shape is valid:

```toml
[mcp.remote]
bind = "127.0.0.1:7443"
tls_termination = "trusted_reverse_proxy"
allowed_hosts = ["security.owned.example"]
allowed_origins = ["https://console.owned.example"]
max_body_bytes = 262144
max_concurrent_requests = 16
max_sessions_per_principal = 8

[[mcp.remote.bindings]]
subject = "operator@owned.example"
engagement_id = "00000000-0000-0000-0000-000000000001"
token_env = "SCORCHKIT_MCP_OPERATOR_TOKEN"
```

`bind` must be loopback. The same-host proxy owns certificates and the public listener; it must
replace `X-Forwarded-Proto` with the single exact value `https`, preserve the public Host, and pass
the bearer `Authorization` header. A supplied browser Origin must match the HTTPS allowlist; missing
Origin remains valid for non-browser MCP clients. The endpoint path is fixed at `/mcp`.

Each subject and environment reference is unique. Token values must be 32–4096 printable ASCII
bytes, are resolved before listening, zeroized after hashing, and retained only as runtime SHA-256
digests. Every binding UUID must equal the one enabled, unexpired `[engagement]` UUID. Client
initialization name/version is never a credential or binding. Each principal receives a separate
stateful session manager, and body, concurrent-request, and per-principal session limits are hard
bounds. Rotate a token by changing its environment value and restarting the host.

This profile does not terminate TLS directly and does not support a non-loopback cleartext hop,
OIDC/OAuth, multiple selectable engagements, tenants, or RBAC.

## Local control API

The control listener is absent by default and starts only with `scorchkit control-api` in a build
that includes `control-api`:

```toml
[control_api]
bind = "127.0.0.1:7444"
subject = "local-operator"
engagement_id = "00000000-0000-0000-0000-000000000001"
token_env = "SCORCHKIT_CONTROL_TOKEN"
max_body_bytes = 262144
max_response_bytes = 4194304
max_concurrent_requests = 16
max_journal_events = 4096
max_event_bytes = 262144
max_subscribers = 32
default_page_size = 50
```

`bind` must be loopback, and the UUID must equal the enabled, unexpired `[engagement]`. The bearer
value is 32–4096 printable non-whitespace ASCII bytes resolved from `token_env`, hashed, and
zeroized before binding. The adapter accepts only loopback Host values and exposes fixed v1
description, control, and event routes. Non-loopback values fail startup. Use the separately
enabled team profile for multi-user routing; the local control bearer never becomes a team
credential.

## Authenticated team profile

The `team` Cargo feature adds an optional `[team]` profile and the explicit `scorchkit team-api`
command. The backend must remain loopback-only behind a trusted same-host TLS proxy. Credentials,
database URLs, and 32-byte AES keys are environment-indirect; each environment name begins with
`SCORCHKIT_TEAM_`, is unique, and never appears as a CLI secret flag.

```toml
[team]
bind = "127.0.0.1:7445"
tls_termination = "trusted_reverse_proxy"
allowed_hosts = ["security.example.test"]
allowed_origins = ["https://security.example.test"]
max_body_bytes = 262144
max_response_bytes = 4194304
max_concurrent_requests = 64

[[team.cells]]
cell_id = "acme-payments"
organization_id = "acme"
project_id = "00000000-0000-0000-0000-000000000101"
database_url_env = "SCORCHKIT_TEAM_ACME_DATABASE_URL"
object_root = "/var/lib/scorchkit/acme-payments/objects"
write_key_id = "2026-08"

[team.cells.engagement]
id = "00000000-0000-0000-0000-000000000201"
name = "Acme payments assessment"
enabled = true

[team.cells.engagement.policy]
allowed_scope = [
  { kind = "exact", value = "payments.example.test" },
  { kind = "path_prefix", value = "/var/lib/scorchkit/acme-payments/objects" },
]
capabilities = ["dast-scan", "local-state"]
effects = ["passive", "active-safe"]

[[team.cells.keys]]
key_id = "2026-08"
key_env = "SCORCHKIT_TEAM_ACME_KEY_2026_08"

[team.cells.quotas]
max_active_jobs = 16
max_requests_per_minute = 600
max_journal_events = 4096
max_event_bytes = 262144
max_subscribers = 32
default_page_size = 50
max_object_bytes = 16777216
max_objects = 100000
max_storage_bytes = 107374182400

[team.cells.retention]
object_days = 90

[[team.bindings]]
subject = "operator@example.test"
cell_id = "acme-payments"
role = "operator"
token_env = "SCORCHKIT_TEAM_ACME_OPERATOR_TOKEN"
```

The database must already contain exactly `project_id`; startup permanently binds the migrated
database to the cell identity. The object directory must already exist as the exact canonical path
granted by the cell engagement and, on Unix, must grant no group or other permissions (`0700` is
recommended). Roots may not overlap. A subject that uses another cell receives a different binding
and bearer. See [Authenticated team service](team-service.md).

## Durable webhooks

Webhook delivery is available only on PostgreSQL-backed job hosts. The engagement that runs the job
must separately authorize the destination hostname and every resolved address with
`webhook-delivery` and `active-safe`; scan-target grants do not imply notification authority.

```toml
[[webhooks]]
id = "security-events"
url = "https://events.owned.example/scorchkit"
events = ["finding_produced", "scan_completed"]
authorization_env = "SCORCHKIT_WEBHOOK_AUTHORIZATION"
max_pending = 1000
max_payload_bytes = 262144
max_attempts = 5
timeout_seconds = 10
backoff_seconds = 5
max_backoff_seconds = 300
max_redirects = 0
batch_size = 25
```

`authorization_env` names an environment variable containing the complete `Authorization` header.
The value is resolved only after a worker claims an authorized attempt and is absent from config
debug output, queue records, audits, reports, and CLI/MCP projections. Embedded URL credentials,
fragments, duplicate IDs, invalid event names, and zero or excessive bounds fail configuration.
URL-only legacy entries derive a stable non-secret destination ID, but they still require durable
storage and explicit policy grants before delivery.
Authenticated destinations must set `max_redirects = 0`, preventing an authorization value from
crossing an origin boundary. Unauthenticated destinations may follow at most ten separately
authorized redirects.

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

## Model analysis

Exact model-role configuration is separate from the legacy `[ai]` adapter and is disabled by
default:

```toml
[model_analysis]
enabled = false
```

Bindings name one provider and exact model for one of the six closed roles. Host and local
adapters name a contract-compatible binary; service adapters use a credential-free HTTP(S)
endpoint, environment-variable credential reference, no redirects, mandatory redaction and no
retention, and bounded input/output/time policy. A binding remains `evaluation_required` until its
exact provider/model/role/contract/corpus result passes all five built-in cases. See
[model analysis](model-analysis.md) for the full schema and safety boundary.

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
