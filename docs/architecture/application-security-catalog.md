# Application-security adapter catalog

ScorchKit keeps every registered scanner available, but implicit profiles and agent-facing catalogs
now select only application-security modules. Network enumeration, enterprise credential testing,
general exploitation frameworks, and cloud-account posture checks require an explicit compatibility
selection. This is a selection boundary, not an authorization grant. The engagement policy still
checks the target, capability, and effect before any network, filesystem, credential, or process
effect.

## Catalogs

| Catalog | Domains | Current modules | Selection |
|---|---|---:|---|
| Application web | source, artifact, runtime, attack path | 67 | Default CLI, MCP, AI, agent, and named DAST profiles |
| Application code | source, dependency, artifact | 21 | Default code profiles and MCP code catalog; ordered supply-chain evidence is composed separately |
| Web compatibility | network, enterprise, cloud account | 22 | Explicit module IDs or the `compatibility` template |
| Code compatibility | cloud account | 1 (`scoutsuite`) | Explicit module ID |

`all_modules()` and `all_code_modules()` retain the full registries for compatibility. Callers that
present a default catalog use `application_modules()` or `application_code_modules()`. The CLI shows
the complete web registry only with `scorchkit modules --include-compatibility`.

## Adapter contract

Every web, code, infrastructure, and cloud module descriptor embeds
`scorchkit.adapter/v1`. The contract records:

- application or compatibility domain;
- lifecycle stage and accepted target kinds;
- strongest effect class;
- native output shape, including JSON, JSONL, XML, text, SARIF, or owned files;
- tool, rule-set, template-set, built-in, or plugin provenance;
- temporary-artifact ownership;
- engine-assigned `first_party` or `third_party` trust and `compiled` or `wasm_worker` runtime.

The root composition package assigns concrete module IDs to these fields. Family packages own the
shared descriptor shape, and agent, CLI, MCP, and orchestrator code read the resulting descriptor.
Scanner IDs and serialized findings are unchanged.

Configured isolated extensions join the same application web catalog after explicit digest and
policy validation. CLI, control, and MCP projections expose their trust/runtime labels; manifests
cannot select compatibility domains or claim first-party trust.

Nuclei, Semgrep, PHPStan, CodeQL, and Psalm use typed parser outcomes. Their execution paths
distinguish a valid empty result from malformed or scanner-failed output and return a parse error for
the latter. CodeQL and Psalm share one strict SARIF decoder. Legacy parser helpers used by existing
callers keep their previous empty-vector behavior. Later adapter tickets should use the same outcome
instead of adding another parser result type.

Code descriptors also declare `fast` or `deep` analysis. `standard` keeps fast application
modules, while `thorough` and `pentest` add CodeQL and Psalm. PHPStan is a correctness module;
its findings do not receive invented vulnerability classifications. The MCP code catalog exposes
category and depth.

Temporary output belongs to the adapter that created it. Scoped temporary files and directories
are removed by their ownership guards. Adapters do not share fixed output directories.

## Explicit access does not bypass policy

An explicit compatibility module selection only makes the module eligible to run. It does not add
an engagement, widen scope, or grant `external-tool`, `credential-use`, `credential-test`, or
`exploit`. The same descriptor-backed effect classification is used for profile filtering and DAST
tool authorization. In particular, Hydra, Kerbrute, NetExec, onesixtyone, and SMBMap require
credential-test authority, while Commix and Metasploit require exploit authority. The compatibility
Prowler wrapper requires a separate passive credential-use grant before it can inherit cloud
credentials.
