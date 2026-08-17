# 03 — Unified assessment

**Goal:** run the authorized DAST, SAST, infrastructure, and optional cloud families through one
command and produce one report.

**Time:** depends on the selected profile and target size.

Build with the families you need:

```bash
cargo build --release --features infra,cloud
```

## 1. Authorize each family

`assess` does not turn one target grant into another. The active engagement must contain:

- the web hostname and each permitted resolved address for DAST;
- a canonical `path_prefix` for the source tree;
- the exact hostname, address, endpoint, or CIDR for infrastructure work;
- an exact cloud resource rule when `--cloud` is present;
- the capability and exact effect required by the selected profile.

Start with targeted web initialization, then review and extend the generated policy only to match
your written authorization:

```bash
scorchkit init https://owned.example
```

For a quick web, code, and infrastructure assessment, the policy normally needs `dast-scan`,
`code-scan`, `infra-scan`, and `external-tool`; `passive` and `active-safe` effects; and scope rules
for all three target forms. A cloud family also needs `cloud-scan`, `credential-use`, and a `cloud`
scope rule. ScorchKit canonicalizes code paths and rechecks network addresses before effects.

## 2. Run the assessment

```bash
scorchkit --output json assess \
  --url https://owned.example \
  --code /absolute/path/to/owned-source \
  --infra 192.0.2.10 \
  --profile quick
```

Every requested family receives the same profile. The families run concurrently, then their
findings merge into one `ScanResult`. A failed family does not erase successful family results. If
all requested families fail, the command returns the first error.

Omit a family you do not intend to run:

```bash
scorchkit assess --code /absolute/path/to/owned-source --profile quick
```

At least one of `--url`, `--code`, `--infra`, or `--cloud` is required.

## 3. Add cloud posture

Cloud support currently registers five policy-gated tool adapters. The native AWS, GCP, and Azure
SDK implementations are quarantined until their transports enforce ScorchKit's endpoint and DNS
policy.

```bash
scorchkit assess \
  --code /absolute/path/to/owned-source \
  --cloud aws:123456789012 \
  --profile quick
```

The cloud target, credentials, and external tools need their own passive grants. Installed tools and
ambient credentials do not expand engagement scope.

## 4. Add CVE correlation

When `[cve]` selects NVD, OSV, or a composite backend, infrastructure execution injects the CVE
matcher. The provider endpoint, every resolved address, and the existing cache directory require
separate passive infrastructure grants. See [CVE correlation](02-cve-correlation.md).

## 5. Read and compare reports

The global `--output` option applies to unified assessments. JSON is useful for deterministic
filtering:

```bash
jq '.findings[] | select(.severity == "Critical" or .severity == "High")' reports/*.json
scorchkit diff reports/baseline.json reports/current.json
```

AI analysis is optional and labeled separately from scanner evidence:

```bash
scorchkit analyze reports/current.json --focus prioritize
```

Codex is the default configured AI adapter. Claude remains an optional compatibility adapter.

## Troubleshooting

| Symptom | Check |
|---|---|
| One family is denied | Its target form, capability, or exact effect is missing from the engagement. |
| `--cloud` is rejected | Rebuild with the `cloud` feature and add a separate cloud target grant. |
| CVE construction fails | Authorize the provider endpoint, its addresses, and an existing cache directory. |
| Report is empty | Check `modules_skipped` and tool availability; an empty result is not proof that a target is safe. |
