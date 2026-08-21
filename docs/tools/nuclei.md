# Trusted Nuclei application probes

**Module ID:** nuclei

**Supported binary:** Nuclei 3.11.1 exactly

**Architecture:** [Trusted Nuclei boundary](../architecture/trusted-nuclei.md)

ScorchKit does not run Nuclei's installed community collection. It runs one explicit local
collection of reviewed application HTTP probes. Every run verifies the collection schema,
certificate digest, template digest, template ID, declared effect, signature fragment, and native
Nuclei signature before accepting results.

The runtime denies code, JavaScript, file, DNS, raw network, headless, WebSocket, workflow,
self-contained, unsafe HTTP, redirect, fuzzing, payload, remote URL, OAST, credential-header, and
authority-changing behavior. Request paths, headers, and bodies cannot introduce unreviewed Nuclei
expressions. The first release supports unauthenticated HTTP probes only.
Response operators are limited to schema-checked non-DSL matchers and extractors, so a matcher
cannot use Nuclei helper functions to resolve an unapproved host or generate a second effect.

## Installation

Install the checksum-verified official 3.11.1 archive. The ScorchKit build host uses:

~~~text
/mnt/fast/scorchkit/tools/nuclei/v3.11.1/nuclei
~~~

and exposes that file through /usr/local/bin/nuclei. Do not install latest, run nuclei -ut, or
depend on an ambient nuclei-templates directory for ScorchKit scans.

## Configuration

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

The engagement must authorize the canonical manifest, certificate, and template paths through a
path_prefix rule with local-state/passive. It must also grant dast-scan and external-tool at the
collection's exact strongest effect for the target and every resolved address.

Configured limits may be reduced, but not raised past ScorchKit's hard ceilings: 8 MiB per manifest
or template, 1 MiB per certificate, 1,024 templates, 64 MiB per output stream, 1 GiB and 10,000
entries per workspace, one hour per process, 1,000 requests per second, 64 concurrent templates,
and 120 seconds per request.

## Collection manifest

The manifest uses scorchkit.nuclei-collection/v1:

~~~json
{
  "schema_version": "scorchkit.nuclei-collection/v1",
  "collection_id": "application-baseline",
  "version": "1.0.0",
  "signer": {
    "identity": "application-security-review",
    "certificate": "reviewer.crt",
    "certificate_sha256": "<lowercase SHA-256>",
    "signature_fragment": "<32 lowercase hexadecimal characters>"
  },
  "templates": [
    {
      "id": "application-health-probe",
      "path": "application-health-probe.yaml",
      "sha256": "<lowercase SHA-256>",
      "strongest_effect": "active-safe",
      "reviewed_by": "reviewer identity",
      "reviewed_at": "2026-08-21T00:00:00Z"
    }
  ]
}
~~~

Paths are strict manifest-relative regular files read through the same no-follow handle that passed
identity and policy authorization. Symlinks, parent components, absolute paths, replacements,
duplicates, size overruns, digest mismatches, unsigned files, and signer mismatches fail closed.

## Review and signing ceremony

1. Put a proposed HTTP template outside every approved collection.
2. Review its exact request behavior and assign its strongest effect.
3. Sign the reviewed bytes with Nuclei using an offline private key.
4. Publish only the public Nuclei certificate.
5. Record the signed file's SHA-256, signer fragment, reviewer, and review time in the manifest.
6. Re-review and re-sign after any byte changes.

The runtime never receives a signing private key. An agent can draft a proposal, but it cannot
promote or sign its own executable probe.

## Execution evidence

JSON, MCP, storage, terminal, HTML, PDF, and SARIF results carry the same adapter assessment:
supported Nuclei version, collection identity, exact template IDs and digests, signer identity,
strongest effect, terminal status, and redacted gaps. Failed signature verification, malformed
JSONL, escaped targets, missing configuration, and process failures cannot become a clean scan.
