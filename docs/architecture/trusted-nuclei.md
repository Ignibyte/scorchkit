# Trusted Nuclei execution

ScorchKit treats a Nuclei template as executable security-test input. A file being present in
Nuclei's home directory, named by an agent, or signed by an unknown key does not make it eligible.
The `nuclei` module runs only templates named by one approved local collection manifest.

## Trust boundary

The collection manifest uses `scorchkit.nuclei-collection/v1` and contains:

- a stable collection ID and version;
- one trusted X.509 certificate path, certificate SHA-256, and Nuclei signer fragment;
- an ordered list of template IDs, relative paths, exact SHA-256 values, declared strongest
  effects, and review records.

Paths are relative to the canonical manifest directory. ScorchKit rejects absolute paths, parent
components, symbolic links, non-regular files, duplicate IDs or paths, unknown fields, oversized
files, excessive entries, and any canonical path outside that directory. It reads each certificate
and template from the same no-follow file handle whose canonical identity was authorized, verifies
those bytes, then writes private owned copies for both Nuclei validation and execution. The scanned
copy is therefore the copy that was inspected.

Approval has three independent parts:

1. the manifest pins the exact file digest and review metadata;
2. the inline Nuclei digest names the manifest's signer fragment;
3. a clean `nuclei -validate -dut` preflight accepts the same owned bytes while
   `NUCLEI_USER_CERTIFICATE` contains only the verified public certificate.

The scan invocation repeats `-dut`. A proposal outside the approved manifest is inert. ScorchKit
never loads a signing private key and never promotes a proposal during a scan.

## Application-only protocol policy

The first trusted runtime accepts structured `http` templates only. It classifies the complete
top-level protocol inventory before invocation and rejects legacy request blocks, workflows, flow,
headless, DNS, TCP/network, file, SSL, WebSocket, WHOIS, code, JavaScript, self-contained, and
multi-protocol templates.

Within an HTTP template, ScorchKit rejects:

- raw or unsafe requests, redirects, out-of-band interaction tokens, external URLs, local payload
  files, fuzzing, and values that can replace the request authority;
- authority, connection, framing, proxy, and credential headers embedded in the template;
- request paths that are not rooted at `{{BaseURL}}` or `{{RootURL}}`;
- CONNECT, TRACE, ambiguous path or header framing, and response DSL; only schema-checked status,
  size, word, regex, binary, JSON, key-value, and regex extraction operators are accepted;
- a declared effect weaker than the minimum implied by its methods and request bodies.

GET, HEAD, and OPTIONS without bodies have an `active-safe` floor. Other methods or bodies have an
`intrusive` floor. A collection may declare a stronger effect, but never a weaker one. Credential
and exploit effects require their separate policy capabilities even when the DAST and process
grants exist.

## Target and process containment

Before any workspace or process exists, the module requires exact grants for:

- the canonical web target and collection's strongest DAST effect;
- the Nuclei external process at that same effect;
- every canonical manifest, certificate, and template path as passive local state;
- credential or exploit capability when the declared effect requires it.

ScorchKit resolves and authorizes every target address through its policy network. It gives Nuclei
a deterministic concrete-address URL, supplies the original host as the HTTP authority and TLS SNI,
and disables redirects. Approved structured paths cannot replace that authority. Nuclei therefore
does not perform a second DNS resolution for the target.

The version probe, signature validation, and scan use the repository process executor with whole
process-group ownership. Each invocation uses a clean environment, private home/config/cache and
working directories, bounded output and artifacts, `-duc`, `-dut`, `-ni`, `-dr`, `-no-stdin`, exact
template paths, explicit rate and concurrency limits, and no cloud, remote-template, AI, workflow,
headless, code, file, or update flags. Supported runtime is pinned to Nuclei 3.11.1 for this ticket.

## Evidence and coverage

Findings keep the verified template ID and SHA-256 as rule provenance and the collection identity
as configuration provenance. Nuclei-reported template paths or digests never replace verified
values. Request and response evidence is normalized and redacted at construction and at every
public or durable projection.

An agent-neutral adapter-execution assessment records the adapter, tool version, configuration
identity, strongest effect, verified inputs, terminal status, and redacted coverage gaps even when
no vulnerability matched. The web orchestrator collects this assessment for successful and failed
runs and projects it through JSON, CLI, MCP, HTML, PDF, SARIF, checkpoints, and storage. A resumed
checkpoint always removes stale Nuclei findings and evidence and reruns the adapter, so a collection
change between processes cannot inherit earlier trust evidence.

## Proposal and review workflow

Agents may add bounded YAML files under an operator-chosen proposals directory and prepare a
candidate manifest entry. Proposal directories are never scanned. A reviewer validates the
application behavior and effect declaration, signs the exact template with a protected Nuclei key,
records reviewer and signer metadata, and adds the final digest-pinned entry to the approved
manifest. Normal Git review remains the change-control boundary; signature possession does not
replace review.
