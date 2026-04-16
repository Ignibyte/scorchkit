# Kubescape

Kubernetes security posture scanner — evaluates manifests and running clusters against NSA, MITRE, ArmoBest, and CIS frameworks. License: Apache-2.0 (upstream: [kubescape/kubescape](https://github.com/kubescape/kubescape)).

## Install

```
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `kubescape scan --format json <path>` and iterates `results[]`, keeping only controls where `status == "failed"`. Severity is derived from the kubescape `scoreFactor`:

| scoreFactor | ScorchKit severity |
|---|---|
| ≥ 7.0 | High |
| ≥ 4.0 | Medium |
| < 4.0 | Low |

Each finding carries:

- **Title**: `kubescape <control-id>: <name>` (e.g. `kubescape C-0001: Forbidden user`)
- **Description**: `Control <id> (<name>) failed`
- **Affected**: `kubernetes-manifests`
- **Evidence**: `controlID=<id> score=<factor>`
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.9

## How to run

```
scorchkit code /path/to/k8s/manifests --modules kubescape
```

180s timeout. Path should contain Kubernetes YAML (deployments, services, RBAC, NetworkPolicies, etc.).

## Limitations vs alternatives

- **vs `kics`**: kics covers many IaC formats with one rule set; kubescape is K8s-focused with framework-level traceability (NSA / MITRE / ArmoBest / CIS) that compliance auditors want. Pair them.
- **vs `checkov`**: checkov has K8s coverage but is less framework-aware; kubescape's strength is the mapping to named control frameworks.
- **Manifest-mode only in this wrapper**. Kubescape also supports live-cluster scanning (`kubescape scan framework --submit`); not wrapped — operators who need it run kubescape directly.
- **No CWE mapping** — kubescape controls are mapped to MITRE ATT&CK and framework IDs, not CWE. Reflected in omitted field rather than a forced-wrong value.
