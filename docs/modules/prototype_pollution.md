# Prototype Pollution Detection

**Module ID:** `prototype_pollution` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/prototype_pollution.rs`

## What It Does

Probes JSON POST endpoints and GET query strings for prototype pollution by
injecting `__proto__` and `constructor.prototype` properties with a canary
value (`scorch_polluted`). If the canary is reflected in the response —
commonly when the server merges user input into an object and echoes it back
— the target's object-merging logic is likely vulnerable. A baseline GET is
taken first so the canary is only flagged when it appears *after* the
injection.

## What It Checks

**JSON body payloads** (4):
- `{"__proto__":{"scorch_polluted":"true"}}`
- `{"constructor":{"prototype":{"scorch_polluted":"true"}}}`
- `{"__proto__":{"toString":"polluted"}}`
- `{"__proto__":{"isAdmin":true}}`

**Query parameter payloads** (3):
- `__proto__[scorch_polluted]=true` (bracket notation)
- `__proto__.scorch_polluted=true` (dot notation)
- `constructor[prototype][scorch_polluted]=true`

| Condition | Severity |
|-----------|----------|
| Canary `scorch_polluted` reflected after JSON body injection | Medium |
| 500 response to a prototype-pollution JSON payload | Low |
| Canary reflected after query-parameter injection | Medium |

## How to Run

```
scorchkit run https://example.com/api/profile --modules prototype_pollution
```

Point at an endpoint that accepts JSON bodies (profile updates, settings,
config merges). Parameter-pollution detection works on any URL.

## Limitations

- Reflection-based detection only — vulnerabilities that *mutate*
  `Object.prototype` without echoing the polluted property back cannot be
  found this way. This module is a screening probe; confirm with
  nuclei/Burp templates for suspected pollution.
- Stops at the first matching payload in each branch (JSON vs. params).
- Confidence is 0.5 for reflection findings; treat as leads for manual
  verification rather than confirmed bugs.

## OWASP / CWE

- **A08:2021 Software and Data Integrity Failures**, CWE-1321 (Improperly
  Controlled Modification of Object Prototype Attributes).
