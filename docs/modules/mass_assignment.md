# Mass Assignment Detection

**Module ID:** `mass_assignment` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/mass_assignment.rs`

## What It Does

Probes JSON-accepting POST endpoints for mass assignment (over-posting) by
injecting a privileged field (`role`, `isAdmin`, `price`, etc.) into the
request body and checking whether the server echoes the field back in the
response. A reflected privileged field is strong evidence the server bound
the raw request to an internal model without allowlist filtering.

A baseline `POST {url}` with `{}` is taken first; any field that naturally
appears in the baseline is skipped to avoid noise.

## What It Checks

| Field | Description | Severity on reflection |
|-------|-------------|------------------------|
| `role` | Role escalation | High |
| `isAdmin`, `is_admin`, `admin` | Admin flag variants | High |
| `is_staff`, `is_superuser` | Django-style privilege flags | High |
| `permissions` | Permissions array (`["admin"]`) | High |
| `price`, `discount` | Business-logic manipulation | Medium |
| `verified`, `email_verified`, `active` | Verification/activation bypass | Medium |

Reflection is detected by case-insensitive substring match on
`"fieldname":` within the response body.

## How to Run

```
scorchkit run https://example.com/api/users --modules mass_assignment
```

Point at an endpoint that accepts JSON POST bodies — account creation,
profile update, order creation — rather than a marketing page.

## Limitations

- JSON reflection is heuristic: a field echoed in an error message counts
  the same as one accepted into the data model. Confidence is 0.6.
- Only sends `POST` with `Content-Type: application/json`. PUT/PATCH, form
  bodies, and XML/GraphQL endpoints are not exercised.
- Sends `{}` as the baseline; endpoints that require authentication,
  anti-CSRF tokens, or specific shape validation will reject every probe
  and produce no findings.
- One finding per matching field — there is no deduplication across related
  fields (e.g. both `admin` and `isAdmin` matching will produce two
  findings).

## OWASP / CWE

- **A04:2021 Insecure Design**, CWE-915 (Improperly Controlled Modification
  of Dynamically-Determined Object Attributes).
