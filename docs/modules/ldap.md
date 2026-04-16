# LDAP Injection

**Module ID:** `ldap` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/ldap.rs`

## What It Does

Tests URL query parameters, crawled links, and HTML form fields for LDAP
injection by appending LDAP filter metacharacters (`*`, `)`, `(`, `|`) and
filter-breakout payloads to each input, then scanning the response for
LDAP-specific error strings. A secondary 500-response heuristic catches
blind injections when the server swallows error text.

## What It Checks

**Payloads** (11 total): wildcard `*`, filter-close + wildcard
`*)(objectClass=*)`, OR bypass `)(cn=*))(|(cn=*`, AND breakout `*)(&`,
null-byte termination `*))%00`, UID wildcard `*)(uid=*`, escaped
metachars `\28 \29 \2a`, blind enumeration `admin*`.

**Error fingerprints** (22): generic LDAP (`ldap_search`, `ldap_bind`,
`ldap error`, `ldapexception`, `invalid filter`, `unbalanced parenthes`),
Java LDAP (`javax.naming`, `namingexception`, `invalidnameexception`),
Active Directory, PHP LDAP (`ldap_get_entries`, `ldap_first_entry`), Python
LDAP (`ldap.filter`, `ldap.dn`).

| Condition | Severity |
|-----------|----------|
| Any LDAP error fingerprint matches response body | High |
| 500 response to a wildcard-containing payload | Medium |

## How to Run

```
scorchkit run 'https://example.com/search?user=admin' --modules ldap
```

The module also fetches the target, extracts up to 20 parameterized links
and 10 forms, and tests each.

## Limitations

- Stops at the first matching payload per parameter / field to limit
  request volume.
- Form testing uses only the first four payloads per field.
- Pure blind injection with no error message and no status differential is
  not detected — there is no boolean-based or time-based probe.
- The error-fingerprint list is English-only; localized LDAP error pages
  will be missed.

## OWASP / CWE

- **A03:2021 Injection**, CWE-90 (Improper Neutralization of Special
  Elements used in an LDAP Query).
