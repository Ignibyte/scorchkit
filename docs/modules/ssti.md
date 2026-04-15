# Server-Side Template Injection (SSTI)

**Module ID:** `ssti` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/ssti.rs`

## What It Does

Detects server-side template injection across eight template engines —
Jinja2, Twig, Freemarker, ERB, Pebble, Velocity, Smarty, Mako — by
injecting mathematical-expression payloads into URL parameters, form
fields, and HTTP headers, then looking for the *computed* result (e.g. `49`
from `{{7*7}}`) in the response. Boundary-aware matching avoids false
positives from pixel sizes, CSS values, and other incidental `49`s.

All payloads are math-only; this module does not attempt RCE.

## What It Checks

**Polyglot / engine-specific payloads** (10):
- `{{7*7}}` → `49` (Jinja2 / Twig)
- `${7*7}` → `49` (Freemarker / Mako)
- `<%= 7*7 %>` → `49` (ERB)
- `#{7*7}` → `49` (Pebble / Ruby)
- `{{7*'7'}}` → `7777777` (Jinja2 string repetition — distinguishes Jinja2
  from Twig)
- `{{4*4}}{{7*7}}` → `1649` (Twig / Jinja2)
- `${3+4}` → `7` (Freemarker)
- `#set($x=7*7)${x}` → `49` (Velocity)
- `{math equation="7*7"}` → `49` (Smarty, safe-math form)

**Engine fingerprints** (18) identify engine from error text when the
output does not match: `jinja2.exceptions`, `twig_error`, `freemarker.core`,
`velocity`, `smarty_internal`, `mako.exceptions`, `pebble`, `erb`, plus
generic "template error" / "template syntax error".

| Condition | Severity |
|-----------|----------|
| Computed template output matched at word boundary (URL param, form field, or header) | Critical |
| Engine-specific error detected but no computed output | High |

## How to Run

```
scorchkit run 'https://example.com/profile?name=Chad' --modules ssti
```

The module also tests the `User-Agent` and `Referer` headers with the
primary `{{7*7}}` polyglot. Forms are tested with the first four payloads
per field.

## Limitations

- Boundary-aware matching requires the expected output to be flanked by
  non-alphanumeric characters. This reduces false positives at the cost of
  missing engines that render output immediately adjacent to existing
  digits.
- Only the math probe is sent — full exploitation chains (e.g. Jinja2
  `{{config.__class__.__init__.__globals__...}}`) must be validated
  manually once SSTI is confirmed.
- Stops at the first matching payload per parameter / form field.
- Smarty's payload uses `{math}` instead of `{php}` to avoid triggering
  RCE in sandboxed Smarty installations.

## OWASP / CWE

- **A03:2021 Injection**, CWE-1336 (Improper Neutralization of Special
  Elements Used in a Template Engine).
