# DOM XSS Detection

**Module ID:** `dom_xss` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/dom_xss.rs`

## What It Does

Performs static pattern analysis of JavaScript embedded in the target
HTML response, flagging dangerous **source → sink** combinations that can
enable DOM-based XSS. The module does not execute JavaScript; it looks for
textual co-occurrence of known user-controllable sources and dangerous
output sinks, then surfaces the pair for manual review.

## What It Checks

**Sources** (12 patterns): `location.hash`, `location.search`,
`location.href`, `location.pathname`, `document.URL`,
`document.documentURI`, `document.referrer`, `window.name`, `postMessage`,
`document.cookie`, `localStorage`, `sessionStorage`.

**Sinks** (15 patterns): `document.write`, `document.writeln`, `.innerHTML`,
`.outerHTML`, `.insertAdjacentHTML`, `eval(`, `setTimeout(`, `setInterval(`,
`Function(`, `execScript(`, `.src=`, `.href=`, `.action=`, `$.html(`,
`$.append(`.

| Condition | Severity |
|-----------|----------|
| Both at least one source and one sink detected in the page | High (confidence 0.4) |
| Critical sink present (`document.write`, `eval(`, `.innerHTML`) with no source visible inline | Medium (confidence 0.4) |

## How to Run

```
scorchkit run https://example.com --modules dom_xss
```

## Limitations

- Only inline scripts and the primary HTML response are analyzed. External
  JavaScript files are **not** fetched here — pair with `js_analysis` to
  cover referenced bundles.
- This is pattern matching, not data-flow analysis. A source and sink on
  the same page does not prove a tainted path; confidence is 0.4
  accordingly.
- No AST parsing — `innerHTML` appearing in a comment or string literal is
  treated the same as a real assignment.
- The orphan-sink branch emits at most one finding per page.

## OWASP / CWE

- **A07:2021 Cross-Site Scripting**, CWE-79.
