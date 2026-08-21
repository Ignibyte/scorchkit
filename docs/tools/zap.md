# OWASP ZAP application DAST

ScorchKit uses the official OWASP ZAP 2.17.0 Automation Framework through the dedicated
`application_dast` service. ZAP is not registered as an implicit scan module and ScorchKit does
not invoke the obsolete `zap-cli` wrapper.

## Runtime contract

- Binary: `zap.sh`
- Required version: exactly `2.17.0`
- Official Linux asset: `ZAP_2.17.0_Linux.tar.gz`
- SHA-256: `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`
- Build-host path: `/mnt/fast/scorchkit/tools/zap/2.17.0/zap.sh`
- Required add-ons: Automation Framework, Client Spider, Reports, Network, Selenium, and Linux
  WebDrivers
- Reviewed browser driver: ChromeDriver `151.0.7922.137`
- ChromeDriver Linux archive SHA-256: `6796e1d222c0a37befa1385c69ff2d62592ebbe2d98ed36c874ae3a67d1d5cba`
- Installed ChromeDriver SHA-256: `8f4f204a7977351c3408f46d4234435f522935921578e8758c178f99fb2f44bb`
- ChromeDriver path: `/mnt/fast/scorchkit/tools/chromedriver/151.0.7922.137/chromedriver`

Set the executable override when it is not already on `PATH`:

```toml
[tools]
zap = "/mnt/fast/scorchkit/tools/zap/2.17.0/zap.sh"
chromedriver = "/mnt/fast/scorchkit/tools/chromedriver/151.0.7922.137/chromedriver"
```

`scorchkit doctor --deep` verifies the exact ZAP version and required add-ons. Browser-authenticated
plans also require `tools.chromedriver` or `tools.geckodriver`; the driver major must match the
installed browser. Driver, browser, and add-on installation or updates are operator-owned
maintenance actions and never happen during a scan.

## Public request

CLI accepts a bounded JSON request file:

```console
scorchkit dast ./dast-request.json
```

The library uses `Engine::application_dast`; MCP uses `application_dast`. The request contains a
credential-free HTTP(S) base URL, the `passive`, `standard`, or `active` phase profile, anonymous
selection, configured persona IDs, and optional local schemas with their expected SHA-256.

```json
{
  "target": "https://app.example.test/",
  "profile": "standard",
  "include_anonymous": true,
  "personas": ["user"],
  "schemas": [
    {
      "kind": "open_api",
      "path": "/owned/app/openapi.yaml",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Persona configuration stores environment-variable names, never credential values. See
[`../architecture/application-dast.md`](../architecture/application-dast.md) for the exact grant,
plan, isolation, evidence, and coverage contracts.

## Evidence

Each ZAP alert instance becomes a separate finding with plugin and CWE identity, confidence,
persona, route, plan digest, ZAP version, optional schema operation, and redacted bounded HTTP
request/response evidence. URL export, method-bearing traffic HAR, Traditional JSON Plus, and
named-persona authentication reports are mandatory. Missing or invalid artifacts, failed or lost
authentication, plan errors, and unobserved schema operations remain explicit typed coverage gaps;
an empty findings list is clean only when all selected phases completed.

Named personas also emit a bounded HAR immediately after the forced verification request. ScorchKit
uses it to prove the exact verification URL, expected status and indicator, and configured
credential transport before discovery begins. ZAP's authentication report then supplies the
session-loss statistics used for the final authentication state.
