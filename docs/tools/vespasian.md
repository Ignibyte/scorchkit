# `vespasian` — API endpoint discovery (Praetorian)

Wrapper around [Vespasian](https://github.com/praetorian-inc/vespasian) (Apache-2.0, Go). Crawls a target via headless browser (powered by Katana), classifies captured HTTP traffic into REST / GraphQL / SOAP / WebSocket buckets, and synthesises an OpenAPI 3.0 spec.

## Install

```
go install github.com/praetorian-inc/vespasian/cmd/vespasian@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

- **Summary** Info finding listing the total endpoint count + spec title
- **Per-endpoint** Info findings (one per `path × method`), capped at 50 per scan to keep reports readable

The full OpenAPI YAML is written to a temp file during the scan; downstream tooling (WORK-108 spec consumer, when shipped) will read it back from `shared_data`.

## Limitations

- Vespasian's crawl is probabilistic — endpoints behind specific request sequences or hidden routes may be missed
- Browser crawl can't observe mobile-app API calls. For mobile, run `vespasian import burp <traffic.xml>` outside ScorchKit and feed the resulting OpenAPI spec into your scanners directly
