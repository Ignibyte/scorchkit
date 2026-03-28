# XXE Detection

**Module ID:** `xxe` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/xxe.rs`

## What It Does

Detects XML External Entity (XXE) injection by sending crafted XML payloads to endpoints that accept XML input. It first probes whether an endpoint processes XML at all, then tests with entity expansion and external file entity payloads to confirm XXE vulnerability.

## Checks Performed

### Endpoints Tested (7)

| # | Path | Rationale |
|---|------|-----------|
| 1 | _(target URL)_ | The target URL itself |
| 2 | `/api` | Generic API endpoint |
| 3 | `/api/v1` | Versioned API endpoint |
| 4 | `/xmlrpc.php` | WordPress XML-RPC |
| 5 | `/soap` | SOAP web service |
| 6 | `/wsdl` | WSDL service description |
| 7 | `/upload` | File upload endpoint |

### XXE Payloads (2)

| # | Payload | Marker | Description |
|---|---------|--------|-------------|
| 1 | Internal entity: `<!ENTITY xxe "scorchkit_xxe_confirmed">` | `scorchkit_xxe_confirmed` | Entity expansion -- confirms DTD processing |
| 2 | External file entity: `<!ENTITY xxe SYSTEM "file:///etc/hostname">` | _(none -- 500 check)_ | File read attempt |

### Detection Flow

1. A benign XML document (`<test>scorchkit</test>`) is POSTed with `Content-Type: application/xml`.
2. If the endpoint returns 404 or 405, it is skipped.
3. If the endpoint processes XML (returns 200, 400, or 500), the XXE payloads are tested.

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| XML External Entity Injection Confirmed | Critical | 611 | Canary marker `scorchkit_xxe_confirmed` found in response |
| Possible XXE: Server Error on Entity Payload | Medium | 611 | Normal XML returns 200 but entity payload returns 500 |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** XXE is enabled by default in many XML parsers. Misconfigured parsers that process DTDs and external entities can lead to file disclosure, SSRF, and denial of service.

## How It Works

1. For each of the 7 endpoints, a benign XML POST is sent to determine if the endpoint accepts XML.
2. Endpoints returning HTTP 404 or 405 are skipped; all other status codes proceed to XXE testing.
3. The internal entity expansion payload injects `<!ENTITY xxe "scorchkit_xxe_confirmed">` and references `&xxe;` in the body. If the response contains the marker string, entity processing is confirmed.
4. The external file entity payload attempts to read `/etc/hostname` via `SYSTEM "file:///etc/hostname"`. Since the hostname content is unpredictable, this payload relies on 500 error detection instead.
5. A 500 error on an XXE payload when the benign XML returned 200 suggests the XML parser is processing DTDs, even if it cannot resolve the external entity.
6. Testing stops at the first confirmed finding across all endpoints.

## Example Output

```
[Critical] XML External Entity Injection Confirmed
  Internal entity expansion confirmed. The server processes external XML entities,
  allowing file read, SSRF, and potentially RCE.
  Evidence: Endpoint: https://example.com/api | Marker: scorchkit_xxe_confirmed found in response
  Remediation: Disable external entity processing in your XML parser. Set DTD processing to prohibited.
  OWASP: A05:2021 Security Misconfiguration | CWE-611
```
