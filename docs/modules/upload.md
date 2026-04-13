# File Upload Testing

**Module ID:** `upload` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/upload.rs`

## What It Does

Tests file upload endpoints for unrestricted file type acceptance and bypass techniques. Discovers upload forms by parsing HTML for `<input type="file">` elements, then submits 9 test payloads covering server-side script uploads, double extension bypass, content-type mismatch, polyglot files, null byte injection, path traversal filenames, and dangerous content (SVG XSS, HTML).

## Checks Performed

| Check | Description |
|-------|-------------|
| Form discovery | Parses HTML for `<form>` elements containing file inputs, extracts action URLs and hidden fields |
| PHP/JSP script upload | Submits .php and .jsp files to test unrestricted server-side script upload |
| Double extension bypass | Uploads `test.php.jpg` to bypass last-extension-only validation |
| Content-Type mismatch | Uploads .php file with `image/png` Content-Type to bypass MIME validation |
| Polyglot GIF+PHP | Uploads file starting with `GIF89a` magic bytes followed by PHP code |
| Null byte filename | Uploads `test.php%00.jpg` to exploit C-style string truncation |
| Path traversal filename | Uploads `../../test.php` to write files outside the upload directory |
| SVG XSS | Uploads SVG with `onload` event handler for stored XSS |
| HTML upload | Uploads HTML with embedded JavaScript for stored XSS |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Upload Accepted: PHP Script Upload | Critical | 434 | Server accepted .php file upload |
| Upload Accepted: JSP Script Upload | Critical | 434 | Server accepted .jsp file upload |
| Upload Accepted: Double Extension Bypass | High | 434 | Server accepted .php.jpg file upload |
| Upload Accepted: Content-Type Mismatch | High | 434 | Server accepted .php with image/png Content-Type |
| Upload Accepted: Polyglot GIF+PHP | High | 434 | Server accepted GIF-headed PHP file |
| Upload Accepted: Null Byte Filename | High | 434 | Server accepted filename with %00 |
| Upload Accepted: Path Traversal Filename | Critical | 22 | Server accepted filename with `../../` |
| Upload Accepted: SVG XSS Upload | Medium | 79 | Server accepted SVG with JavaScript event handler |
| Upload Accepted: HTML Upload | Medium | 79 | Server accepted HTML with embedded script |

## OWASP Coverage

**A04:2021 -- Insecure Design.** Covers unrestricted file upload leading to remote code execution (CWE-434), path traversal via filename manipulation (CWE-22), and stored cross-site scripting via dangerous content types (CWE-79).

## How It Works

1. **Form discovery**: Fetches the target URL, parses the HTML with `scraper`, and finds `<form>` elements containing `<input type="file">`. Extracts the form action URL (resolved against base URL), the file field name, and any hidden input fields (e.g., CSRF tokens).
2. **Payload submission**: For each discovered form, submits all 9 test payloads via multipart/form-data POST. Each payload has a specific filename, Content-Type, and body content designed to test a particular bypass technique.
3. **Acceptance heuristic**: Determines if the upload was accepted based on HTTP status (200, 201, 302 = accepted; 400, 403, 415, 422, 500+ = rejected) and response body analysis (checks for error indicators like "file type not allowed", "invalid file", "upload failed").

## Example Output

```
[Critical] Upload Accepted: PHP Script Upload
  The upload form at 'https://example.com/upload' (field: 'document') accepted
  a PHP Script Upload upload. Server-side script files can lead to remote code
  execution if stored in a web-accessible directory.
  Evidence: Filename: scorchkit-test.php | Content-Type: application/x-php | Form field: document
  Remediation: Restrict uploads to a whitelist of safe file extensions
  OWASP: A04:2021 Insecure Design | CWE-434
```
