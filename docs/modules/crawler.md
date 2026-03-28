# Web Crawler

**Module ID:** `crawler` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/crawler.rs`

## What It Does

Crawls the target website to discover endpoints, forms, URL parameters, and JavaScript files. The crawler follows links up to a configurable depth, extracts form structures and input fields, identifies external JS resources, and parses inline JavaScript for API route patterns. It feeds discovered information into the scan context for use by other modules.

## Checks Performed

### Link Extraction and Following

- Parses all `<a href>` elements from each crawled page
- Resolves relative URLs against the current page URL
- Follows discovered links up to **depth 3**
- Stops after visiting **100 pages** maximum

### Scope Enforcement

- Only follows links whose host matches the target's base domain
- Skips URLs with paths containing `logout`, `signout`, or `delete` to avoid destructive actions
- Skips responses with non-HTML/non-JavaScript content types

### Form Discovery

- Parses all `<form>` elements from crawled pages
- Extracts `action` URL (resolved to absolute) and HTTP `method`
- Collects all named `<input>`, `<textarea>`, and `<select>` field names
- Reports POST forms with more than 1 field

### URL Parameter Collection

- Extracts query string parameter names from every visited URL
- Deduplicates parameter names across all pages
- Reports up to 30 unique parameters

### JavaScript File Discovery

- Collects all `<script src>` URLs from crawled pages
- Resolves relative script paths to absolute URLs
- Deduplicates across the entire crawl

### API Route Extraction from Inline JS

Parses `<script>` elements without a `src` attribute (inline JavaScript) and searches for common API route patterns:

| Pattern | What It Indicates |
|---------|-------------------|
| `/api/` | REST API endpoint |
| `/v1/` | Versioned API (v1) |
| `/v2/` | Versioned API (v2) |
| `/v3/` | Versioned API (v3) |
| `/graphql` | GraphQL endpoint |
| `/rest/` | REST service endpoint |

Routes are extracted by finding the pattern in each line, then scanning backwards for a quote character (`"`, `'`, `` ` ``) to identify the start of the URL string. Discovered routes are resolved against the current page URL and added to the discovered URL set.

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| Crawled {N} Pages | Info | Summary with counts of pages, URLs, forms, JS files |
| Form Discovered: POST {url} | Info | POST form with its field names (only forms with >1 field) |
| {N} URL Parameters Discovered | Info | List of discovered query parameter names (up to 30) |

## OWASP Coverage

The crawler is a reconnaissance tool that supports all other scanning modules. Its discoveries feed into checks for:

- **A03:2021 -- Injection**: Discovered parameters and forms become injection test targets
- **A01:2021 -- Broken Access Control**: Discovered endpoints reveal access control boundaries
- **A04:2021 -- Insecure Design**: API routes and form structures reveal application architecture

## How It Works

1. Initializes a breadth-first crawl queue starting from the target URL at depth 0.
2. For each URL in the queue:
   - Validates the URL is within scope (same domain as target).
   - Skips dangerous paths (logout, signout, delete).
   - Sends a GET request and checks the Content-Type (must be HTML or JavaScript).
   - Parses the response body with the `scraper` crate.
3. Extraction phase for each page:
   - **Links**: Selects `a[href]` elements, resolves URLs, adds in-scope links to the crawl queue for the next depth level.
   - **Forms**: Selects `form` elements, extracts action/method, then selects `input[name]`, `textarea[name]`, `select[name]` within each form.
   - **Parameters**: Iterates over query string pairs from the current URL.
   - **JS files**: Selects `script[src]` elements and resolves the `src` attribute.
   - **Inline JS routes**: Selects `script:not([src])` elements and scans text content for API route patterns.
4. After the crawl completes, generates summary findings covering page count, discovered URLs, forms with their fields, and parameter lists.

## Example Output

```
[INFO] Crawled 47 Pages
  URL: https://example.com/
  Web crawler visited 47 pages and discovered 152 unique URLs, 8 forms, 23 JS files.
  Evidence: Pages: 47 | URLs: 152 | Forms: 8 | Parameters: 12 | JS files: 23

[INFO] Form Discovered: POST https://example.com/contact
  URL: https://example.com/contact
  POST form with fields: name, email, subject, message
  Evidence: POST https://example.com/contact | Fields: name, email, subject, message

[INFO] Form Discovered: POST https://example.com/login
  URL: https://example.com/login
  POST form with fields: username, password, csrf_token
  Evidence: POST https://example.com/login | Fields: username, password, csrf_token

[INFO] 12 URL Parameters Discovered
  URL: https://example.com/
  URL parameters found during crawling that may be testable for injection.
  Evidence: Parameters: page, id, q, sort, category, lang, ref, utm_source, token, action, type, format
```
