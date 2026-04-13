# Technology Fingerprinting

**Module ID:** `tech` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/tech.rs`

## What It Does

Identifies the server technologies, frameworks, CMS platforms, and infrastructure providers powering the target web application. The module analyzes response headers, HTML body content, meta tags, cookie names, and asset paths to build a comprehensive technology profile. All findings are informational and help guide further scanning.

## Checks Performed

### Server Header Signatures (20 patterns)

| Pattern | Technology |
|---------|-----------|
| `nginx` | Nginx |
| `apache` | Apache |
| `iis` | Microsoft IIS |
| `litespeed` | LiteSpeed |
| `caddy` | Caddy |
| `cloudflare` | Cloudflare |
| `openresty` | OpenResty |
| `gunicorn` | Gunicorn (Python) |
| `uvicorn` | Uvicorn (Python) |
| `express` | Express.js |
| `kestrel` | Kestrel (ASP.NET) |
| `cowboy` | Cowboy (Erlang) |
| `envoy` | Envoy Proxy |
| `traefik` | Traefik |
| `jetty` | Jetty (Java) |
| `tomcat` | Apache Tomcat |
| `werkzeug` | Werkzeug (Python/Flask) |
| `phusion passenger` | Phusion Passenger |
| `thin` | Thin (Ruby) |
| `puma` | Puma (Ruby) |

### X-Powered-By and Framework Headers

- `X-Powered-By` -- runtime/framework disclosure
- `X-AspNet-Version` -- ASP.NET version
- `X-AspNetMvc-Version` -- ASP.NET MVC version

### Meta Generator Tags

Parses `<meta name="generator" content="...">` tags from the HTML to identify CMS platforms (e.g., WordPress 6.4, Drupal 10, Hugo 0.120).

### Cookie Patterns (23 signatures)

| Cookie Name | Technology |
|-------------|-----------|
| `JSESSIONID` | Java |
| `PHPSESSID` | PHP |
| `ASP.NET_SessionId` | ASP.NET |
| `ASPSESSIONID` | Classic ASP |
| `laravel_session` | Laravel (PHP) |
| `ci_session` | CodeIgniter (PHP) |
| `connect.sid` | Express.js (Node.js) |
| `_rails_session` | Ruby on Rails |
| `rack.session` | Rack (Ruby) |
| `SERVERID` | HAProxy |
| `AWSALB` | AWS ALB |
| `AWSALBCORS` | AWS ALB |
| `__cfduid` | Cloudflare |
| `cf_clearance` | Cloudflare |
| `wp-settings-` | WordPress |
| `wordpress_logged_in` | WordPress |
| `Drupal.visitor` | Drupal |
| `SSESS` | Drupal |
| `csrftoken` | Django (Python) |
| `sessionid` | Django (Python) |
| `_ga` | Google Analytics |
| `_gid` | Google Analytics |
| `__stripe_mid` | Stripe |

### Body Signatures (28 patterns)

Scans the HTML body (case-insensitive) for framework and CMS indicators:

- **WordPress**: `wp-content/`, `wp-includes/`, `wp-json/`
- **Drupal**: `/sites/default/files/`, `drupal.js`, `jquery.once`
- **Joomla**: `joomla`, `/media/system/js/`
- **Shopify**: `shopify.com/s/files`, `cdn.shopify.com`
- **Squarespace**: `squarespace.com`, `static.squarespace.com`
- **Next.js**: `_next/static`, `__next`
- **Nuxt.js**: `__nuxt`
- **SvelteKit**: `_sveltekit`
- **Gatsby**: `gatsby-`
- **React**: `data-reactroot`
- **Angular**: `ng-version`
- **Vue.js**: `data-v-`
- **Ember.js**: `ember-view`
- **Ghost CMS**: `ghost.io`, `ghost-url`
- **TYPO3**: `typo3temp/`
- **Magento**: `magento/`, `skin/frontend/`

### Framework Headers (8 providers)

| Header | Platform |
|--------|----------|
| `x-drupal-cache` / `x-generator: drupal` | Drupal |
| `x-shopify-stage` | Shopify |
| `x-wix-request-id` | Wix |
| `x-vercel-id` | Vercel |
| `x-netlify-request-id` / `x-nf-request-id` | Netlify |
| `cf-ray` | Cloudflare |
| `x-amz-cf-id` / `x-amz-request-id` | AWS |
| `x-firebase-hosting` | Firebase Hosting |

### Asset Path Patterns (16 patterns)

Inspects `<link href>` and `<script src>` attributes for CMS-identifying paths:

| Path Pattern | Technology |
|-------------|-----------|
| `/wp-content/` | WordPress |
| `/wp-includes/` | WordPress |
| `/sites/all/` | Drupal |
| `/sites/default/` | Drupal |
| `/core/misc/` | Drupal |
| `/modules/` | Drupal |
| `/media/system/` | Joomla |
| `/components/com_` | Joomla |
| `/_next/` | Next.js |
| `/__nuxt/` | Nuxt.js |
| `/static/js/main.` | Create React App |
| `/build/` | Laravel Mix |
| `/bundles/` | Symfony |
| `/typo3conf/` | TYPO3 |
| `/skin/frontend/` | Magento |
| `/static/version` | Magento 2 |

## Findings

All findings from this module use **Info** severity.

| Title | Description |
|-------|-------------|
| Server Technology Detected | Server technology identified from the Server header |
| Framework/Runtime Detected via X-Powered-By | X-Powered-By header reveals runtime or framework |
| ASP.NET Version Detected | Version exposed via X-AspNet-Version or X-AspNetMvc-Version |
| CMS/Framework Detected via Meta Generator | `<meta name="generator">` tag reveals CMS or framework |
| Technology Detected via Cookie Names | Cookie names match known technology patterns |
| {Technology} Detected | Technology detected from framework-specific response headers or body signatures |
| {Technology} Detected via Asset Paths | CSS/JS resource paths in HTML reveal CMS or framework |

## OWASP Coverage

This module is informational and does not directly map to OWASP Top 10 categories. However, the information it gathers supports:

- **A05:2021 -- Security Misconfiguration**: Identifying exposed technology versions
- **A06:2021 -- Vulnerable and Outdated Components**: Determining what software is in use to check for known CVEs

## How It Works

1. Sends a single GET request to the target URL.
2. Clones the response headers and reads the full response body.
3. Runs 6 detection functions in sequence:
   - `detect_server_tech` -- matches the `Server` header against 20 known server signatures.
   - `detect_powered_by` -- reads `X-Powered-By`, `X-AspNet-Version`, and `X-AspNetMvc-Version`.
   - `detect_meta_generator` -- parses HTML with the `scraper` crate to find `<meta name="generator">` tags.
   - `detect_cookie_tech` -- aggregates all `Set-Cookie` headers and matches names against 23 known patterns.
   - `detect_framework_signatures` -- checks 8 platform-specific response headers and scans the body for 28 technology markers.
   - `detect_cms_indicators` -- parses `<link>` and `<script>` elements, matching `href`/`src` attributes against 16 asset path patterns.
4. Each detection method produces one or more Info-severity findings with evidence strings.

## Example Output

```
[INFO] Server Technology Detected
  URL: https://example.com/
  Server technology identified: Nginx
  Evidence: Server: nginx/1.24.0

[INFO] CMS/Framework Detected via Meta Generator
  URL: https://example.com/
  The page declares its generator: WordPress 6.4.2
  Evidence: <meta name="generator" content="WordPress 6.4.2">

[INFO] Technology Detected via Cookie Names
  URL: https://example.com/
  Cookie names suggest: WordPress (cookie: wp-settings-)
  Evidence: Cookies: wp-settings-

[INFO] Cloudflare Detected
  URL: https://example.com/
  The target appears to use Cloudflare
  Evidence: Detected via response signatures
```
