use async_trait::async_trait;
use reqwest::StatusCode;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Discovers sensitive files, directories, and endpoints on the target.
#[derive(Debug)]
pub struct DiscoveryModule;

#[async_trait]
impl ScanModule for DiscoveryModule {
    fn name(&self) -> &'static str {
        "Directory & File Discovery"
    }

    fn id(&self) -> &'static str {
        "discovery"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Discover sensitive files, directories, and exposed endpoints"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let base_url = ctx.target.base_url();
        let mut findings = Vec::new();

        for probe in PROBES {
            let full_url = format!("{}{}", base_url, probe.path);

            let response = ctx
                .http_client
                .get(&full_url)
                .send()
                .await
                .map_err(|e| ScorchError::Http { url: full_url.clone(), source: e })?;

            let status = response.status();

            // Check if the probe matched
            match probe.check {
                ProbeCheck::StatusOk => {
                    if status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        // Verify it's not a generic 200 (custom 404 page)
                        if !is_soft_404(&body, probe.path) {
                            findings.push(build_finding(probe, &full_url, status, Some(&body)));
                        }
                    }
                }
                ProbeCheck::StatusOkWithContent(marker) => {
                    if status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        if body.contains(marker) {
                            findings.push(build_finding(probe, &full_url, status, Some(&body)));
                        }
                    }
                }
                ProbeCheck::StatusOkNoContent(forbidden_marker) => {
                    if status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        if !body.contains(forbidden_marker) && !is_soft_404(&body, probe.path) {
                            findings.push(build_finding(probe, &full_url, status, Some(&body)));
                        }
                    }
                }
                ProbeCheck::AnyNon404 => {
                    if status != StatusCode::NOT_FOUND
                        && status != StatusCode::GONE
                        && status != StatusCode::METHOD_NOT_ALLOWED
                    {
                        findings.push(build_finding(probe, &full_url, status, None));
                    }
                }
            }
        }

        // Check additional paths from custom wordlist if configured
        if let Some(ref wordlist_path) = ctx.config.wordlists.directory {
            if let Ok(extra_paths) = crate::config::load_wordlist(wordlist_path) {
                for path in &extra_paths {
                    let path =
                        if path.starts_with('/') { path.clone() } else { format!("/{path}") };
                    let full_url = format!("{base_url}{path}");
                    let Ok(response) = ctx.http_client.get(&full_url).send().await else {
                        continue;
                    };
                    let status = response.status();
                    if status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        if !is_soft_404(&body, &path) {
                            findings.push(
                                Finding::new(
                                    "discovery",
                                    Severity::Low,
                                    "Discovered Path",
                                    format!("Path {path} is accessible"),
                                    &full_url,
                                )
                                .with_evidence(format!("HTTP {} at {full_url}", status.as_u16()))
                                .with_confidence(0.6),
                            );
                        }
                    }
                }
            }
        }

        // Check for directory listing on the root
        check_directory_listing(ctx, &base_url, &mut findings).await?;

        Ok(findings)
    }
}

fn build_finding(probe: &Probe, url: &str, status: StatusCode, body: Option<&str>) -> Finding {
    let mut f = Finding::new("discovery", probe.severity, probe.title, probe.description, url)
        .with_evidence(format!("HTTP {} at {}", status.as_u16(), url));

    if let Some(remediation) = probe.remediation {
        f = f.with_remediation(remediation);
    }
    if let Some(owasp) = probe.owasp {
        f = f.with_owasp(owasp);
    }
    if let Some(cwe) = probe.cwe {
        f = f.with_cwe(cwe);
    }

    // Add a snippet of the body as additional evidence if available
    if let Some(body) = body {
        if !body.is_empty() {
            let snippet: String = body.chars().take(200).collect();
            f = f.with_evidence(format!(
                "HTTP {} at {} | Body preview: {}",
                status.as_u16(),
                url,
                snippet.replace('\n', " ").replace('\r', "")
            ));
        }
    }

    f = f.with_confidence(0.6);

    f
}

/// Heuristic to detect soft 404 pages (pages that return 200 but are actually "not found").
fn is_soft_404(body: &str, path: &str) -> bool {
    let lower = body.to_lowercase();

    // If the body is very small and generic, likely soft 404
    if body.len() < 50 {
        return false; // Too small to tell, let it through
    }

    // Common soft 404 indicators
    let indicators = [
        "page not found",
        "404 not found",
        "not found",
        "does not exist",
        "page you requested",
        "no longer available",
        "could not be found",
        "we couldn't find",
    ];

    // If the page says "not found" AND doesn't reference the path we probed, it's likely soft 404
    let has_not_found = indicators.iter().any(|i| lower.contains(i));
    let mentions_path = lower.contains(&path.to_lowercase());

    has_not_found && !mentions_path
}

/// Check if directory listing is enabled on the target root.
async fn check_directory_listing(
    ctx: &ScanContext,
    base_url: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Try a few common paths that might show directory listings
    let test_paths = ["/icons/", "/images/", "/assets/", "/static/", "/uploads/"];

    for path in &test_paths {
        let url = format!("{base_url}{path}");
        let response = ctx.http_client.get(&url).send().await;

        if let Ok(resp) = response {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if is_directory_listing(&body) {
                    findings.push(
                        Finding::new(
                            "discovery",
                            Severity::Medium,
                            "Directory Listing Enabled",
                            format!(
                                "Directory listing is enabled at {url}. \
                                 This exposes the file structure to attackers."
                            ),
                            &url,
                        )
                        .with_evidence("Response contains directory index markers")
                        .with_remediation(
                            "Disable directory listing in your web server configuration",
                        )
                        .with_owasp("A05:2021 Security Misconfiguration")
                        .with_cwe(548)
                        .with_confidence(0.6),
                    );
                    break; // One finding is enough
                }
            }
        }
    }

    Ok(())
}

/// Detect if a response body looks like a directory listing.
fn is_directory_listing(body: &str) -> bool {
    let lower = body.to_lowercase();

    // Apache-style directory listing
    if lower.contains("<title>index of") || lower.contains("parent directory") {
        return true;
    }

    // Nginx-style directory listing
    if lower.contains("<title>index of") && lower.contains("<hr>") {
        return true;
    }

    // IIS-style directory listing
    if lower.contains("[to parent directory]") {
        return true;
    }

    // Generic directory listing markers
    if lower.contains("directory listing for") {
        return true;
    }

    false
}

// --- Probe definitions ---

#[derive(Debug)]
enum ProbeCheck {
    /// Path returns HTTP 200
    StatusOk,
    /// Path returns HTTP 200 and body contains the given marker
    StatusOkWithContent(&'static str),
    /// Path returns HTTP 200 and body does NOT contain the given marker
    StatusOkNoContent(&'static str),
    /// Path returns anything other than 404/410/405
    AnyNon404,
}

#[derive(Debug)]
struct Probe {
    path: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    check: ProbeCheck,
    remediation: Option<&'static str>,
    owasp: Option<&'static str>,
    cwe: Option<u32>,
}

/// Sensitive paths to probe.
static PROBES: &[Probe] = &[
    // --- Source control exposure ---
    Probe {
        path: "/.git/HEAD",
        title: "Git Repository Exposed",
        description: "The .git directory is accessible. The entire source code and commit history may be downloadable.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkWithContent("ref:"),
        remediation: Some("Block access to .git/ in your web server configuration"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(538),
    },
    Probe {
        path: "/.svn/entries",
        title: "SVN Repository Exposed",
        description: "The .svn directory is accessible, potentially exposing source code.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOk,
        remediation: Some("Block access to .svn/ in your web server configuration"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(538),
    },
    Probe {
        path: "/.hg/store/00manifest.i",
        title: "Mercurial Repository Exposed",
        description: "The .hg directory is accessible, potentially exposing source code.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOk,
        remediation: Some("Block access to .hg/ in your web server configuration"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(538),
    },

    // --- Environment / config files ---
    Probe {
        path: "/.env",
        title: "Environment File Exposed (.env)",
        description: "The .env file is accessible. It typically contains database credentials, API keys, and other secrets.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkNoContent("<!DOCTYPE"),
        remediation: Some("Block access to .env files in your web server configuration"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/.env.backup",
        title: "Environment Backup File Exposed",
        description: "A backup .env file is accessible, potentially containing secrets.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkNoContent("<!DOCTYPE"),
        remediation: Some("Remove backup files from the web root"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/config.php",
        title: "PHP Config File Accessible",
        description: "config.php is accessible and may expose database credentials or application secrets.",
        severity: Severity::High,
        check: ProbeCheck::StatusOkNoContent("<!DOCTYPE"),
        remediation: Some("Move config files outside the web root or block access"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/wp-config.php.bak",
        title: "WordPress Config Backup Exposed",
        description: "A backup of wp-config.php is accessible, exposing database credentials.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkWithContent("DB_"),
        remediation: Some("Remove backup files from the web root"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },

    // --- Informational files ---
    Probe {
        path: "/robots.txt",
        title: "robots.txt Found",
        description: "robots.txt is accessible. It may reveal hidden paths and directories that the site owner wants to keep from search engines.",
        severity: Severity::Info,
        check: ProbeCheck::StatusOkWithContent("isallow"),
        remediation: None,
        owasp: None,
        cwe: None,
    },
    Probe {
        path: "/sitemap.xml",
        title: "sitemap.xml Found",
        description: "sitemap.xml is accessible, revealing the site's URL structure.",
        severity: Severity::Info,
        check: ProbeCheck::StatusOkWithContent("<?xml"),
        remediation: None,
        owasp: None,
        cwe: None,
    },
    Probe {
        path: "/.well-known/security.txt",
        title: "security.txt Found",
        description: "A security.txt file is present, indicating a responsible disclosure policy.",
        severity: Severity::Info,
        check: ProbeCheck::StatusOkWithContent("Contact"),
        remediation: None,
        owasp: None,
        cwe: None,
    },
    Probe {
        path: "/security.txt",
        title: "security.txt Found (root)",
        description: "A security.txt file is present at the root, indicating a responsible disclosure policy.",
        severity: Severity::Info,
        check: ProbeCheck::StatusOkWithContent("Contact"),
        remediation: None,
        owasp: None,
        cwe: None,
    },

    // --- Admin panels ---
    Probe {
        path: "/admin",
        title: "Admin Panel Found",
        description: "An admin panel or login page was found at /admin.",
        severity: Severity::Low,
        check: ProbeCheck::AnyNon404,
        remediation: Some("Restrict access to admin panels by IP or VPN"),
        owasp: Some("A01:2021 Broken Access Control"),
        cwe: Some(284),
    },
    Probe {
        path: "/wp-admin/",
        title: "WordPress Admin Panel Found",
        description: "The WordPress admin panel is accessible.",
        severity: Severity::Low,
        check: ProbeCheck::AnyNon404,
        remediation: Some("Restrict access to wp-admin by IP, use strong credentials, and enable 2FA"),
        owasp: Some("A01:2021 Broken Access Control"),
        cwe: Some(284),
    },
    Probe {
        path: "/administrator/",
        title: "Joomla Admin Panel Found",
        description: "The Joomla administrator panel is accessible.",
        severity: Severity::Low,
        check: ProbeCheck::AnyNon404,
        remediation: Some("Restrict access to the admin panel by IP or VPN"),
        owasp: Some("A01:2021 Broken Access Control"),
        cwe: Some(284),
    },
    Probe {
        path: "/wp-login.php",
        title: "WordPress Login Page Exposed",
        description: "The WordPress login page is publicly accessible.",
        severity: Severity::Info,
        check: ProbeCheck::StatusOk,
        remediation: Some("Consider restricting access or hiding the login URL"),
        owasp: Some("A07:2021 Identification and Authentication Failures"),
        cwe: None,
    },

    // --- Debug / status endpoints ---
    Probe {
        path: "/server-status",
        title: "Apache server-status Exposed",
        description: "Apache mod_status is accessible, revealing server load, uptime, and active requests.",
        severity: Severity::Medium,
        check: ProbeCheck::StatusOkWithContent("Apache Server Status"),
        remediation: Some("Restrict access to /server-status to localhost or trusted IPs"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/server-info",
        title: "Apache server-info Exposed",
        description: "Apache mod_info is accessible, revealing full server configuration.",
        severity: Severity::High,
        check: ProbeCheck::StatusOkWithContent("Apache Server Information"),
        remediation: Some("Restrict access to /server-info to localhost or trusted IPs"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/phpinfo.php",
        title: "phpinfo() Page Exposed",
        description: "A phpinfo() page is accessible, revealing PHP version, configuration, environment variables, and loaded modules.",
        severity: Severity::High,
        check: ProbeCheck::StatusOkWithContent("phpinfo()"),
        remediation: Some("Remove phpinfo.php from the web server"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/info.php",
        title: "PHP Info Page Exposed",
        description: "A PHP info page is accessible, potentially revealing sensitive configuration.",
        severity: Severity::High,
        check: ProbeCheck::StatusOkWithContent("phpinfo()"),
        remediation: Some("Remove info.php from the web server"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/debug",
        title: "Debug Endpoint Found",
        description: "A debug endpoint is accessible, which may expose sensitive application internals.",
        severity: Severity::Medium,
        check: ProbeCheck::StatusOk,
        remediation: Some("Disable debug mode and remove debug endpoints in production"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(215),
    },
    Probe {
        path: "/elmah.axd",
        title: "ELMAH Error Log Exposed (ASP.NET)",
        description: "ELMAH error log viewer is accessible, exposing stack traces and application errors.",
        severity: Severity::High,
        check: ProbeCheck::StatusOk,
        remediation: Some("Restrict access to ELMAH in web.config"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/actuator/health",
        title: "Spring Boot Actuator Exposed",
        description: "Spring Boot Actuator endpoints are accessible, potentially revealing application health and configuration.",
        severity: Severity::Medium,
        check: ProbeCheck::StatusOkWithContent("status"),
        remediation: Some("Secure Spring Boot Actuator endpoints with authentication"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },

    // --- Backup files ---
    Probe {
        path: "/backup.sql",
        title: "SQL Backup File Exposed",
        description: "A SQL backup file is accessible, potentially containing the entire database.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkWithContent("INSERT INTO"),
        remediation: Some("Remove backup files from the web root immediately"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/database.sql",
        title: "Database Dump Exposed",
        description: "A database dump file is accessible.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkWithContent("CREATE TABLE"),
        remediation: Some("Remove database dumps from the web root immediately"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/dump.sql",
        title: "Database Dump Exposed",
        description: "A database dump file is accessible.",
        severity: Severity::Critical,
        check: ProbeCheck::StatusOkWithContent("CREATE TABLE"),
        remediation: Some("Remove database dumps from the web root immediately"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },

    // --- API docs ---
    Probe {
        path: "/swagger-ui.html",
        title: "Swagger UI Exposed",
        description: "Swagger API documentation is publicly accessible, revealing all API endpoints.",
        severity: Severity::Low,
        check: ProbeCheck::StatusOk,
        remediation: Some("Restrict access to API documentation in production"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/api-docs",
        title: "API Documentation Exposed",
        description: "API documentation is publicly accessible.",
        severity: Severity::Low,
        check: ProbeCheck::StatusOk,
        remediation: Some("Restrict access to API documentation in production"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: Some(200),
    },
    Probe {
        path: "/graphql",
        title: "GraphQL Endpoint Found",
        description: "A GraphQL endpoint is accessible. Introspection may reveal the entire API schema.",
        severity: Severity::Low,
        check: ProbeCheck::AnyNon404,
        remediation: Some("Disable GraphQL introspection in production"),
        owasp: Some("A05:2021 Security Misconfiguration"),
        cwe: None,
    },
];

#[cfg(test)]
mod tests {
    /// Unit tests for directory/file discovery heuristics.
    use super::*;

    /// Verify `is_soft_404` detects a soft-404 page that says "not found" without referencing the path.
    #[test]
    fn test_is_soft_404_detected() {
        // Arrange
        let body = "<!DOCTYPE html><html><body><h1>Page Not Found</h1>\
                     <p>Sorry, the page you are looking for does not exist.</p></body></html>";
        let path = "/.env";

        // Act
        let result = is_soft_404(body, path);

        // Assert
        assert!(result, "body with 'not found' text and no path mention should be soft 404");
    }

    /// Verify `is_soft_404` lets through real content that does not contain 404 indicators.
    #[test]
    fn test_is_soft_404_real_content() {
        // Arrange
        let body = "<!DOCTYPE html><html><body><h1>Welcome to our site</h1>\
                     <p>This is the home page with plenty of real content for testing.</p></body></html>";
        let path = "/robots.txt";

        // Act
        let result = is_soft_404(body, path);

        // Assert
        assert!(!result, "real content without 404 indicators should not be soft 404");
    }

    /// Verify `is_soft_404` returns false when the body mentions the probed path (not a generic 404).
    #[test]
    fn test_is_soft_404_mentions_path() {
        // Arrange
        let body = "<!DOCTYPE html><html><body><h1>Not Found</h1>\
                     <p>The file /.env could not be found on this server.</p></body></html>";
        let path = "/.env";

        // Act
        let result = is_soft_404(body, path);

        // Assert
        assert!(!result, "body mentioning the probed path should not be treated as soft 404");
    }

    /// Verify `is_soft_404` returns false for an empty or very short body.
    #[test]
    fn test_is_soft_404_empty_body() {
        // Arrange
        let body = "";
        let path = "/test";

        // Act
        let result = is_soft_404(body, path);

        // Assert
        assert!(!result, "empty body should not be flagged as soft 404");
    }

    /// Verify `is_directory_listing` detects Apache-style directory listings.
    #[test]
    fn test_is_directory_listing_apache() {
        // Arrange
        let body = "<html><head><title>Index of /images</title></head>\
                     <body><h1>Index of /images</h1><hr><a href=\"../\">Parent Directory</a></body></html>";

        // Act
        let result = is_directory_listing(body);

        // Assert
        assert!(result, "Apache-style directory listing should be detected");
    }

    /// Verify `is_directory_listing` detects Nginx-style directory listings.
    #[test]
    fn test_is_directory_listing_nginx() {
        // Arrange
        let body = "<html><head><title>Index of /assets/</title></head>\
                     <body><h1>Index of /assets/</h1><hr><pre><a href=\"../\">../</a></pre><hr></body></html>";

        // Act
        let result = is_directory_listing(body);

        // Assert
        assert!(result, "Nginx-style directory listing should be detected");
    }

    /// Verify `is_directory_listing` detects IIS-style directory listings.
    #[test]
    fn test_is_directory_listing_iis() {
        // Arrange
        let body = "<html><body><h1>Directory Listing</h1>\
                     <a href=\"/\">[To Parent Directory]</a><br>file1.txt<br>file2.txt</body></html>";

        // Act
        let result = is_directory_listing(body);

        // Assert
        assert!(result, "IIS-style directory listing should be detected");
    }

    /// Verify `is_directory_listing` returns false for a normal HTML page.
    #[test]
    fn test_is_directory_listing_normal_page() {
        // Arrange
        let body = "<html><head><title>My Website</title></head>\
                     <body><h1>Welcome</h1><p>This is a normal page.</p></body></html>";

        // Act
        let result = is_directory_listing(body);

        // Assert
        assert!(!result, "normal page should not be detected as directory listing");
    }

    /// Verify the PROBES array is non-empty and each probe has valid fields.
    #[test]
    fn test_probes_array_integrity() {
        // Assert — PROBES has entries
        assert!(!PROBES.is_empty(), "PROBES array must not be empty");

        // Assert — every probe has a non-empty path, title, and description
        for (i, probe) in PROBES.iter().enumerate() {
            assert!(!probe.path.is_empty(), "probe [{i}] path must not be empty");
            assert!(
                probe.path.starts_with('/'),
                "probe [{i}] path '{}' must start with '/'",
                probe.path
            );
            assert!(!probe.title.is_empty(), "probe [{i}] title must not be empty");
            assert!(!probe.description.is_empty(), "probe [{i}] description must not be empty");
        }
    }
}
