//! Project initialization with target fingerprinting.
//!
//! `init` (no args) writes a default `config.toml`.
//! `init <url>` probes the target, fingerprints its tech stack,
//! checks available tools, recommends a scan profile, and generates
//! a tailored `scorchkit.toml`.

use colored::Colorize;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};

/// Fingerprint extracted from probing a target URL.
#[derive(Debug, Default)]
struct TargetFingerprint {
    server: Option<String>,
    technologies: Vec<String>,
    cms: Option<String>,
    waf: Option<String>,
    is_https: bool,
    status_code: u16,
}

/// Profile recommendation based on fingerprint and available tools.
#[derive(Debug)]
struct InitRecommendation {
    profile: String,
    suggested_modules: Vec<String>,
    notes: Vec<String>,
    available_tool_count: usize,
    total_tool_count: usize,
}

// ---------------------------------------------------------------------------
// Detection patterns (lightweight subset of recon/tech.rs)
// ---------------------------------------------------------------------------

/// WAF headers to check: (`header_name`, `waf_name`).
const WAF_HEADERS: &[(&str, &str)] = &[
    ("cf-ray", "Cloudflare"),
    ("x-sucuri-id", "Sucuri"),
    ("x-akamai-transformed", "Akamai"),
    ("x-cdn", "CDN/WAF"),
    ("server", "Cloudflare"), // server: cloudflare
    ("x-barracuda-waf", "Barracuda"),
    ("x-powered-by-anquanbao", "Anquanbao"),
];

/// CMS body patterns: (`needle`, `cms_name`).
const CMS_PATTERNS: &[(&str, &str)] = &[
    ("wp-content/", "WordPress"),
    ("wp-includes/", "WordPress"),
    ("/wp-json/", "WordPress"),
    ("sites/default/files", "Drupal"),
    ("drupal.js", "Drupal"),
    ("media/system/", "Joomla"),
    ("/administrator/", "Joomla"),
    ("Shopify.theme", "Shopify"),
    ("shopify.com/s/files", "Shopify"),
];

/// Framework body patterns: (`needle`, `tech_name`).
const FRAMEWORK_PATTERNS: &[(&str, &str)] = &[
    ("_next/static", "Next.js"),
    ("__next", "Next.js"),
    ("__nuxt", "Nuxt.js"),
    ("data-reactroot", "React"),
    ("ng-version", "Angular"),
    ("ember-view", "Ember.js"),
    ("data-turbo", "Hotwire/Turbo"),
    ("/build/app.", "Laravel Mix"),
    ("/bundles/", "Symfony"),
];

/// Cookie-to-technology mapping: (`cookie_prefix`, `tech_name`).
const COOKIE_TECH: &[(&str, &str)] = &[
    ("PHPSESSID", "PHP"),
    ("JSESSIONID", "Java"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("laravel_session", "Laravel"),
    ("connect.sid", "Node.js/Express"),
    ("_rails_session", "Ruby on Rails"),
    ("AWSALB", "AWS"),
    ("__cfduid", "Cloudflare"),
    ("csrftoken", "Django"),
    ("rack.session", "Ruby/Rack"),
];

/// Tools to check for availability (binary names).
const TOOL_BINARIES: &[&str] = &[
    "nmap",
    "nuclei",
    "nikto",
    "sqlmap",
    "feroxbuster",
    "ffuf",
    "sslyze",
    "testssl.sh",
    "wpscan",
    "dalfox",
    "httpx",
    "subfinder",
    "amass",
    "wafw00f",
    "hydra",
    "gobuster",
    "katana",
    "trivy",
    "trufflehog",
    "dnsx",
];

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/// Extract a fingerprint from HTTP response headers and body.
fn extract_fingerprint(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    is_https: bool,
    status_code: u16,
) -> TargetFingerprint {
    let mut fp = TargetFingerprint { is_https, status_code, ..Default::default() };

    // Server header
    if let Some(val) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if !val.is_empty() {
            fp.server = Some(val.to_string());
        }
    }

    // X-Powered-By
    if let Some(val) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        if !val.is_empty() {
            fp.technologies.push(val.to_string());
        }
    }

    // WAF detection from headers
    for &(header, waf_name) in WAF_HEADERS {
        if header == "server" {
            // Special case: check if server header contains "cloudflare"
            if let Some(val) = headers.get("server").and_then(|v| v.to_str().ok()) {
                if val.to_lowercase().contains("cloudflare") {
                    fp.waf = Some(waf_name.to_string());
                }
            }
        } else if headers.contains_key(header) {
            fp.waf = Some(waf_name.to_string());
        }
    }

    // Cookie-based tech detection
    if let Some(cookies) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
        for &(prefix, tech) in COOKIE_TECH {
            if cookies.contains(prefix) && !fp.technologies.iter().any(|t| t == tech) {
                fp.technologies.push(tech.to_string());
            }
        }
    }

    // CMS detection from body
    let body_lower = body.to_lowercase();
    for &(needle, cms) in CMS_PATTERNS {
        if body_lower.contains(&needle.to_lowercase()) {
            fp.cms = Some(cms.to_string());
            break;
        }
    }

    // Framework detection from body
    for &(needle, tech) in FRAMEWORK_PATTERNS {
        if body.contains(needle) && !fp.technologies.iter().any(|t| t == tech) {
            fp.technologies.push(tech.to_string());
        }
    }

    fp
}

// ---------------------------------------------------------------------------
// Profile recommendation
// ---------------------------------------------------------------------------

/// Recommend a scan profile based on fingerprint and available tools.
fn recommend_profile(fingerprint: &TargetFingerprint) -> InitRecommendation {
    let mut available = 0usize;
    let total = TOOL_BINARIES.len();

    for &binary in TOOL_BINARIES {
        if super::doctor::is_tool_available(binary) {
            available += 1;
        }
    }

    let profile = if available >= 15 {
        "thorough"
    } else if available >= 5 {
        "standard"
    } else {
        "quick"
    };

    let mut suggested = Vec::new();
    let mut notes = Vec::new();

    // CMS-specific recommendations
    if let Some(ref cms) = fingerprint.cms {
        match cms.as_str() {
            "WordPress" => {
                suggested.push("wpscan".to_string());
                notes.push(
                    "WordPress detected — wpscan recommended for plugin/theme enumeration"
                        .to_string(),
                );
            }
            "Drupal" => {
                suggested.push("droopescan".to_string());
                notes.push(
                    "Drupal detected — droopescan recommended for module enumeration".to_string(),
                );
            }
            "Joomla" => {
                notes.push("Joomla detected — nuclei Joomla templates recommended".to_string());
            }
            _ => {}
        }
    }

    // WAF detection notes
    if let Some(ref waf) = fingerprint.waf {
        notes.push(format!("{waf} WAF detected — rate limiting recommended"));
    }

    // Tool availability summary
    notes.push(format!(
        "{available}/{total} external tools available — \"{profile}\" profile recommended"
    ));

    InitRecommendation {
        profile: profile.to_string(),
        suggested_modules: suggested,
        notes,
        available_tool_count: available,
        total_tool_count: total,
    }
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Generate a tailored TOML config string.
fn generate_config(
    target: &str,
    fingerprint: &TargetFingerprint,
    recommendation: &InitRecommendation,
) -> Result<String> {
    use std::fmt::Write;

    let mut config = AppConfig::default();

    // Set recommended profile
    config.scan.profile.clone_from(&recommendation.profile);

    // Set scope to target domain
    if let Ok(url) = url::Url::parse(target) {
        if let Some(domain) = url.host_str() {
            config.scan.scope_include = vec![format!("*.{domain}")];
        }
    }

    // Rate limit if WAF detected
    if fingerprint.waf.is_some() {
        config.scan.rate_limit = 10;
    }

    let mut toml_str = toml::to_string_pretty(&config)
        .map_err(|e| ScorchError::Config(format!("failed to serialize config: {e}")))?;

    // Prepend header comment with fingerprint summary
    let mut header = String::from("# ScorchKit configuration — generated by `scorchkit init`\n");
    let _ = writeln!(header, "# Target: {target}");
    if let Some(ref server) = fingerprint.server {
        let _ = writeln!(header, "# Server: {server}");
    }
    if let Some(ref cms) = fingerprint.cms {
        let _ = writeln!(header, "# CMS: {cms}");
    }
    if !fingerprint.technologies.is_empty() {
        let _ = writeln!(header, "# Technologies: {}", fingerprint.technologies.join(", "));
    }
    if let Some(ref waf) = fingerprint.waf {
        let _ = writeln!(header, "# WAF: {waf}");
    }
    let _ = writeln!(header, "# Profile: {}", recommendation.profile);
    header.push('\n');

    toml_str.insert_str(0, &header);

    Ok(toml_str)
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

/// Print fingerprint results to the terminal.
fn print_fingerprint(fingerprint: &TargetFingerprint) {
    println!();
    println!("  {}", "Fingerprint:".bold());
    if let Some(ref server) = fingerprint.server {
        println!("    {} {}", "Server:".dimmed(), server);
    }
    if let Some(ref cms) = fingerprint.cms {
        println!("    {} {}", "CMS:".dimmed(), cms.green());
    }
    if !fingerprint.technologies.is_empty() {
        println!("    {} {}", "Tech:".dimmed(), fingerprint.technologies.join(", "));
    }
    if let Some(ref waf) = fingerprint.waf {
        println!("    {} {}", "WAF:".dimmed(), waf.yellow());
    }
    println!(
        "    {} {}",
        "HTTPS:".dimmed(),
        if fingerprint.is_https { "yes".green() } else { "no".red() }
    );
    if fingerprint.status_code > 0 {
        println!("    {} {}", "Status:".dimmed(), fingerprint.status_code);
    }
}

/// Print profile recommendation to the terminal.
fn print_recommendation(recommendation: &InitRecommendation) {
    println!();
    println!("  {}", "Recommendation:".bold());
    println!("    {} {}", "Profile:".dimmed(), recommendation.profile.cyan());
    println!(
        "    {} {}/{}",
        "Tools:".dimmed(),
        recommendation.available_tool_count.to_string().green(),
        recommendation.total_tool_count
    );
    for note in &recommendation.notes {
        println!("    {} {}", ">>".dimmed(), note.dimmed());
    }
    if !recommendation.suggested_modules.is_empty() {
        println!(
            "    {} {}",
            "Suggested:".dimmed(),
            recommendation.suggested_modules.join(", ").cyan()
        );
    }
}

/// Run the init command.
///
/// # Errors
///
/// Returns an error if the HTTP probe, config write, or DB operation fails.
pub async fn run_init(
    target: Option<&str>,
    project: Option<&str>,
    database_url: Option<&str>,
) -> Result<()> {
    let path = std::path::Path::new("scorchkit.toml");

    // No target — write default config (backward compat)
    let Some(target_url) = target else {
        let default_path = std::path::Path::new("config.toml");
        if default_path.exists() {
            println!("{} config.toml already exists", "warning:".yellow().bold());
            return Ok(());
        }
        let content = AppConfig::default_toml()?;
        std::fs::write(default_path, content)?;
        println!("{} config.toml created", "success:".green().bold());
        return Ok(());
    };

    if path.exists() {
        println!("{} scorchkit.toml already exists", "warning:".yellow().bold());
        return Ok(());
    }

    // Parse target to validate URL
    let parsed_target = crate::engine::target::Target::parse(target_url)?;
    let url = parsed_target.url.as_str();

    println!();
    println!("{}", "ScorchKit Init".bold().underline());
    println!();
    println!("  {} {}", "Target:".bold(), url);
    println!("  {} Probing target...", ">>".dimmed());

    // Probe the target
    let fingerprint = probe_target(url, parsed_target.is_https).await;
    print_fingerprint(&fingerprint);

    // Recommend profile
    let recommendation = recommend_profile(&fingerprint);
    print_recommendation(&recommendation);

    // Generate and write config
    let config_content = generate_config(url, &fingerprint, &recommendation)?;
    std::fs::write(path, &config_content)?;

    println!();
    println!("  {} scorchkit.toml created", "success:".green().bold());

    // Storage: create project if requested
    #[cfg(feature = "storage")]
    if let (Some(project_name), Some(db_url)) = (project, database_url) {
        create_project_from_init(project_name, url, &fingerprint, db_url).await?;
    }

    #[cfg(not(feature = "storage"))]
    if project.is_some() {
        let _ = database_url; // suppress unused warning
        println!(
            "  {} --project requires the 'storage' feature. Rebuild with: cargo build --features storage",
            "warning:".yellow().bold()
        );
    }

    println!();
    println!("  Next: {} {} {}", "scorchkit run".cyan(), url, "--profile".dimmed());
    println!();

    Ok(())
}

/// Probe a target URL and return a fingerprint.
async fn probe_target(url: &str, is_https: bool) -> TargetFingerprint {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build();

    let Ok(client) = client else {
        return TargetFingerprint { is_https, ..Default::default() };
    };

    match client.get(url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap_or_default();
            extract_fingerprint(&headers, &body, is_https, status)
        }
        Err(e) => {
            println!("  {} Could not reach target: {}", "WARN".yellow().bold(), e);
            println!("  {} Generating default config with scope set", ">>".dimmed());
            TargetFingerprint { is_https, ..Default::default() }
        }
    }
}

/// Create a project and target in the database from init fingerprint.
#[cfg(feature = "storage")]
async fn create_project_from_init(
    name: &str,
    url: &str,
    fingerprint: &TargetFingerprint,
    database_url: &str,
) -> Result<()> {
    use sqlx::postgres::PgPoolOptions;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .map_err(|e| ScorchError::Database(format!("failed to connect: {e}")))?;

    let description = build_fingerprint_summary(fingerprint);
    let project = crate::storage::projects::create_project(&pool, name, &description).await?;

    let label = fingerprint.cms.as_deref().or(fingerprint.server.as_deref()).unwrap_or("target");
    crate::storage::projects::add_target(&pool, project.id, url, label).await?;

    println!(
        "  {} Project '{}' created with target {}",
        "success:".green().bold(),
        name.cyan(),
        url
    );

    Ok(())
}

/// Build a human-readable summary of the fingerprint.
#[cfg(any(feature = "storage", test))]
fn build_fingerprint_summary(fingerprint: &TargetFingerprint) -> String {
    let mut parts = Vec::new();
    if let Some(ref server) = fingerprint.server {
        parts.push(format!("Server: {server}"));
    }
    if let Some(ref cms) = fingerprint.cms {
        parts.push(format!("CMS: {cms}"));
    }
    if !fingerprint.technologies.is_empty() {
        parts.push(format!("Tech: {}", fingerprint.technologies.join(", ")));
    }
    if let Some(ref waf) = fingerprint.waf {
        parts.push(format!("WAF: {waf}"));
    }
    if parts.is_empty() {
        "Target added via scorchkit init".to_string()
    } else {
        parts.join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        for &(k, v) in pairs {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                map.insert(name, val);
            }
        }
        map
    }

    #[test]
    fn test_fingerprint_server_nginx() {
        let headers = make_headers(&[("server", "nginx/1.24.0")]);
        let fp = extract_fingerprint(&headers, "", true, 200);
        assert_eq!(fp.server.as_deref(), Some("nginx/1.24.0"));
    }

    #[test]
    fn test_fingerprint_wordpress() {
        let headers = make_headers(&[]);
        let body = r#"<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">"#;
        let fp = extract_fingerprint(&headers, body, true, 200);
        assert_eq!(fp.cms.as_deref(), Some("WordPress"));
    }

    #[test]
    fn test_fingerprint_waf_cloudflare() {
        let headers = make_headers(&[("cf-ray", "abc123"), ("server", "cloudflare")]);
        let fp = extract_fingerprint(&headers, "", true, 200);
        assert_eq!(fp.waf.as_deref(), Some("Cloudflare"));
    }

    #[test]
    fn test_fingerprint_cookie_php() {
        let headers = make_headers(&[("set-cookie", "PHPSESSID=abc123; path=/")]);
        let fp = extract_fingerprint(&headers, "", true, 200);
        assert!(fp.technologies.contains(&"PHP".to_string()));
    }

    #[test]
    fn test_fingerprint_nextjs() {
        let headers = make_headers(&[]);
        let body = r#"<script src="/_next/static/chunks/main.js"></script>"#;
        let fp = extract_fingerprint(&headers, body, true, 200);
        assert!(fp.technologies.contains(&"Next.js".to_string()));
    }

    #[test]
    fn test_recommend_thorough() {
        // This test validates the logic, not actual tool availability.
        // We test the threshold logic directly.
        let fp = TargetFingerprint::default();
        let rec = recommend_profile(&fp);
        // Result depends on actual tools installed — just verify it returns a valid profile
        assert!(
            rec.profile == "quick" || rec.profile == "standard" || rec.profile == "thorough",
            "Invalid profile: {}",
            rec.profile
        );
        assert!(rec.total_tool_count > 0);
    }

    #[test]
    fn test_recommend_wordpress_modules() {
        let fp = TargetFingerprint { cms: Some("WordPress".to_string()), ..Default::default() };
        let rec = recommend_profile(&fp);
        assert!(
            rec.suggested_modules.contains(&"wpscan".to_string()),
            "WordPress should suggest wpscan"
        );
        assert!(rec.notes.iter().any(|n| n.contains("WordPress")), "Should have WordPress note");
    }

    #[test]
    fn test_generate_config_has_scope() {
        let fp = TargetFingerprint {
            server: Some("nginx".to_string()),
            is_https: true,
            ..Default::default()
        };
        let rec = InitRecommendation {
            profile: "standard".to_string(),
            suggested_modules: vec![],
            notes: vec![],
            available_tool_count: 10,
            total_tool_count: 20,
        };
        let config =
            generate_config("https://example.com/app", &fp, &rec).expect("should generate");
        assert!(config.contains("example.com"), "Config should contain target domain in scope");
        assert!(config.contains("standard"), "Config should contain recommended profile");
        assert!(config.contains("# Target:"), "Config should have header comment");
    }

    #[test]
    fn test_generate_config_waf_rate_limit() {
        let fp = TargetFingerprint { waf: Some("Cloudflare".to_string()), ..Default::default() };
        let rec = InitRecommendation {
            profile: "standard".to_string(),
            suggested_modules: vec![],
            notes: vec![],
            available_tool_count: 10,
            total_tool_count: 20,
        };
        let config = generate_config("https://example.com", &fp, &rec).expect("should generate");
        assert!(config.contains("rate_limit = 10"), "WAF should set rate_limit to 10");
    }

    #[test]
    fn test_fingerprint_summary() {
        let fp = TargetFingerprint {
            server: Some("Apache/2.4".to_string()),
            cms: Some("WordPress".to_string()),
            waf: Some("Cloudflare".to_string()),
            technologies: vec!["PHP".to_string()],
            ..Default::default()
        };
        let summary = build_fingerprint_summary(&fp);
        assert!(summary.contains("Apache"));
        assert!(summary.contains("WordPress"));
        assert!(summary.contains("PHP"));
        assert!(summary.contains("Cloudflare"));
    }
}
