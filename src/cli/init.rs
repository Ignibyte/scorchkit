//! Project initialization with a fail-closed engagement bootstrap.
//!
//! `init` (no args) writes a default `config.toml`.
//! `init <url>` validates the target, resolves and pins its current addresses,
//! checks available tools, and generates a quick-profile `scorchkit.toml`.
//! It does not send an HTTP request to the target.

use colored::Colorize;

use crate::config::AppConfig;
use crate::engine::error::{Result, ScorchError};
use crate::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy, PolicyTarget};
use crate::engine::scope::ScopeRule;
use crate::engine::target::Target;
use crate::report::terminal::escape_terminal_text;

/// Fingerprint extracted from probing a target URL.
#[derive(Debug, Default)]
struct TargetFingerprint {
    server: Option<String>,
    technologies: Vec<String>,
    cms: Option<String>,
    waf: Option<String>,
    #[cfg(test)]
    is_https: bool,
    #[cfg(test)]
    status_code: u16,
}

/// Profile recommendation based on fingerprint and available tools.
#[derive(Debug, Default)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
    "trufflehog",
    "dnsx",
];

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/// Extract a fingerprint from HTTP response headers and body.
#[cfg(test)]
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

fn recommend_profile_with(
    fingerprint: &TargetFingerprint,
    is_available: impl Fn(&str) -> bool,
) -> InitRecommendation {
    let available = TOOL_BINARIES.iter().filter(|binary| is_available(binary)).count();
    let total = TOOL_BINARIES.len();

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

fn bootstrap_recommendation(fingerprint: &TargetFingerprint) -> InitRecommendation {
    let mut recommendation = recommend_profile_with(fingerprint, super::doctor::is_tool_available);
    recommendation.profile = "quick".to_string();
    recommendation.notes.retain(|note| !note.contains("profile recommended"));
    recommendation.notes.push(format!(
        "{}/{} external tools available; broader profiles require explicit effect grants",
        recommendation.available_tool_count, recommendation.total_tool_count
    ));
    recommendation.notes.push("Bootstrap grants only passive and active-safe effects".to_string());
    recommendation
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Generate a tailored TOML config string.
fn generate_config(
    target: &str,
    fingerprint: &TargetFingerprint,
    recommendation: &InitRecommendation,
    resolved_addresses: &[std::net::IpAddr],
) -> Result<String> {
    use std::fmt::Write;

    let mut config = AppConfig::default();

    // Set recommended profile
    config.scan.profile.clone_from(&recommendation.profile);

    // Bind the generated configuration to the exact host and DNS answers
    // reviewed during bootstrap. Later DNS changes fail closed until the
    // operator regenerates or explicitly edits the engagement.
    if let Ok(url) = url::Url::parse(target) {
        if let Some(host) = url.host_str() {
            config.scan.scope_include = vec![host.to_string()];
            let mut policy = EngagementPolicy::default()
                .allow_scope(ScopeRule::parse(host).ok_or_else(|| {
                    ScorchError::Config(format!("cannot build scope rule for '{host}'"))
                })?)
                .allow_capability(Capability::DastScan)
                .allow_capability(Capability::ExternalTool)
                .allow_effect(EffectClass::Passive)
                .allow_effect(EffectClass::ActiveSafe);
            for address in resolved_addresses {
                policy = policy.allow_scope(ScopeRule::parse(&address.to_string()).ok_or_else(
                    || ScorchError::Config(format!("cannot build scope rule for '{address}'")),
                )?);
            }
            config.engagement = Some(Engagement::new(format!("quick scan: {host}"), policy));
        }
    }

    // Rate limit if WAF detected
    if fingerprint.waf.is_some() {
        config.scan.rate_limit = 10;
    }

    let mut toml_str = toml::to_string_pretty(&config)
        .map_err(|e| ScorchError::Config(format!("failed to serialize config: {e}")))?;

    // Prepend a human-readable bootstrap summary.
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

/// Render a profile recommendation for the terminal.
fn render_recommendation(recommendation: &InitRecommendation) -> String {
    use std::fmt::Write;

    let mut output = String::new();
    let tools =
        format!("{}/{}", recommendation.available_tool_count, recommendation.total_tool_count)
            .green();
    let _ = writeln!(output);
    let _ = writeln!(output, "  {}", "Recommendation:".bold());
    let _ = writeln!(output, "    {} {}", "Profile:".dimmed(), recommendation.profile.cyan());
    let _ = writeln!(output, "    {} {tools}", "Tools:".dimmed());
    for note in &recommendation.notes {
        let _ = writeln!(output, "    {} {}", ">>".dimmed(), note.dimmed());
    }
    if !recommendation.suggested_modules.is_empty() {
        let _ = writeln!(
            output,
            "    {} {}",
            "Suggested:".dimmed(),
            recommendation.suggested_modules.join(", ").cyan()
        );
    }
    output
}

/// Run the init command.
///
/// # Errors
///
/// Returns an error if target resolution, config writing, or database setup fails.
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
    let parsed_target = Target::parse(target_url)?;
    let url = parsed_target.url.as_str();

    println!();
    println!("{}", "ScorchKit Init".bold().underline());
    println!();
    println!("  {} {}", "Target:".bold(), escape_terminal_text(url));
    println!("  {} Resolving and pinning authorized addresses...", ">>".dimmed());

    let resolved_addresses = resolve_target_addresses(&parsed_target).await?;
    let fingerprint = TargetFingerprint::default();

    // Bootstrap never grants intrusive, credential, or exploit effects.
    let recommendation = bootstrap_recommendation(&fingerprint);
    print!("{}", render_recommendation(&recommendation));

    // Generate and write config
    let config_content = generate_config(url, &fingerprint, &recommendation, &resolved_addresses)?;
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
    println!(
        "  Next: {} {} {}",
        "scorchkit run".cyan(),
        escape_terminal_text(url),
        "--profile quick".dimmed()
    );
    println!();

    Ok(())
}

async fn resolve_target_addresses(target: &Target) -> Result<Vec<std::net::IpAddr>> {
    let host = target
        .domain
        .as_deref()
        .ok_or_else(|| ScorchError::Config("target has no resolvable host".to_string()))?;
    let bootstrap = Engagement::new(
        "scorchkit init bootstrap",
        EngagementPolicy::default()
            .allow_scope(ScopeRule::parse(host).ok_or_else(|| {
                ScorchError::Config(format!("cannot build bootstrap scope for '{host}'"))
            })?)
            .allow_capability(Capability::DastScan)
            .allow_effect(EffectClass::ActiveSafe),
    );
    bootstrap
        .authorize(
            PolicyTarget::Web(target.url.clone()),
            Capability::DastScan,
            EffectClass::ActiveSafe,
        )
        .require()?;

    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![address]);
    }

    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, target.port)),
    )
    .await
    .map_err(|_| ScorchError::Config(format!("DNS resolution timed out for '{host}'")))?
    .map_err(|error| ScorchError::Config(format!("DNS resolution failed for '{host}': {error}")))?;
    let addresses: std::collections::BTreeSet<_> = lookup.map(|socket| socket.ip()).collect();
    if addresses.is_empty() {
        return Err(ScorchError::Config(format!("DNS returned no addresses for '{host}'")));
    }
    Ok(addresses.into_iter().collect())
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
        escape_terminal_text(name).cyan(),
        escape_terminal_text(url)
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

    fn recommend_with_tool_count(
        fingerprint: &TargetFingerprint,
        available: usize,
    ) -> InitRecommendation {
        let enabled = &TOOL_BINARIES[..available];
        recommend_profile_with(fingerprint, |binary| enabled.contains(&binary))
    }

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
        assert!(fp.is_https);
        assert_eq!(fp.status_code, 200);
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
    fn recommendation_profile_thresholds_are_exact() {
        let fp = TargetFingerprint::default();
        for (available, expected) in [
            (0, "quick"),
            (4, "quick"),
            (5, "standard"),
            (14, "standard"),
            (15, "thorough"),
            (TOOL_BINARIES.len(), "thorough"),
        ] {
            let recommendation = recommend_with_tool_count(&fp, available);
            assert_eq!(recommendation.profile, expected, "available tools: {available}");
            assert_eq!(recommendation.available_tool_count, available);
            assert_eq!(recommendation.total_tool_count, TOOL_BINARIES.len());
        }
    }

    #[test]
    fn recommendation_preserves_cms_and_waf_guidance() {
        let cases = [
            ("WordPress", Some("wpscan"), "WordPress detected"),
            ("Drupal", Some("droopescan"), "Drupal detected"),
            ("Joomla", None, "Joomla detected"),
        ];
        for (cms, module, note) in cases {
            let fp = TargetFingerprint { cms: Some(cms.to_string()), ..Default::default() };
            let recommendation = recommend_with_tool_count(&fp, 0);
            assert_eq!(recommendation.suggested_modules.first().map(String::as_str), module);
            assert!(recommendation.notes.iter().any(|item| item.contains(note)));
        }

        let fp = TargetFingerprint { waf: Some("Cloudflare".to_string()), ..Default::default() };
        let recommendation = recommend_with_tool_count(&fp, 0);
        assert!(recommendation
            .notes
            .iter()
            .any(|note| note == "Cloudflare WAF detected — rate limiting recommended"));
    }

    #[test]
    fn test_generate_config_has_scope() {
        let fp = TargetFingerprint {
            server: Some("nginx".to_string()),
            cms: Some("Drupal".to_string()),
            technologies: vec!["Rust".to_string(), "Axum".to_string()],
            waf: Some("Cloudflare".to_string()),
            is_https: true,
            ..Default::default()
        };
        let rec = InitRecommendation {
            profile: "quick".to_string(),
            suggested_modules: vec![],
            notes: vec![],
            available_tool_count: 10,
            total_tool_count: 19,
        };
        let config = generate_config(
            "https://example.com/app",
            &fp,
            &rec,
            &["192.0.2.10".parse().expect("fixture IP")],
        )
        .expect("should generate");
        assert!(config.contains("example.com"), "Config should contain target domain in scope");
        assert!(config.contains("192.0.2.10"), "Config should pin resolved addresses");
        let parsed: AppConfig = toml::from_str(&config).expect("generated config must parse");
        let engagement = parsed.engagement.expect("generated config must contain engagement");
        assert!(engagement.policy.effects.contains(&EffectClass::ActiveSafe));
        assert!(!engagement.policy.effects.contains(&EffectClass::Intrusive));
        assert!(config.contains("quick"), "Config should contain the safe bootstrap profile");
        assert!(config.contains("# Target:"), "Config should have header comment");
        for expected in
            ["# Server: nginx", "# CMS: Drupal", "# Technologies: Rust, Axum", "# WAF: Cloudflare"]
        {
            assert!(config.contains(expected), "generated config omitted {expected:?}");
        }
    }

    #[test]
    fn generated_config_omits_empty_fingerprint_sections() {
        let recommendation = InitRecommendation {
            profile: "quick".to_string(),
            suggested_modules: Vec::new(),
            notes: Vec::new(),
            available_tool_count: 0,
            total_tool_count: TOOL_BINARIES.len(),
        };
        let config = generate_config(
            "https://example.com",
            &TargetFingerprint::default(),
            &recommendation,
            &[],
        )
        .expect("generate empty fingerprint config");
        for absent in ["# Server:", "# CMS:", "# Technologies:", "# WAF:"] {
            assert!(!config.contains(absent), "empty config included {absent:?}");
        }
    }

    #[test]
    fn recommendation_rendering_distinguishes_full_and_empty_sections() {
        let full = InitRecommendation {
            profile: "standard".to_string(),
            suggested_modules: vec!["wpscan".to_string(), "nuclei".to_string()],
            notes: vec!["first note".to_string(), "second note".to_string()],
            available_tool_count: 7,
            total_tool_count: 19,
        };
        let rendered = render_recommendation(&full);
        for expected in [
            "Recommendation:",
            "Profile:",
            "standard",
            "7/19",
            "first note",
            "second note",
            "Suggested:",
            "wpscan, nuclei",
        ] {
            assert!(rendered.contains(expected), "recommendation omitted {expected:?}");
        }

        let empty = InitRecommendation {
            profile: "quick".to_string(),
            suggested_modules: Vec::new(),
            notes: Vec::new(),
            available_tool_count: 0,
            total_tool_count: 19,
        };
        let rendered = render_recommendation(&empty);
        assert!(rendered.contains("quick"));
        assert!(rendered.contains("0/19"));
        assert!(!rendered.contains("Suggested:"));
        assert!(!rendered.contains(">>"));
    }

    #[test]
    fn test_generate_config_waf_rate_limit() {
        let fp = TargetFingerprint { waf: Some("Cloudflare".to_string()), ..Default::default() };
        let rec = InitRecommendation {
            profile: "quick".to_string(),
            suggested_modules: vec![],
            notes: vec![],
            available_tool_count: 10,
            total_tool_count: 19,
        };
        let config =
            generate_config("https://example.com", &fp, &rec, &[]).expect("should generate");
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

    #[test]
    fn bootstrap_recommendation_is_quick_and_names_its_effect_boundary() {
        let recommendation = bootstrap_recommendation(&TargetFingerprint::default());

        assert_eq!(recommendation.profile, "quick");
        assert!(recommendation.notes.iter().all(|note| !note.contains("profile recommended")));
        assert!(recommendation
            .notes
            .iter()
            .any(|note| note.contains("broader profiles require explicit effect grants")));
        assert!(recommendation
            .notes
            .iter()
            .any(|note| note == "Bootstrap grants only passive and active-safe effects"));
    }

    #[tokio::test]
    async fn address_bootstrap_preserves_an_authorized_literal_address() {
        let target = Target::parse("http://127.0.0.1:4567").expect("parse loopback target");
        assert_eq!(
            resolve_target_addresses(&target).await.expect("resolve literal target"),
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
        );
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn project_bootstrap_persists_the_project_and_registered_target() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else { return };
        let pool = crate::storage::connect(&database_url).await.expect("connect database");
        crate::storage::migrate::run_migrations(&pool).await.expect("migrate database");
        let name = format!("cli-init-project-{}", uuid::Uuid::new_v4());
        let url = "http://127.0.0.1:4567/";

        let result =
            create_project_from_init(&name, url, &TargetFingerprint::default(), &database_url)
                .await;
        let project = crate::storage::projects::get_project_by_name(&pool, &name)
            .await
            .expect("query project");
        let targets = if let Some(project) = &project {
            crate::storage::projects::list_targets(&pool, project.id).await.expect("query targets")
        } else {
            Vec::new()
        };
        if let Some(project) = project {
            crate::storage::projects::delete_project(&pool, project.id)
                .await
                .expect("delete fixture project");
        }

        assert!(result.is_ok(), "project bootstrap failed: {result:?}");
        assert_eq!(targets.len(), 1, "bootstrap must register exactly one target");
        assert_eq!(targets[0].url, url);
    }
}
