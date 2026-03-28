use async_trait::async_trait;
use scraper::{Html, Selector};
use url::Url;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects open redirect vulnerabilities.
#[derive(Debug)]
pub struct RedirectModule;

#[async_trait]
impl ScanModule for RedirectModule {
    fn name(&self) -> &'static str {
        "Open Redirect Detection"
    }
    fn id(&self) -> &'static str {
        "redirect"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect open redirect vulnerabilities in URL parameters"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Build a non-following client to see redirects
        let no_redirect_client = reqwest::Client::builder()
            .user_agent(&ctx.config.scan.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ScorchError::Config(format!("client build error: {e}")))?;

        // 1. Test the target URL's own parameters
        test_url_params_redirect(&no_redirect_client, url, &mut findings).await?;

        // 2. Spider for redirect-like parameters
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;
        let body = response.text().await.unwrap_or_default();
        let links = extract_redirect_links(&body, &ctx.target.url);

        for link in &links {
            test_url_params_redirect(&no_redirect_client, link, &mut findings).await?;
        }

        Ok(findings)
    }
}

async fn test_url_params_redirect(
    client: &reqwest::Client,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    for (param_name, _) in &params {
        let lower = param_name.to_lowercase();
        if !REDIRECT_PARAM_NAMES.iter().any(|p| lower.contains(p)) {
            continue;
        }

        // Inject an external URL
        let evil_url = "https://evil-attacker.com/pwned";
        let mut test_url = parsed.clone();
        {
            let mut q = test_url.query_pairs_mut();
            q.clear();
            for (k, v) in &params {
                if k == param_name {
                    q.append_pair(k, evil_url);
                } else {
                    q.append_pair(k, v);
                }
            }
        }

        if let Ok(resp) = client.get(test_url.as_str()).send().await {
            let status = resp.status();
            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location") {
                    let loc = location.to_str().unwrap_or("");
                    if loc.contains("evil-attacker.com") {
                        findings.push(
                            Finding::new("redirect", Severity::Medium, format!("Open Redirect: {param_name}"), format!("The parameter '{param_name}' redirects to arbitrary external URLs."), url_str)
                                .with_evidence(format!("Parameter: {param_name} | Payload: {evil_url} | Location: {loc}"))
                                .with_remediation("Validate redirect destinations against an allowlist of trusted domains")
                                .with_owasp("A01:2021 Broken Access Control")
                                .with_cwe(601),
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

fn extract_redirect_links(body: &str, base_url: &Url) -> Vec<String> {
    let document = Html::parse_document(body);
    let mut links = Vec::new();
    let Ok(selector) = Selector::parse("a[href]") else { return links };

    for el in document.select(&selector) {
        if let Some(href) = el.value().attr("href") {
            if let Ok(resolved) = base_url.join(href) {
                if resolved.host() == base_url.host() {
                    let has_redirect_param = resolved.query_pairs().any(|(k, _)| {
                        REDIRECT_PARAM_NAMES.iter().any(|p| k.to_lowercase().contains(p))
                    });
                    if has_redirect_param {
                        links.push(resolved.to_string());
                    }
                }
            }
        }
    }

    links.truncate(10);
    links
}

const REDIRECT_PARAM_NAMES: &[&str] = &[
    "url",
    "redirect",
    "return",
    "next",
    "dest",
    "destination",
    "rurl",
    "return_url",
    "redirect_uri",
    "redirect_url",
    "continue",
    "forward",
    "goto",
    "target",
    "redir",
    "returnto",
    "return_to",
];
