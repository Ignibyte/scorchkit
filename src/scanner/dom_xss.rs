//! DOM-based XSS scanner module.
//!
//! Performs static analysis of JavaScript in HTML responses to identify
//! dangerous source-to-sink data flows that could enable DOM-based
//! cross-site scripting. This is pattern-matching based and does not
//! execute JavaScript — it identifies high-risk patterns for manual review.

use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects DOM-based XSS via static source/sink analysis of JavaScript.
#[derive(Debug)]
pub struct DomXssModule;

#[async_trait]
impl ScanModule for DomXssModule {
    fn name(&self) -> &'static str {
        "DOM XSS Detection"
    }

    fn id(&self) -> &'static str {
        "dom_xss"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect DOM-based XSS via static JavaScript source/sink analysis"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let body = response.text().await.unwrap_or_default();

        // Analyze inline scripts and HTML for source/sink patterns
        let sources_found = detect_sources(&body);
        let sinks_found = detect_sinks(&body);

        // If both sources and sinks are present, flag potential DOM XSS
        if !sources_found.is_empty() && !sinks_found.is_empty() {
            findings.push(
                Finding::new(
                    "dom_xss",
                    Severity::High,
                    "Potential DOM XSS: source/sink pattern detected",
                    format!(
                        "The page contains both DOM XSS sources ({sources}) and sinks \
                         ({sinks}). This combination indicates potential DOM-based XSS \
                         if user-controlled data flows from a source to a sink without \
                         sanitization. Manual review recommended.",
                        sources = sources_found.join(", "),
                        sinks = sinks_found.join(", "),
                    ),
                    url,
                )
                .with_evidence(format!(
                    "Sources: {} | Sinks: {}",
                    sources_found.join(", "),
                    sinks_found.join(", ")
                ))
                .with_remediation(
                    "Sanitize all user-controlled DOM values before using them in sinks. \
                     Use textContent instead of innerHTML. Avoid eval(), document.write(), \
                     and setTimeout/setInterval with string arguments. Use DOMPurify for \
                     HTML sanitization.",
                )
                .with_owasp("A07:2021 Cross-Site Scripting")
                .with_cwe(79)
                .with_confidence(0.4),
            );
        }

        // Also flag dangerous sinks even without detected sources
        // (sources may be in external JS files we didn't fetch)
        for sink in &sinks_found {
            if CRITICAL_SINKS.iter().any(|&(s, _)| *sink == s) && sources_found.is_empty() {
                findings.push(
                    Finding::new(
                        "dom_xss",
                        Severity::Medium,
                        format!("DOM XSS Sink: `{sink}` found without visible source"),
                        format!(
                            "The page uses the dangerous DOM sink `{sink}` in JavaScript. \
                             While no DOM XSS source was detected in inline scripts, the \
                             source may be in external JavaScript files. Manual review \
                             of data flow into this sink is recommended.",
                        ),
                        url,
                    )
                    .with_evidence(format!("Sink: {sink} detected in page JavaScript"))
                    .with_remediation(
                        "Review the data flow into this sink. Replace with safer alternatives \
                         (textContent instead of innerHTML, etc.).",
                    )
                    .with_owasp("A07:2021 Cross-Site Scripting")
                    .with_cwe(79)
                    .with_confidence(0.4),
                );
                break; // One finding for orphan sinks is enough
            }
        }

        Ok(findings)
    }
}

/// DOM XSS sources — user-controllable input points in the DOM.
const DOM_SOURCES: &[(&str, &str)] = &[
    ("location.hash", "URL fragment"),
    ("location.search", "URL query string"),
    ("location.href", "Full URL"),
    ("location.pathname", "URL path"),
    ("document.URL", "Document URL"),
    ("document.documentURI", "Document URI"),
    ("document.referrer", "Referrer URL"),
    ("window.name", "Window name"),
    ("postMessage", "Cross-origin message"),
    ("document.cookie", "Cookie value"),
    ("localStorage", "Local storage"),
    ("sessionStorage", "Session storage"),
];

/// DOM XSS sinks — dangerous output points.
const DOM_SINKS: &[(&str, &str)] = &[
    ("document.write", "Document write"),
    ("document.writeln", "Document writeln"),
    (".innerHTML", "innerHTML assignment"),
    (".outerHTML", "outerHTML assignment"),
    (".insertAdjacentHTML", "insertAdjacentHTML"),
    ("eval(", "eval execution"),
    ("setTimeout(", "setTimeout with string"),
    ("setInterval(", "setInterval with string"),
    ("Function(", "Function constructor"),
    ("execScript(", "execScript"),
    (".src=", "Source attribute assignment"),
    (".href=", "Href attribute assignment"),
    (".action=", "Form action assignment"),
    ("$.html(", "jQuery html()"),
    ("$.append(", "jQuery append()"),
];

/// Critical sinks that warrant a finding even without visible sources.
const CRITICAL_SINKS: &[(&str, &str)] = &[
    ("document.write", "Document write"),
    ("eval(", "eval execution"),
    (".innerHTML", "innerHTML assignment"),
];

/// Detect DOM XSS sources in page content.
///
/// Returns a list of source names found in the page.
fn detect_sources(body: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for &(pattern, _desc) in DOM_SOURCES {
        if body.contains(pattern) {
            found.push(pattern);
        }
    }
    found.dedup();
    found
}

/// Detect DOM XSS sinks in page content.
///
/// Returns a list of sink names found in the page.
fn detect_sinks(body: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    for &(pattern, _desc) in DOM_SINKS {
        if body.contains(pattern) {
            found.push(pattern);
        }
    }
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the DOM XSS scanner module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_dom_xss() {
        let module = DomXssModule;
        assert_eq!(module.id(), "dom_xss");
        assert_eq!(module.name(), "DOM XSS Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
    }

    /// Verify source detection finds `location.hash` in JavaScript.
    #[test]
    fn test_detect_sources() {
        let body = "<script>var x = location.hash; var y = document.referrer;</script>";
        let sources = detect_sources(body);

        assert!(sources.contains(&"location.hash"), "should detect location.hash");
        assert!(sources.contains(&"document.referrer"), "should detect document.referrer");
    }

    /// Verify sink detection finds `innerHTML` and `eval`.
    #[test]
    fn test_detect_sinks() {
        let body = "<script>el.innerHTML = data; eval(userInput);</script>";
        let sinks = detect_sinks(body);

        assert!(sinks.contains(&".innerHTML"), "should detect innerHTML");
        assert!(sinks.contains(&"eval("), "should detect eval");
    }

    /// Verify no false positives on normal HTML without JS patterns.
    #[test]
    fn test_detect_sources_negative() {
        let body = "<html><body><h1>Welcome</h1><p>No scripts here.</p></body></html>";
        assert!(detect_sources(body).is_empty());
        assert!(detect_sinks(body).is_empty());
    }

    /// Verify source and sink databases are non-empty and cover key patterns.
    #[test]
    fn test_source_sink_databases() {
        assert!(!DOM_SOURCES.is_empty());
        assert!(!DOM_SINKS.is_empty());
        assert!(!CRITICAL_SINKS.is_empty());

        let source_names: Vec<&str> = DOM_SOURCES.iter().map(|&(s, _)| s).collect();
        assert!(source_names.contains(&"location.hash"));
        assert!(source_names.contains(&"document.referrer"));

        let sink_names: Vec<&str> = DOM_SINKS.iter().map(|&(s, _)| s).collect();
        assert!(sink_names.contains(&".innerHTML"));
        assert!(sink_names.contains(&"eval("));
        assert!(sink_names.contains(&"document.write"));
    }
}
