use async_trait::async_trait;
use url::Url;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects Insecure Direct Object Reference (IDOR) vulnerabilities.
#[derive(Debug)]
pub struct IdorModule;

#[async_trait]
impl ScanModule for IdorModule {
    fn name(&self) -> &'static str {
        "IDOR Detection"
    }
    fn id(&self) -> &'static str {
        "idor"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }
    fn description(&self) -> &'static str {
        "Detect Insecure Direct Object References by manipulating IDs"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        test_url_params_idor(ctx, url, &mut findings).await?;
        test_path_segments_idor(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

async fn test_url_params_idor(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let params: Vec<(String, String)> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    for (param_name, param_value) in &params {
        // Only test parameters that look like IDs
        if !looks_like_id(param_name, param_value) {
            continue;
        }

        // Get baseline response
        let baseline = match ctx.http_client.get(url_str).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let baseline_status = baseline.status();
        let baseline_body = baseline.text().await.unwrap_or_default();

        // Try adjacent IDs
        let test_values = generate_adjacent_ids(param_value);
        for test_val in &test_values {
            let mut test_url = parsed.clone();
            {
                let mut q = test_url.query_pairs_mut();
                q.clear();
                for (k, v) in &params {
                    if k == param_name {
                        q.append_pair(k, test_val);
                    } else {
                        q.append_pair(k, v);
                    }
                }
            }

            let response = match ctx.http_client.get(test_url.as_str()).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // If adjacent ID returns 200 with different content, possible IDOR
            if status == baseline_status
                && status.is_success()
                && body != baseline_body
                && body.len() > 100
            {
                // Check it's not just a generic page
                let similarity = calculate_similarity(&baseline_body, &body);
                if similarity > 0.3 && similarity < 0.95 {
                    findings.push(
                        Finding::new("idor", Severity::High, format!("Possible IDOR: {param_name}"), format!("Changing '{param_name}' from '{param_value}' to '{test_val}' returns different content ({}% similar). This may expose another user's data.", (similarity * 100.0) as u32), url_str)
                            .with_evidence(format!("Parameter: {param_name} | Original: {param_value} | Test: {test_val} | Similarity: {:.0}%", similarity * 100.0))
                            .with_remediation("Implement proper authorization checks. Verify the requesting user owns the requested resource.")
                            .with_owasp("A01:2021 Broken Access Control")
                            .with_cwe(639),
                    );
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

async fn test_path_segments_idor(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()),
    };

    let segments: Vec<&str> = parsed.path_segments().map_or(Vec::new(), |s| s.collect());

    for (i, segment) in segments.iter().enumerate() {
        if !segment.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if segment.len() > 10 {
            continue;
        } // Skip UUIDs/hashes

        let test_values = generate_adjacent_ids(segment);
        let baseline = match ctx.http_client.get(url_str).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let baseline_body = baseline.text().await.unwrap_or_default();

        for test_val in &test_values {
            let mut new_segments = segments.clone();
            new_segments[i] = test_val;
            let new_path = format!("/{}", new_segments.join("/"));

            let mut test_url = parsed.clone();
            test_url.set_path(&new_path);

            let response = match ctx.http_client.get(test_url.as_str()).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

            let body = response.text().await.unwrap_or_default();
            if body != baseline_body && body.len() > 100 {
                let similarity = calculate_similarity(&baseline_body, &body);
                if similarity > 0.3 && similarity < 0.95 {
                    findings.push(
                        Finding::new("idor", Severity::High, format!("Possible IDOR in Path: /{}", segments.join("/")), format!("Changing path segment '{segment}' to '{test_val}' returns different content."), url_str)
                            .with_evidence(format!("Original: {url_str} | Test: {} | Similarity: {:.0}%", test_url, similarity * 100.0))
                            .with_remediation("Implement authorization checks on path-based resource access.")
                            .with_owasp("A01:2021 Broken Access Control")
                            .with_cwe(639),
                    );
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn looks_like_id(name: &str, value: &str) -> bool {
    let lower = name.to_lowercase();
    let id_names = [
        "id", "uid", "user_id", "userid", "account", "profile", "doc", "file", "order", "item",
        "record", "num", "no",
    ];
    if id_names.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Pure numeric value
    value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() && value.len() <= 10
}

fn generate_adjacent_ids(value: &str) -> Vec<String> {
    if let Ok(num) = value.parse::<i64>() {
        vec![(num + 1).to_string(), (num - 1).max(0).to_string(), (num + 100).to_string()]
    } else {
        Vec::new()
    }
}

fn calculate_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let max_len = a.len().max(b.len()) as f64;
    let common = a.chars().zip(b.chars()).filter(|(x, y)| x == y).count() as f64;
    common / max_len
}
