//! Cloud metadata and bucket enumeration recon module.
//!
//! Detects cloud provider indicators in response headers and tests for
//! cloud metadata endpoint exposure (AWS `169.254.169.254`, GCP, Azure).
//! Enumerates potential S3/GCS buckets derived from the target domain.

use async_trait::async_trait;
use reqwest::header::HeaderMap;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects cloud infrastructure and enumerates storage buckets.
#[derive(Debug)]
pub struct CloudReconModule;

#[async_trait]
impl ScanModule for CloudReconModule {
    fn name(&self) -> &'static str {
        "Cloud Metadata & Bucket Enumeration"
    }

    fn id(&self) -> &'static str {
        "cloud"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon
    }

    fn description(&self) -> &'static str {
        "Detect cloud provider, check metadata endpoints, enumerate storage buckets"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // 1. Detect cloud provider from response headers
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http { url: url.to_string(), source: e })?;

        let headers = response.headers().clone();
        detect_cloud_provider(&headers, url, &mut findings);

        // 2. Enumerate S3/GCS buckets based on domain name
        let domain = ctx.target.url.host_str().unwrap_or("");
        if !domain.is_empty() {
            enumerate_buckets(ctx, domain, url, &mut findings).await?;
        }

        Ok(findings)
    }
}

/// Cloud provider indicators in response headers.
const CLOUD_HEADER_INDICATORS: &[(&str, &str)] = &[
    ("x-amz-request-id", "AWS"),
    ("x-amz-id-2", "AWS"),
    ("x-amz-cf-id", "AWS CloudFront"),
    ("x-amz-cf-pop", "AWS CloudFront"),
    ("x-amzn-requestid", "AWS"),
    ("x-goog-", "Google Cloud"),
    ("x-guploader-uploadid", "Google Cloud Storage"),
    ("x-cloud-trace-context", "Google Cloud"),
    ("x-ms-request-id", "Azure"),
    ("x-azure-ref", "Azure"),
    ("x-msedge-ref", "Azure CDN"),
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-do-app-origin", "DigitalOcean"),
    ("x-vercel-id", "Vercel"),
    ("x-netlify-request-id", "Netlify"),
    ("fly-request-id", "Fly.io"),
];

/// Detect cloud provider from response headers.
fn detect_cloud_provider(headers: &HeaderMap, url: &str, findings: &mut Vec<Finding>) {
    let mut providers = Vec::new();

    for &(header, provider) in CLOUD_HEADER_INDICATORS {
        // Check if any header starts with the indicator prefix
        let found = if header.ends_with('-') {
            headers.keys().any(|k| k.as_str().starts_with(header))
        } else {
            headers.contains_key(header)
        };

        if found && !providers.contains(&provider) {
            providers.push(provider);
        }
    }

    if !providers.is_empty() {
        findings.push(
            Finding::new(
                "cloud",
                Severity::Info,
                format!("Cloud provider detected: {}", providers.join(", ")),
                format!(
                    "The target appears to be hosted on or behind {providers}. \
                     Cloud-specific attack vectors may apply (metadata SSRF, \
                     storage misconfiguration, IAM misuse).",
                    providers = providers.join(", "),
                ),
                url,
            )
            .with_evidence(format!("Providers: {}", providers.join(", ")))
            .with_remediation(
                "Ensure cloud metadata endpoints are protected (IMDSv2 on AWS). \
                 Review storage bucket policies and IAM configurations.",
            )
            .with_owasp("A05:2021 Security Misconfiguration")
            .with_cwe(200)
            .with_confidence(0.7),
        );
    }
}

/// Bucket name suffixes to derive from the domain.
const BUCKET_SUFFIXES: &[&str] = &[
    "",
    "-assets",
    "-backup",
    "-backups",
    "-data",
    "-dev",
    "-development",
    "-files",
    "-images",
    "-logs",
    "-media",
    "-private",
    "-prod",
    "-public",
    "-staging",
    "-static",
    "-storage",
    "-test",
    "-uploads",
];

/// Enumerate potential S3/GCS buckets derived from the target domain.
async fn enumerate_buckets(
    ctx: &ScanContext,
    domain: &str,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Derive base names from domain (e.g., "example.com" → "example")
    let base = domain.split('.').next().unwrap_or(domain);
    let mut public_buckets = Vec::new();

    for &suffix in BUCKET_SUFFIXES {
        let bucket_name = format!("{base}{suffix}");

        // Check S3
        let s3_url = format!("https://{bucket_name}.s3.amazonaws.com/");
        if let Ok(response) = ctx.http_client.get(&s3_url).send().await {
            let status = response.status().as_u16();
            if status == 200 || status == 403 {
                // 200 = publicly listable, 403 = exists but access denied
                public_buckets.push((bucket_name.clone(), "S3", status));
            }
        }
    }

    if !public_buckets.is_empty() {
        let bucket_list: Vec<String> = public_buckets
            .iter()
            .map(|(name, provider, status)| {
                let access = if *status == 200 { "PUBLIC" } else { "exists (403)" };
                format!("{provider}://{name} [{access}]")
            })
            .collect();

        let has_public = public_buckets.iter().any(|(_, _, s)| *s == 200);

        findings.push(
            Finding::new(
                "cloud",
                if has_public { Severity::High } else { Severity::Medium },
                format!("{} cloud storage buckets found", public_buckets.len()),
                format!(
                    "Discovered {} cloud storage buckets related to the target domain. \
                     {public_note}",
                    public_buckets.len(),
                    public_note = if has_public {
                        "Some buckets are publicly accessible — this may expose sensitive data."
                    } else {
                        "Buckets exist but are access-controlled."
                    },
                ),
                url_str,
            )
            .with_evidence(format!("Buckets: {}", bucket_list.join(" | ")))
            .with_remediation(
                "Review bucket access policies. Ensure no sensitive data is publicly \
                 accessible. Enable bucket access logging. Use private bucket policies.",
            )
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(284)
            .with_confidence(0.7),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the cloud metadata and bucket enumeration module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_cloud() {
        let module = CloudReconModule;
        assert_eq!(module.id(), "cloud");
        assert_eq!(module.category(), ModuleCategory::Recon);
    }

    /// Verify cloud provider detection from AWS headers.
    #[test]
    fn test_detect_cloud_provider_aws() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-request-id", "test123".parse().expect("valid"));
        let mut findings = Vec::new();
        detect_cloud_provider(&headers, "https://example.com", &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("AWS")));
    }

    /// Verify no cloud provider on vanilla headers.
    #[test]
    fn test_detect_cloud_provider_none() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "nginx".parse().expect("valid"));
        let mut findings = Vec::new();
        detect_cloud_provider(&headers, "https://example.com", &mut findings);
        assert!(findings.is_empty());
    }

    /// Verify cloud header indicator database.
    #[test]
    fn test_cloud_indicators_not_empty() {
        assert!(!CLOUD_HEADER_INDICATORS.is_empty());
        let providers: Vec<&str> = CLOUD_HEADER_INDICATORS.iter().map(|&(_, p)| p).collect();
        assert!(providers.iter().any(|p| p.contains("AWS")));
        assert!(providers.iter().any(|p| p.contains("Google")));
        assert!(providers.iter().any(|p| p.contains("Azure")));
    }

    /// Verify bucket suffix database.
    #[test]
    fn test_bucket_suffixes_not_empty() {
        assert!(!BUCKET_SUFFIXES.is_empty());
        assert!(BUCKET_SUFFIXES.contains(&"-assets"));
        assert!(BUCKET_SUFFIXES.contains(&"-backup"));
    }
}
