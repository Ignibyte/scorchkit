mod acl;
mod api;
mod api_schema;
mod auth;
mod clickjacking;
mod cmdi;
mod cors;
mod crlf;
mod csp;
mod csrf;
mod dom_xss;
mod graphql;
mod host_header;
mod idor;
mod injection;
mod jwt;
mod ldap;
mod mass_assignment;
mod misconfig;
mod nosql;
mod path_traversal;
mod prototype_pollution;
mod ratelimit;
mod redirect;
mod sensitive;
mod smuggling;
mod ssl;
mod ssrf;
mod ssti;
mod subtakeover;
mod upload;
mod waf;
mod websocket;
mod xss;
mod xxe;

use crate::engine::error::{Result, ScorchError};
use crate::engine::module_trait::ScanModule;

const MAX_SCANNER_RESPONSE_BYTES: usize = 256 * 1024;

/// Read one decoded scanner response under the shared hard byte ceiling.
pub(crate) async fn bounded_response_text(mut response: reqwest::Response) -> Result<String> {
    let url = scorchkit_core::observation::redact_url(response.url().as_str()).0;
    let mut body = Vec::new();
    while let Some(chunk) =
        response.chunk().await.map_err(|source| ScorchError::Http { url: url.clone(), source })?
    {
        if chunk.len() > MAX_SCANNER_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(ScorchError::HttpResponseLimit { limit_bytes: MAX_SCANNER_RESPONSE_BYTES });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub(crate) fn supports_application_pentest_field(name: &str) -> bool {
    mass_assignment::supports_application_pentest_field(name)
}

/// Register all scanner modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(auth::AuthSessionModule),
        Box::new(cors::CorsModule),
        Box::new(csp::CspModule),
        Box::new(waf::WafModule),
        Box::new(ssl::SslModule),
        Box::new(misconfig::MisconfigModule),
        Box::new(csrf::CsrfModule),
        Box::new(injection::InjectionModule),
        Box::new(cmdi::CmdiModule),
        Box::new(xss::XssModule),
        Box::new(ssrf::SsrfModule),
        Box::new(xxe::XxeModule),
        Box::new(idor::IdorModule),
        Box::new(jwt::JwtModule),
        Box::new(redirect::RedirectModule),
        Box::new(sensitive::SensitiveDataModule),
        Box::new(upload::UploadModule),
        Box::new(websocket::WebSocketModule),
        Box::new(graphql::GraphQLModule),
        Box::new(subtakeover::SubdomainTakeoverModule),
        Box::new(acl::AclModule),
        Box::new(api::ApiSecurityModule),
        Box::new(api_schema::ApiSchemaModule),
        Box::new(ratelimit::RateLimitModule),
        Box::new(path_traversal::PathTraversalModule),
        Box::new(ssti::SstiModule),
        Box::new(crlf::CrlfModule),
        Box::new(host_header::HostHeaderModule),
        Box::new(nosql::NosqlModule),
        Box::new(ldap::LdapModule),
        Box::new(smuggling::SmugglingModule),
        Box::new(prototype_pollution::PrototypePollutionModule),
        Box::new(mass_assignment::MassAssignmentModule),
        Box::new(clickjacking::ClickjackingModule),
        Box::new(dom_xss::DomXssModule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scanner_response_reader_rejects_the_first_byte_over_the_limit() {
        let server = httpmock::MockServer::start_async().await;
        let response = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET).path("/oversized");
                then.status(200).body("x".repeat(MAX_SCANNER_RESPONSE_BYTES + 1));
            })
            .await;
        let received = reqwest::Client::new()
            .get(server.url("/oversized"))
            .send()
            .await
            .expect("loopback response");

        assert!(matches!(
            bounded_response_text(received).await,
            Err(ScorchError::HttpResponseLimit { limit_bytes })
                if limit_bytes == MAX_SCANNER_RESPONSE_BYTES
        ));
        assert_eq!(response.calls_async().await, 1);
    }

    #[tokio::test]
    async fn scanner_response_reader_accepts_the_exact_limit() {
        let server = httpmock::MockServer::start_async().await;
        let response = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET).path("/exact");
                then.status(200).body("x".repeat(MAX_SCANNER_RESPONSE_BYTES));
            })
            .await;
        let received = reqwest::Client::new()
            .get(server.url("/exact"))
            .send()
            .await
            .expect("loopback response");

        let body = bounded_response_text(received).await.expect("exact limit");
        assert_eq!(body.len(), MAX_SCANNER_RESPONSE_BYTES);
        assert_eq!(response.calls_async().await, 1);
    }
}
