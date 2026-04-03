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

use crate::engine::module_trait::ScanModule;

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
