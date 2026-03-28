mod api_schema;
mod cmdi;
mod csrf;
mod idor;
mod injection;
mod jwt;
mod misconfig;
mod ratelimit;
mod redirect;
mod sensitive;
mod ssl;
mod ssrf;
mod waf;
mod xss;
mod xxe;

use crate::engine::module_trait::ScanModule;

/// Register all scanner modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
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
        Box::new(api_schema::ApiSchemaModule),
        Box::new(ratelimit::RateLimitModule),
    ]
}
