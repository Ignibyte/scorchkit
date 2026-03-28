mod crawler;
mod discovery;
mod headers;
mod subdomain;
mod tech;

use crate::engine::module_trait::ScanModule;

/// Register all recon modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(headers::HeadersModule),
        Box::new(tech::TechModule),
        Box::new(discovery::DiscoveryModule),
        Box::new(subdomain::SubdomainModule),
        Box::new(crawler::CrawlerModule),
    ]
}
