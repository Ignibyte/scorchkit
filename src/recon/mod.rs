mod cloud;
mod cname_takeover;
mod crawler;
mod discovery;
mod dns;
mod headers;
mod js_analysis;
mod subdomain;
mod tech;
mod vhost;

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
        Box::new(dns::DnsSecurityModule),
        Box::new(js_analysis::JsAnalysisModule),
        Box::new(cname_takeover::CnameTakeoverModule),
        Box::new(vhost::VhostModule),
        Box::new(cloud::CloudReconModule),
    ]
}
