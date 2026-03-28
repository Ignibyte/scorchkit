pub mod amass;
pub mod arjun;
pub mod cewl;
pub mod dalfox;
pub mod droopescan;
pub mod feroxbuster;
pub mod ffuf;
pub mod httpx;
pub mod hydra;
pub mod metasploit;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod sqlmap;
pub mod sslyze;
pub mod subfinder;
pub mod testssl;
pub mod theharvester;
pub mod wafw00f;
pub mod wpscan;
pub mod zap;

use crate::engine::module_trait::ScanModule;

/// Register all external tool wrapper modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(nmap::NmapModule),
        Box::new(nuclei::NucleiModule),
        Box::new(nikto::NiktoModule),
        Box::new(sqlmap::SqlmapModule),
        Box::new(feroxbuster::FeroxbusterModule),
        Box::new(sslyze::SslyzeModule),
        Box::new(zap::ZapModule),
        Box::new(ffuf::FfufModule),
        Box::new(metasploit::MetasploitModule),
        Box::new(wafw00f::Wafw00fModule),
        Box::new(testssl::TestsslModule),
        Box::new(wpscan::WpscanModule),
        Box::new(amass::AmassModule),
        Box::new(subfinder::SubfinderModule),
        Box::new(dalfox::DalfoxModule),
        Box::new(hydra::HydraModule),
        Box::new(httpx::HttpxModule),
        Box::new(theharvester::TheHarvesterModule),
        Box::new(arjun::ArjunModule),
        Box::new(cewl::CewlModule),
        Box::new(droopescan::DroopescanModule),
    ]
}
