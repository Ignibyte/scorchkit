pub mod amass;
pub mod arjun;
pub mod cewl;
pub mod commix;
pub mod dalfox;
pub mod dnsrecon;
pub mod dnsx;
pub mod droopescan;
pub mod enum4linux;
pub mod eyewitness;
pub mod feroxbuster;
pub mod ffuf;
pub mod gau;
pub mod gobuster;
pub mod httpx;
pub mod hydra;
pub mod interactsh;
pub mod katana;
pub mod kerbrute;
pub mod linkfinder;
pub mod masscan;
pub mod metasploit;
pub mod naabu;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod nxc;
pub mod onesixtyone;
pub mod paramspider;
pub mod prowler;
pub mod smbmap;
pub mod sqlmap;
pub mod ssh_audit;
pub mod sslyze;
pub mod subfinder;
pub mod testssl;
pub mod theharvester;
pub mod trivy;
pub mod trufflehog;
pub mod vespasian;
pub mod wafw00f;
pub mod wapiti;
pub mod whatweb;
pub mod wpscan;
pub mod xsstrike;
pub mod zap;

use crate::engine::module_trait::ScanModule;

/// Register all external tool wrapper modules.
#[must_use]
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(interactsh::InteractshModule),
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
        Box::new(katana::KatanaModule),
        Box::new(gau::GauModule),
        Box::new(paramspider::ParamSpiderModule),
        Box::new(trufflehog::TrufflehogModule),
        Box::new(prowler::ProwlerModule),
        Box::new(trivy::TrivyModule),
        Box::new(dnsx::DnsxModule),
        Box::new(gobuster::GobusterModule),
        Box::new(dnsrecon::DnsreconModule),
        Box::new(enum4linux::Enum4linuxModule),
        // WORK-111: network/infra tool batch
        Box::new(masscan::MasscanModule),
        Box::new(naabu::NaabuModule),
        Box::new(smbmap::SmbmapModule),
        Box::new(nxc::NxcModule),
        Box::new(kerbrute::KerbruteModule),
        Box::new(ssh_audit::SshAuditModule),
        Box::new(onesixtyone::OnesixtyoneModule),
        // WORK-107: Vespasian API endpoint discovery
        Box::new(vespasian::VespasianModule),
        // WORK-112: DAST polish tool batch
        Box::new(commix::CommixModule),
        Box::new(xsstrike::XsstrikeModule),
        Box::new(whatweb::WhatwebModule),
        Box::new(wapiti::WapitiModule),
        Box::new(linkfinder::LinkfinderModule),
        Box::new(eyewitness::EyewitnessModule),
    ]
}
