//! Canonical application-security classification for concrete scanner adapters.

#[cfg(feature = "cloud")]
use crate::engine::cloud_module::CloudCategory;
use crate::engine::code_module::CodeCategory;
#[cfg(feature = "infra")]
use crate::engine::infra_module::InfraCategory;
use crate::engine::module_trait::ModuleCategory;
use crate::engine::policy::EffectClass;
use scorchkit_core::{
    AdapterContractV1, AdapterOutputContract, AdapterTargetKind, LifecycleStage,
    ProvenanceStrategy, SecurityDomain, TemporaryArtifactPolicy, ADAPTER_CONTRACT_V1,
};

const SOURCE_TARGET: &[AdapterTargetKind] = &[AdapterTargetKind::SourceTree];
const DEPENDENCY_TARGETS: &[AdapterTargetKind] =
    &[AdapterTargetKind::DependencyManifest, AdapterTargetKind::SourceTree];
const ARTIFACT_TARGETS: &[AdapterTargetKind] = &[AdapterTargetKind::ApplicationArtifact];
const WEB_TARGETS: &[AdapterTargetKind] =
    &[AdapterTargetKind::WebApplication, AdapterTargetKind::Api];
const NETWORK_TARGET: &[AdapterTargetKind] = &[AdapterTargetKind::Network];
const CLOUD_TARGET: &[AdapterTargetKind] = &[AdapterTargetKind::CloudAccount];

const COMPATIBILITY_NETWORK_WEB_IDS: &[&str] = &[
    "amass",
    "cname_takeover",
    "dns-security",
    "dnsrecon",
    "dnsx",
    "masscan",
    "naabu",
    "nmap",
    "onesixtyone",
    "ssh_audit",
    "subdomain",
    "subfinder",
    "theharvester",
];

const COMPATIBILITY_ENTERPRISE_WEB_IDS: &[&str] =
    &["cewl", "enum4linux", "hydra", "kerbrute", "metasploit", "nxc", "smbmap"];

const COMPATIBILITY_CLOUD_WEB_IDS: &[&str] = &["cloud", "prowler"];

const APPLICATION_SOURCE_WEB_IDS: &[&str] = &["trufflehog"];
const APPLICATION_ARTIFACT_WEB_IDS: &[&str] = &[];
const APPLICATION_ATTACK_PATH_WEB_IDS: &[&str] = &["commix", "interactsh"];

const WEB_JSON_LINES_IDS: &[&str] = &[
    "amass",
    "dalfox",
    "feroxbuster",
    "httpx",
    "interactsh",
    "katana",
    "naabu",
    "nuclei",
    "subfinder",
    "testssl",
    "trufflehog",
    "whatweb",
];
const WEB_JSON_IDS: &[&str] = &[
    "arjun",
    "dnsrecon",
    "droopescan",
    "ffuf",
    "nikto",
    "prowler",
    "ssh_audit",
    "sslyze",
    "wafw00f",
    "wapiti",
    "wpscan",
];
const WEB_XML_IDS: &[&str] = &["nmap"];
const WEB_FILE_ARTIFACT_IDS: &[&str] = &["eyewitness", "vespasian"];
const WEB_SCOPED_TEMP_IDS: &[&str] =
    &["eyewitness", "kerbrute", "onesixtyone", "sqlmap", "vespasian", "wapiti"];

/// All production web module IDs expected from the built-in registries.
pub const KNOWN_WEB_ADAPTER_IDS: &[&str] = &[
    "acl",
    "amass",
    "api-schema",
    "api-security",
    "arjun",
    "auth-session",
    "cewl",
    "clickjacking",
    "cloud",
    "cmdi",
    "cname_takeover",
    "commix",
    "cors-deep",
    "crawler",
    "crlf",
    "csp-deep",
    "csrf",
    "dalfox",
    "discovery",
    "dns-security",
    "dnsrecon",
    "dnsx",
    "dom_xss",
    "droopescan",
    "enum4linux",
    "eyewitness",
    "feroxbuster",
    "ffuf",
    "gau",
    "gobuster",
    "graphql",
    "headers",
    "host_header",
    "httpx",
    "hydra",
    "idor",
    "injection",
    "interactsh",
    "js_analysis",
    "jwt",
    "katana",
    "kerbrute",
    "ldap",
    "linkfinder",
    "mass_assignment",
    "masscan",
    "metasploit",
    "misconfig",
    "naabu",
    "nikto",
    "nmap",
    "nosql",
    "nuclei",
    "nxc",
    "onesixtyone",
    "paramspider",
    "path_traversal",
    "prototype_pollution",
    "prowler",
    "ratelimit",
    "redirect",
    "sensitive",
    "smbmap",
    "smuggling",
    "sqlmap",
    "ssh_audit",
    "ssl",
    "sslyze",
    "ssrf",
    "ssti",
    "subdomain",
    "subfinder",
    "subtakeover",
    "tech",
    "testssl",
    "theharvester",
    "trufflehog",
    "upload",
    "vespasian",
    "vhost",
    "waf",
    "wafw00f",
    "wapiti",
    "websocket",
    "whatweb",
    "wpscan",
    "xss",
    "xsstrike",
    "xxe",
];

/// All production code module IDs expected from the built-in registries.
pub const KNOWN_CODE_ADAPTER_IDS: &[&str] = &[
    "bandit",
    "brakeman",
    "cargo_audit",
    "cargo_deny",
    "checkov",
    "codeql",
    "dep-audit",
    "dockle",
    "eslint-security",
    "gitleaks",
    "gosec",
    "hadolint",
    "kics",
    "kubescape",
    "phpstan",
    "psalm",
    "scoutsuite",
    "semgrep",
    "slither",
    "snyk-code",
    "snyk-test",
    "tflint",
];

/// Return the common descriptor contract for one URL-targeted module.
#[must_use]
pub fn web_adapter_contract(
    id: &str,
    category: ModuleCategory,
    requires_external_tool: bool,
    required_tool: Option<&str>,
) -> AdapterContractV1<'static> {
    let security_domain = web_security_domain(id);
    let lifecycle_stage = match security_domain {
        SecurityDomain::ApplicationSource => LifecycleStage::Source,
        SecurityDomain::ApplicationArtifact | SecurityDomain::ApplicationDependency => {
            LifecycleStage::Build
        }
        SecurityDomain::ApplicationAttackPath => LifecycleStage::Manual,
        SecurityDomain::ApplicationRuntime => LifecycleStage::Runtime,
        SecurityDomain::CompatibilityCloud
        | SecurityDomain::CompatibilityEnterprise
        | SecurityDomain::CompatibilityNetwork => LifecycleStage::Platform,
    };
    let target_kinds = match security_domain {
        SecurityDomain::ApplicationSource => SOURCE_TARGET,
        SecurityDomain::ApplicationArtifact => ARTIFACT_TARGETS,
        SecurityDomain::ApplicationRuntime | SecurityDomain::ApplicationAttackPath => WEB_TARGETS,
        SecurityDomain::CompatibilityCloud => CLOUD_TARGET,
        SecurityDomain::CompatibilityEnterprise | SecurityDomain::CompatibilityNetwork => {
            NETWORK_TARGET
        }
        SecurityDomain::ApplicationDependency => DEPENDENCY_TARGETS,
    };
    let strongest_effect = if requires_external_tool {
        external_web_tool_effect(required_tool.unwrap_or(id)).unwrap_or(EffectClass::Intrusive)
    } else if category == ModuleCategory::Recon {
        EffectClass::ActiveSafe
    } else {
        EffectClass::Intrusive
    };

    AdapterContractV1 {
        schema_version: ADAPTER_CONTRACT_V1,
        security_domain,
        lifecycle_stage,
        target_kinds,
        strongest_effect,
        output_contract: web_output_contract(id, requires_external_tool),
        provenance: if id == "nuclei" {
            ProvenanceStrategy::TemplateSet
        } else if id == "rule-engine" || !KNOWN_WEB_ADAPTER_IDS.contains(&id) {
            ProvenanceStrategy::PluginDefinition
        } else if requires_external_tool {
            ProvenanceStrategy::ToolVersion
        } else {
            ProvenanceStrategy::BuiltIn
        },
        temporary_artifacts: if WEB_SCOPED_TEMP_IDS.contains(&id) {
            TemporaryArtifactPolicy::ScopedOwned
        } else {
            TemporaryArtifactPolicy::None
        },
    }
}

/// Return the common descriptor contract for one source or artifact module.
#[must_use]
pub fn code_adapter_contract(
    id: &str,
    category: CodeCategory,
    requires_external_tool: bool,
) -> AdapterContractV1<'static> {
    let security_domain = if id == "scoutsuite" {
        SecurityDomain::CompatibilityCloud
    } else {
        match category {
            CodeCategory::Sast | CodeCategory::Correctness | CodeCategory::Secrets => {
                SecurityDomain::ApplicationSource
            }
            CodeCategory::Sca => SecurityDomain::ApplicationDependency,
            CodeCategory::Iac | CodeCategory::Container => SecurityDomain::ApplicationArtifact,
        }
    };
    let (lifecycle_stage, target_kinds) = match security_domain {
        SecurityDomain::ApplicationSource => (LifecycleStage::Source, SOURCE_TARGET),
        SecurityDomain::ApplicationDependency => (LifecycleStage::Build, DEPENDENCY_TARGETS),
        SecurityDomain::ApplicationArtifact => (LifecycleStage::Build, ARTIFACT_TARGETS),
        SecurityDomain::CompatibilityCloud => (LifecycleStage::Platform, CLOUD_TARGET),
        SecurityDomain::ApplicationRuntime
        | SecurityDomain::ApplicationAttackPath
        | SecurityDomain::CompatibilityEnterprise
        | SecurityDomain::CompatibilityNetwork => (LifecycleStage::Platform, SOURCE_TARGET),
    };

    AdapterContractV1 {
        schema_version: ADAPTER_CONTRACT_V1,
        security_domain,
        lifecycle_stage,
        target_kinds,
        strongest_effect: EffectClass::Passive,
        output_contract: if matches!(id, "codeql" | "psalm") {
            AdapterOutputContract::Sarif
        } else if requires_external_tool {
            AdapterOutputContract::Json
        } else {
            AdapterOutputContract::NativeFindings
        },
        provenance: if matches!(id, "semgrep" | "codeql" | "psalm") {
            ProvenanceStrategy::RuleSet
        } else if requires_external_tool {
            ProvenanceStrategy::ToolVersion
        } else {
            ProvenanceStrategy::BuiltIn
        },
        temporary_artifacts: if matches!(id, "codeql" | "kics" | "psalm" | "scoutsuite" | "semgrep")
        {
            TemporaryArtifactPolicy::ScopedOwned
        } else {
            TemporaryArtifactPolicy::None
        },
    }
}

/// Return the compatibility contract for one infrastructure module.
#[cfg(feature = "infra")]
#[must_use]
pub fn infra_adapter_contract(
    id: &str,
    _category: InfraCategory,
    requires_external_tool: bool,
) -> AdapterContractV1<'static> {
    AdapterContractV1 {
        schema_version: ADAPTER_CONTRACT_V1,
        security_domain: SecurityDomain::CompatibilityNetwork,
        lifecycle_stage: LifecycleStage::Platform,
        target_kinds: NETWORK_TARGET,
        strongest_effect: EffectClass::ActiveSafe,
        output_contract: if id == "nmap" {
            AdapterOutputContract::Xml
        } else if requires_external_tool {
            AdapterOutputContract::Json
        } else {
            AdapterOutputContract::NativeFindings
        },
        provenance: if requires_external_tool {
            ProvenanceStrategy::ToolVersion
        } else {
            ProvenanceStrategy::BuiltIn
        },
        temporary_artifacts: TemporaryArtifactPolicy::None,
    }
}

/// Return the compatibility contract for one cloud-posture module.
#[cfg(feature = "cloud")]
#[must_use]
pub fn cloud_adapter_contract(
    id: &str,
    _category: CloudCategory,
    requires_external_tool: bool,
) -> AdapterContractV1<'static> {
    AdapterContractV1 {
        schema_version: ADAPTER_CONTRACT_V1,
        security_domain: SecurityDomain::CompatibilityCloud,
        lifecycle_stage: LifecycleStage::Platform,
        target_kinds: CLOUD_TARGET,
        strongest_effect: if id == "pacu-cloud" {
            EffectClass::Exploit
        } else {
            EffectClass::Passive
        },
        output_contract: if requires_external_tool {
            AdapterOutputContract::Json
        } else {
            AdapterOutputContract::NativeFindings
        },
        provenance: if requires_external_tool {
            ProvenanceStrategy::ToolVersion
        } else {
            ProvenanceStrategy::BuiltIn
        },
        temporary_artifacts: if matches!(id, "cloudsplaining-cloud" | "scoutsuite-cloud") {
            TemporaryArtifactPolicy::ScopedOwned
        } else {
            TemporaryArtifactPolicy::None
        },
    }
}

/// Strongest special effect for credential-testing and exploit-capable web tools.
///
/// `None` means the caller must use the profile's ordinary DAST effect.
#[must_use]
pub fn external_web_tool_effect(tool_name: &str) -> Option<EffectClass> {
    match tool_name {
        "hydra" | "kerbrute" | "nxc" | "onesixtyone" | "smbmap" => {
            Some(EffectClass::CredentialTest)
        }
        "commix" | "msfconsole" => Some(EffectClass::Exploit),
        _ => None,
    }
}

/// Whether a web-family compatibility tool reads ambient account credentials.
#[must_use]
pub fn external_web_tool_uses_ambient_credentials(tool_name: &str) -> bool {
    matches!(tool_name, "prowler")
}

fn web_security_domain(id: &str) -> SecurityDomain {
    if COMPATIBILITY_NETWORK_WEB_IDS.contains(&id) {
        SecurityDomain::CompatibilityNetwork
    } else if COMPATIBILITY_ENTERPRISE_WEB_IDS.contains(&id) {
        SecurityDomain::CompatibilityEnterprise
    } else if COMPATIBILITY_CLOUD_WEB_IDS.contains(&id) {
        SecurityDomain::CompatibilityCloud
    } else if APPLICATION_SOURCE_WEB_IDS.contains(&id) {
        SecurityDomain::ApplicationSource
    } else if APPLICATION_ARTIFACT_WEB_IDS.contains(&id) {
        SecurityDomain::ApplicationArtifact
    } else if APPLICATION_ATTACK_PATH_WEB_IDS.contains(&id) {
        SecurityDomain::ApplicationAttackPath
    } else {
        SecurityDomain::ApplicationRuntime
    }
}

fn web_output_contract(id: &str, requires_external_tool: bool) -> AdapterOutputContract {
    if !requires_external_tool {
        AdapterOutputContract::NativeFindings
    } else if WEB_JSON_LINES_IDS.contains(&id) {
        AdapterOutputContract::JsonLines
    } else if WEB_JSON_IDS.contains(&id) {
        AdapterOutputContract::Json
    } else if WEB_XML_IDS.contains(&id) {
        AdapterOutputContract::Xml
    } else if WEB_FILE_ARTIFACT_IDS.contains(&id) {
        AdapterOutputContract::FileArtifacts
    } else {
        AdapterOutputContract::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_tool_effects_are_exact() {
        for tool in ["hydra", "kerbrute", "nxc", "onesixtyone", "smbmap"] {
            assert_eq!(external_web_tool_effect(tool), Some(EffectClass::CredentialTest));
        }
        for tool in ["commix", "msfconsole"] {
            assert_eq!(external_web_tool_effect(tool), Some(EffectClass::Exploit));
        }
        for tool in ["nuclei", "zap.sh", "sqlmap"] {
            assert_eq!(external_web_tool_effect(tool), None);
        }
        assert!(external_web_tool_uses_ambient_credentials("prowler"));
        assert!(!external_web_tool_uses_ambient_credentials("nuclei"));
    }

    #[test]
    fn representative_contracts_pin_product_and_provenance_boundaries() {
        let nuclei = web_adapter_contract("nuclei", ModuleCategory::Scanner, true, Some("nuclei"));
        assert_eq!(nuclei.security_domain, SecurityDomain::ApplicationRuntime);
        assert_eq!(nuclei.output_contract, AdapterOutputContract::JsonLines);
        assert_eq!(nuclei.provenance, ProvenanceStrategy::TemplateSet);

        let metasploit =
            web_adapter_contract("metasploit", ModuleCategory::Scanner, true, Some("msfconsole"));
        assert_eq!(metasploit.security_domain, SecurityDomain::CompatibilityEnterprise);
        assert_eq!(metasploit.strongest_effect, EffectClass::Exploit);
        assert_eq!(metasploit.output_contract, AdapterOutputContract::Text);

        let nmap = web_adapter_contract("nmap", ModuleCategory::Recon, true, Some("nmap"));
        assert_eq!(nmap.output_contract, AdapterOutputContract::Xml);

        let sqlmap = web_adapter_contract("sqlmap", ModuleCategory::Scanner, true, Some("sqlmap"));
        assert_eq!(sqlmap.output_contract, AdapterOutputContract::Text);
        assert_eq!(sqlmap.temporary_artifacts, TemporaryArtifactPolicy::ScopedOwned);

        let semgrep = code_adapter_contract("semgrep", CodeCategory::Sast, true);
        assert_eq!(semgrep.security_domain, SecurityDomain::ApplicationSource);
        assert_eq!(semgrep.provenance, ProvenanceStrategy::RuleSet);

        let scoutsuite = code_adapter_contract("scoutsuite", CodeCategory::Container, true);
        assert_eq!(scoutsuite.security_domain, SecurityDomain::CompatibilityCloud);
    }

    #[test]
    fn web_contracts_distinguish_effect_and_provenance_branches() {
        let built_in_recon = web_adapter_contract("headers", ModuleCategory::Recon, false, None);
        assert_eq!(built_in_recon.strongest_effect, EffectClass::ActiveSafe);
        assert_eq!(built_in_recon.provenance, ProvenanceStrategy::BuiltIn);

        let built_in_scanner =
            web_adapter_contract("headers", ModuleCategory::Scanner, false, None);
        assert_eq!(built_in_scanner.strongest_effect, EffectClass::Intrusive);

        let rule_engine = web_adapter_contract("rule-engine", ModuleCategory::Scanner, false, None);
        assert_eq!(rule_engine.provenance, ProvenanceStrategy::PluginDefinition);

        let unknown = web_adapter_contract("custom-adapter", ModuleCategory::Scanner, true, None);
        assert_eq!(unknown.provenance, ProvenanceStrategy::PluginDefinition);

        let known_tool = web_adapter_contract("nmap", ModuleCategory::Recon, true, Some("nmap"));
        assert_eq!(known_tool.provenance, ProvenanceStrategy::ToolVersion);
    }

    #[cfg(feature = "cloud")]
    #[test]
    fn cloud_contracts_distinguish_exploit_and_passive_tools() {
        let pacu = cloud_adapter_contract("pacu-cloud", CloudCategory::Iam, true);
        assert_eq!(pacu.strongest_effect, EffectClass::Exploit);

        let prowler = cloud_adapter_contract("prowler-cloud", CloudCategory::Compliance, true);
        assert_eq!(prowler.strongest_effect, EffectClass::Passive);
    }
}
