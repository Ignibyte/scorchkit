//! Translate CPE 2.3 identifiers to OSV ecosystem package coordinates.
//!
//! [`cpe_to_package`] is a pure function used by
//! [`crate::infra::cve_osv::OsvCveLookup`] to bridge the CPE-keyed
//! [`crate::engine::cve::CveLookup`] trait to OSV.dev's
//! ecosystem-keyed query API. The translator is intentionally
//! conservative — it returns `None` (cache-as-empty) for anything not
//! in its embedded mapping table rather than guessing a possibly-wrong
//! package coordinate.
//!
//! ## Coverage
//!
//! [`MAPPING`] covers the highest-value language-ecosystem CPEs across
//! `npm`, `PyPI`, `Maven`, `Go` modules, `crates.io`, `RubyGems`,
//! `NuGet`, and `Packagist` — vendors and products commonly surfaced
//! by service fingerprinting that have application-level CVEs.
//!
//! System software CPEs (nginx, OpenSSH, OpenSSL, Apache HTTPD) are
//! intentionally absent: they don't have OSV ecosystem coordinates.
//! NVD remains the right backend for those.
//!
//! ## Extending the table
//!
//! Add a tuple to [`MAPPING`] in the form
//! `((vendor, product), (ecosystem, package_name))`. The `vendor` and
//! `product` are matched case-insensitively against CPE 2.3 fields 3
//! and 4. `ecosystem` must be a valid [OSV defined ecosystem][osv]
//! string. `package_name` must be the exact OSV package identifier
//! (Maven uses `groupId:artifactId`, Go uses the import path, npm/PyPI
//! use the package name).
//!
//! [osv]: https://ossf.github.io/osv-schema/#defined-ecosystems

/// Resolved package coordinate suitable for an OSV.dev v1 query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCoord {
    /// OSV ecosystem identifier (`"npm"`, `"PyPI"`, `"Maven"`, ...).
    pub ecosystem: &'static str,
    /// Ecosystem-specific package name.
    pub name: String,
    /// Version from CPE field 6.
    pub version: String,
}

/// One `((vendor, product), (ecosystem, package_name))` entry in
/// [`MAPPING`]. Aliased to keep the table type readable and satisfy
/// clippy's `type_complexity` lint.
type CpeMapEntry = ((&'static str, &'static str), (&'static str, &'static str));

/// Static CPE → OSV-package mapping table.
///
/// Entries are matched case-insensitively against CPE 2.3 vendor and
/// product fields. Order doesn't matter — the first match wins (and
/// every entry is unique). Keep alphabetised by ecosystem then vendor
/// for human grep-ability.
const MAPPING: &[CpeMapEntry] = &[
    // npm
    (("expressjs", "express"), ("npm", "express")),
    (("axios", "axios"), ("npm", "axios")),
    (("lodash", "lodash"), ("npm", "lodash")),
    (("momentjs", "moment"), ("npm", "moment")),
    (("webpack", "webpack"), ("npm", "webpack")),
    (("nodemailer", "nodemailer"), ("npm", "nodemailer")),
    (("socket", "socket.io"), ("npm", "socket.io")),
    (("babel", "babel"), ("npm", "@babel/core")),
    (("nestjs", "nest"), ("npm", "@nestjs/core")),
    (("nextjs", "next.js"), ("npm", "next")),
    // PyPI
    (("djangoproject", "django"), ("PyPI", "django")),
    (("palletsprojects", "flask"), ("PyPI", "flask")),
    (("fastapi", "fastapi"), ("PyPI", "fastapi")),
    (("python", "requests"), ("PyPI", "requests")),
    (("pyyaml", "pyyaml"), ("PyPI", "pyyaml")),
    (("python", "pillow"), ("PyPI", "pillow")),
    (("sqlalchemy", "sqlalchemy"), ("PyPI", "sqlalchemy")),
    (("celeryproject", "celery"), ("PyPI", "celery")),
    // Maven
    (("apache", "struts"), ("Maven", "org.apache.struts:struts2-core")),
    (("apache", "log4j"), ("Maven", "org.apache.logging.log4j:log4j-core")),
    (("fasterxml", "jackson-databind"), ("Maven", "com.fasterxml.jackson.core:jackson-databind")),
    (("springframework", "spring_framework"), ("Maven", "org.springframework:spring-core")),
    (("apache", "commons_text"), ("Maven", "org.apache.commons:commons-text")),
    (("apache", "tomcat"), ("Maven", "org.apache.tomcat.embed:tomcat-embed-core")),
    (("snakeyaml_project", "snakeyaml"), ("Maven", "org.yaml:snakeyaml")),
    // Go modules
    (("hashicorp", "consul"), ("Go", "github.com/hashicorp/consul")),
    (("kubernetes", "kubernetes"), ("Go", "k8s.io/kubernetes")),
    (("gin-gonic", "gin"), ("Go", "github.com/gin-gonic/gin")),
    (("etcd-io", "etcd"), ("Go", "go.etcd.io/etcd")),
    // crates.io
    (("tokio-rs", "tokio"), ("crates.io", "tokio")),
    (("serde-rs", "serde"), ("crates.io", "serde")),
    (("actix", "actix-web"), ("crates.io", "actix-web")),
    // RubyGems
    (("rubyonrails", "rails"), ("RubyGems", "rails")),
    (("nokogiri", "nokogiri"), ("RubyGems", "nokogiri")),
    (("plataformatec", "devise"), ("RubyGems", "devise")),
    // NuGet
    (("newtonsoft", "json.net"), ("NuGet", "Newtonsoft.Json")),
    (("microsoft", "aspnetcore"), ("NuGet", "Microsoft.AspNetCore.App")),
    // Packagist
    (("drupal", "drupal"), ("Packagist", "drupal/core")),
    (("symfony", "symfony"), ("Packagist", "symfony/symfony")),
    (("laravel", "laravel"), ("Packagist", "laravel/framework")),
    (("magento", "magento2"), ("Packagist", "magento/magento2")),
];

/// Translate a CPE 2.3 string into an OSV [`PackageCoord`].
///
/// Returns `None` when:
///
/// - The CPE is malformed (not enough fields to extract vendor /
///   product / version, or wrong prefix).
/// - The vendor/product pair is not in [`MAPPING`].
/// - The version field is the CPE wildcard `"*"` or empty (OSV needs
///   an exact version to filter against `affected[]`).
///
/// CPE 2.3 syntax:
/// `cpe:2.3:a:VENDOR:PRODUCT:VERSION:UPDATE:EDITION:LANG:SW_EDITION:TARGET_SW:TARGET_HW:OTHER`
///
/// The translator is conservative: anything outside its narrow happy
/// path returns `None`, and the caller (`OsvCveLookup`) treats that as
/// "no records, do not query OSV". This is the right default — sending
/// OSV a bogus query wastes the rate budget and returns nothing useful.
#[must_use]
pub fn cpe_to_package(cpe: &str) -> Option<PackageCoord> {
    let fields: Vec<&str> = cpe.split(':').collect();
    // cpe:2.3:a:vendor:product:version:... → 6 leading fields minimum.
    if fields.len() < 6 {
        return None;
    }
    if fields[0] != "cpe" || fields[1] != "2.3" {
        return None;
    }
    // We only consider application CPEs (`a:`); operating-system
    // (`o:`) and hardware (`h:`) CPEs are not language-package CPEs by
    // definition.
    if fields[2] != "a" {
        return None;
    }
    let vendor = fields[3];
    let product = fields[4];
    let version = fields[5];
    if version.is_empty() || version == "*" || version == "-" {
        return None;
    }

    for ((v, p), (eco, name)) in MAPPING {
        if v.eq_ignore_ascii_case(vendor) && p.eq_ignore_ascii_case(product) {
            return Some(PackageCoord {
                ecosystem: eco,
                name: (*name).to_string(),
                version: version.to_string(),
            });
        }
    }
    None
}

/// Number of entries in [`MAPPING`]. Exposed for invariant tests.
#[must_use]
pub const fn mapping_len() -> usize {
    MAPPING.len()
}

#[cfg(test)]
mod tests {
    //! Coverage for [`cpe_to_package`] — happy paths across each
    //! ecosystem we support, the unmapped case, and the malformed
    //! cases. Plus a coverage invariant: at least 30 entries in
    //! [`MAPPING`] (the design commitment for v1).

    use super::*;

    #[test]
    fn cpe_to_package_npm_express() {
        let p = cpe_to_package("cpe:2.3:a:expressjs:express:4.17.0:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "npm");
        assert_eq!(p.name, "express");
        assert_eq!(p.version, "4.17.0");
    }

    #[test]
    fn cpe_to_package_maven_log4j() {
        let p = cpe_to_package("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "Maven");
        assert_eq!(p.name, "org.apache.logging.log4j:log4j-core");
        assert_eq!(p.version, "2.14.1");
    }

    #[test]
    fn cpe_to_package_pypi_django() {
        let p = cpe_to_package("cpe:2.3:a:djangoproject:django:3.2.0:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "PyPI");
        assert_eq!(p.name, "django");
    }

    #[test]
    fn cpe_to_package_rubygems_rails() {
        let p = cpe_to_package("cpe:2.3:a:rubyonrails:rails:6.1.0:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "RubyGems");
        assert_eq!(p.name, "rails");
    }

    #[test]
    fn cpe_to_package_crates_io_tokio() {
        let p = cpe_to_package("cpe:2.3:a:tokio-rs:tokio:1.0.0:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "crates.io");
        assert_eq!(p.name, "tokio");
    }

    /// Vendor/product casing should not affect the lookup — CPE 2.3
    /// values are case-insensitive per spec.
    #[test]
    fn cpe_to_package_case_insensitive() {
        let p = cpe_to_package("cpe:2.3:a:ExpressJS:Express:4.17.0:*:*:*:*:*:*:*").expect("map");
        assert_eq!(p.ecosystem, "npm");
    }

    /// System software (nginx, openssh) intentionally has no entry —
    /// OSV doesn't index those by ecosystem. NVD remains the answer.
    #[test]
    fn cpe_to_package_unmapped_returns_none() {
        assert!(cpe_to_package("cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*").is_none());
        assert!(cpe_to_package("cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*").is_none());
    }

    /// Wildcard or empty version means we have no exact version to
    /// query OSV with — return None rather than guessing.
    #[test]
    fn cpe_to_package_wildcard_version_returns_none() {
        assert!(cpe_to_package("cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*").is_none());
        assert!(cpe_to_package("cpe:2.3:a:expressjs:express:-:*:*:*:*:*:*:*").is_none());
    }

    /// Operating-system (`o:`) and hardware (`h:`) CPEs are not
    /// language-package CPEs by definition.
    #[test]
    fn cpe_to_package_rejects_non_application_cpes() {
        assert!(cpe_to_package("cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*").is_none());
        assert!(cpe_to_package("cpe:2.3:h:cisco:asa_5500:9.0:*:*:*:*:*:*:*").is_none());
    }

    /// Garbage in → None out. We never panic on malformed CPE strings.
    #[test]
    fn cpe_to_package_malformed_returns_none() {
        assert!(cpe_to_package("not a cpe").is_none());
        assert!(cpe_to_package("cpe:2.3").is_none());
        assert!(cpe_to_package("cpe:2.3:a").is_none());
        assert!(cpe_to_package("").is_none());
    }

    /// v1 design commitment: the embedded table covers at least 30
    /// high-value language-ecosystem CPEs. If a future change drops
    /// below that, this test catches it.
    #[test]
    fn cpe_to_package_table_has_at_least_30_entries() {
        assert!(mapping_len() >= 30, "MAPPING has {} entries; v1 contract is ≥30", mapping_len());
    }

    /// Every ecosystem string in [`MAPPING`] is a known OSV ecosystem
    /// per the OSV schema. Drift here would silently produce queries
    /// OSV can't satisfy.
    #[test]
    fn cpe_to_package_table_uses_valid_osv_ecosystems() {
        const VALID: &[&str] =
            &["npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Packagist"];
        for ((_, _), (eco, _)) in MAPPING {
            assert!(VALID.contains(eco), "unknown OSV ecosystem in table: {eco}");
        }
    }
}
