//! Offline `CodeQL` adapter for deep no-build static analysis.

use std::collections::BTreeSet;
use std::time::Duration;

use async_trait::async_trait;
use scorchkit_core::AdapterParseOutcome;

use super::sarif::{parse_sarif_output, read_bounded_sarif, SarifAdapter};
use crate::engine::code_context::CodeContext;
use crate::engine::code_module::{CodeAnalysisDepth, CodeCategory, CodeModule};
use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::runner::subprocess::ToolInvocation;

/// Deep static analysis using locally installed `CodeQL` query packs.
#[derive(Debug)]
pub struct CodeqlModule;

#[derive(Debug, Clone, Copy)]
struct CodeqlLanguage {
    source_name: &'static str,
    extractor: &'static str,
    query_pack: &'static str,
    suite_name: &'static str,
}

const CODEQL_LANGUAGES: &[CodeqlLanguage] = &[
    CodeqlLanguage {
        source_name: "javascript",
        extractor: "javascript-typescript",
        query_pack: "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        suite_name: "javascript-security-extended",
    },
    CodeqlLanguage {
        source_name: "typescript",
        extractor: "javascript-typescript",
        query_pack: "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        suite_name: "javascript-security-extended",
    },
    CodeqlLanguage {
        source_name: "python",
        extractor: "python",
        query_pack: "codeql/python-queries:codeql-suites/python-security-extended.qls",
        suite_name: "python-security-extended",
    },
    CodeqlLanguage {
        source_name: "ruby",
        extractor: "ruby",
        query_pack: "codeql/ruby-queries:codeql-suites/ruby-security-extended.qls",
        suite_name: "ruby-security-extended",
    },
];

#[async_trait]
impl CodeModule for CodeqlModule {
    fn name(&self) -> &'static str {
        "CodeQL Deep SAST"
    }

    fn id(&self) -> &'static str {
        "codeql"
    }

    fn category(&self) -> CodeCategory {
        CodeCategory::Sast
    }

    fn depth(&self) -> CodeAnalysisDepth {
        CodeAnalysisDepth::Deep
    }

    fn description(&self) -> &'static str {
        "Offline CodeQL security-extended analysis for supported no-build languages"
    }

    fn languages(&self) -> &'static [&'static str] {
        &["javascript", "typescript", "python", "ruby"]
    }

    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&'static str> {
        Some("codeql")
    }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        let languages = selected_languages(&ctx.languages);
        let artifacts = tempfile::tempdir()?;
        let mut findings = Vec::new();
        for language in languages {
            let database = artifacts.path().join(format!("{}-database", language.extractor));
            let report = artifacts.path().join(format!("{}-results.sarif", language.extractor));
            create_database(ctx, language, &database).await?;
            analyze_database(ctx, language, &database, &report).await?;
            let sarif = read_bounded_sarif(&report, "codeql")?;
            findings.extend(parse_codeql_sarif(&sarif, language).into_result("codeql")?);
        }
        Ok(findings)
    }
}

fn selected_languages(detected: &[String]) -> Vec<CodeqlLanguage> {
    let mut extractors = BTreeSet::new();
    detected
        .iter()
        .filter_map(|detected| {
            CODEQL_LANGUAGES
                .iter()
                .find(|language| language.source_name.eq_ignore_ascii_case(detected))
                .copied()
        })
        .filter(|language| extractors.insert(language.extractor))
        .collect()
}

async fn create_database(
    ctx: &CodeContext,
    language: CodeqlLanguage,
    database: &std::path::Path,
) -> Result<()> {
    let database = database.display().to_string();
    let source_root = ctx.path.display().to_string();
    let language_arg = format!("--language={}", language.extractor);
    let source_arg = format!("--source-root={source_root}");
    ctx.run_invocation(
        ToolInvocation::strict(
            "codeql",
            &[
                "database",
                "create",
                &database,
                &language_arg,
                &source_arg,
                "--build-mode=none",
                "--threads=2",
                "--ram=4096",
            ],
            Duration::from_mins(15),
        )
        .with_working_directory(&ctx.path),
    )
    .await?;
    Ok(())
}

async fn analyze_database(
    ctx: &CodeContext,
    language: CodeqlLanguage,
    database: &std::path::Path,
    report: &std::path::Path,
) -> Result<()> {
    let database = database.display().to_string();
    let output_arg = format!("--output={}", report.display());
    let category_arg = format!("--sarif-category={}", language.extractor);
    ctx.run_invocation(
        ToolInvocation::strict(
            "codeql",
            &[
                "database",
                "analyze",
                "--format=sarif-latest",
                &output_arg,
                &category_arg,
                "--threads=2",
                "--ram=4096",
                "--no-download",
                "--",
                &database,
                language.query_pack,
            ],
            Duration::from_mins(20),
        )
        .with_working_directory(&ctx.path),
    )
    .await?;
    Ok(())
}

fn parse_codeql_sarif(sarif: &str, language: CodeqlLanguage) -> AdapterParseOutcome<Vec<Finding>> {
    parse_sarif_output(
        sarif,
        SarifAdapter {
            scanner_id: "codeql",
            config_identity: language.suite_name,
            default_confidence: 0.85,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use scorchkit_core::{ObservationLocation, Severity};

    #[test]
    fn language_mapping_is_no_build_and_deduplicates_javascript_typescript() {
        let selected = selected_languages(&[
            "typescript".to_string(),
            "javascript".to_string(),
            "python".to_string(),
            "php".to_string(),
        ]);
        assert_eq!(
            selected.iter().map(|language| language.extractor).collect::<Vec<_>>(),
            ["javascript-typescript", "python"]
        );
    }

    #[test]
    fn codeql_golden_preserves_query_path_and_every_flow_step() {
        let sarif = include_str!("../../tests/fixtures/sast/codeql-path.sarif.json");
        let outcome = parse_codeql_sarif(sarif, CODEQL_LANGUAGES[0]);
        let AdapterParseOutcome::Findings(findings) = outcome else {
            panic!("expected one CodeQL finding");
        };
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe_id, Some(89));
        assert_eq!(finding.appsec.provenance.rule_id.as_deref(), Some("js/sql-injection"));
        assert!(finding
            .appsec
            .provenance
            .config_identity
            .as_deref()
            .is_some_and(|identity| identity.contains("javascript-security-extended")));
        assert!(matches!(
            finding.appsec.location,
            ObservationLocation::Source { ref path, .. } if path == "src/query.js"
        ));
        let steps = &finding.appsec.code_flows[0].thread_flows[0].steps;
        assert_eq!(steps.len(), 3);
        assert!(matches!(
            steps[0].location,
            ObservationLocation::Source { ref path, .. } if path == "src/request.js"
        ));
        assert_eq!(steps[2].kinds, ["sink"]);
        assert!(!finding.appsec.evidence.is_empty());
    }

    #[test]
    fn codeql_descriptor_text_and_languages_are_exact() {
        assert_eq!(CodeqlModule.name(), "CodeQL Deep SAST");
        assert_eq!(
            CodeqlModule.description(),
            "Offline CodeQL security-extended analysis for supported no-build languages"
        );
        assert_eq!(CodeqlModule.languages(), ["javascript", "typescript", "python", "ruby"]);
    }
}
