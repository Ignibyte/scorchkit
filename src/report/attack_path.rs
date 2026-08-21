//! Security-safe projections of canonical source-to-runtime attack paths.

use std::fmt::Write;

use crate::engine::attack_path::{
    AttackPathCorrelation, AttackPathCorrelationStatus, ATTACK_PATH_CORRELATION_SCHEMA_V1,
};
use crate::engine::observation::{redact_text, redact_url};

/// Projection error for a malformed canonical contract or JSON failure.
#[derive(Debug)]
pub enum AttackPathReportError {
    /// The supplied correlation or nested path violates the canonical contract.
    NonCanonical(&'static str),
    /// JSON serialization failed.
    Json(serde_json::Error),
}

impl std::fmt::Display for AttackPathReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonical(reason) => write!(formatter, "non-canonical attack paths: {reason}"),
            Self::Json(error) => write!(formatter, "attack-path JSON failure: {error}"),
        }
    }
}

impl std::error::Error for AttackPathReportError {}

impl From<serde_json::Error> for AttackPathReportError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Render the complete versioned correlation contract as redacted, pretty JSON.
///
/// # Errors
///
/// Returns an error if the canonical contract cannot be serialized.
pub fn render_attack_paths_json(
    correlation: &AttackPathCorrelation,
) -> Result<String, AttackPathReportError> {
    validate_correlation(correlation)?;
    let mut value = serde_json::to_value(correlation)?;
    redact_json_strings(&mut value);
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Render a terminal-safe summary followed by the complete canonical JSON projection.
#[must_use]
pub fn format_attack_paths(correlation: &AttackPathCorrelation) -> String {
    let json = match render_attack_paths_json(correlation) {
        Ok(json) => json,
        Err(error) => {
            return format!(
                "Attack-path report unavailable: {}\n",
                safe_inline(&error.to_string())
            );
        }
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Attack paths: {} | status: {} | schema: {}",
        correlation.paths.len(),
        correlation_status(correlation.status),
        safe_inline(&correlation.schema)
    );
    for path in &correlation.paths {
        let _ = writeln!(
            out,
            "- {} | {} | severity {} | confidence {}",
            safe_inline(&path.identity.value),
            path.state.as_str(),
            path.severity,
            path.path_confidence
        );
    }
    out.push_str("\nCanonical record:\n");
    out.push_str(&json);
    out.push('\n');
    out
}

/// Render an escaped Mermaid flowchart without embedding executable HTML or arbitrary node IDs.
///
/// # Errors
///
/// Returns an error if the correlation or a nested path is non-canonical.
pub fn render_attack_paths_mermaid(
    correlation: &AttackPathCorrelation,
) -> Result<String, AttackPathReportError> {
    validate_correlation(correlation)?;
    let mut out = String::from("flowchart LR\n");
    for (path_index, path) in correlation.paths.iter().enumerate() {
        let path_node = format!("path_{path_index}");
        let identity = path.identity.value.get(..12).unwrap_or(&path.identity.value);
        let label = mermaid_label(&format!("{} {}", path.state.as_str(), identity));
        let _ = writeln!(out, "  {path_node}[\"{label}\"]");
        for (member_index, member) in path.members.iter().enumerate() {
            let member_node = format!("path_{path_index}_member_{member_index}");
            let member_label = mermaid_label(&format!(
                "{} {}",
                member.role.as_str(),
                safe_inline(&member.module_id)
            ));
            let _ = writeln!(out, "  {member_node}[\"{member_label}\"]");
            let _ = writeln!(out, "  {member_node} --> {path_node}");
        }
    }
    Ok(out)
}

fn validate_correlation(correlation: &AttackPathCorrelation) -> Result<(), AttackPathReportError> {
    if correlation.schema != ATTACK_PATH_CORRELATION_SCHEMA_V1 {
        return Err(AttackPathReportError::NonCanonical("correlation schema"));
    }
    if !correlation
        .paths
        .windows(2)
        .all(|window| window[0].identity.value < window[1].identity.value)
        || !correlation.gaps.windows(2).all(|window| window[0] < window[1])
    {
        return Err(AttackPathReportError::NonCanonical("ordering or duplicate identity"));
    }
    if (correlation.status == AttackPathCorrelationStatus::Complete) != correlation.gaps.is_empty()
    {
        return Err(AttackPathReportError::NonCanonical("status and coverage gaps disagree"));
    }
    if correlation.paths.iter().any(|path| path.validate().is_err()) {
        return Err(AttackPathReportError::NonCanonical("nested path validation"));
    }
    Ok(())
}

const fn correlation_status(status: AttackPathCorrelationStatus) -> &'static str {
    match status {
        AttackPathCorrelationStatus::Complete => "complete",
        AttackPathCorrelationStatus::Incomplete => "incomplete",
    }
}

fn redact_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = safe_string(text),
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json_strings),
        serde_json::Value::Object(values) => values.values_mut().for_each(redact_json_strings),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn safe_string(value: &str) -> String {
    let (url, _) = redact_url(value);
    redact_text(&url)
}

fn safe_inline(value: &str) -> String {
    safe_string(value)
        .chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .collect()
}

fn mermaid_label(value: &str) -> String {
    safe_inline(value)
        .chars()
        .map(|character| match character {
            '"' | '\\' | '`' | '<' | '>' | '&' | '[' | ']' | '{' | '}' | '|' | ';' => ' ',
            _ => character,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::attack_path::{
        correlate_attack_paths, AttackPathCorrelationGap, AttackPathCorrelationGapKind,
    };
    use crate::engine::finding::Finding;
    use crate::engine::observation::{CorrelationKey, ObservationLocation};
    use crate::engine::severity::Severity;

    fn reachable_correlation() -> AttackPathCorrelation {
        let source = Finding::new("semgrep", Severity::High, "rule", "desc", "src/app.rs:7")
            .with_location(ObservationLocation::Source {
                path: "src/app.rs".to_string(),
                region: None,
            })
            .with_correlation_key(CorrelationKey::new("route", "/users"));
        let runtime =
            Finding::new("nuclei", Severity::High, "probe", "desc", "https://example.test/users")
                .with_location(ObservationLocation::Runtime {
                    uri: "https://example.test/users".to_string(),
                    route: Some("/users".to_string()),
                    parameter: None,
                });
        correlate_attack_paths(&[source, runtime])
    }

    fn two_path_correlation() -> AttackPathCorrelation {
        let mut findings = Vec::new();
        for (route, cwe) in [("/alpha", 89), ("/beta", 79)] {
            findings.push(
                Finding::new("semgrep", Severity::High, "rule", "desc", "src/app.rs:7")
                    .with_location(ObservationLocation::Source {
                        path: format!("src{route}.rs"),
                        region: None,
                    })
                    .with_cwe(cwe)
                    .with_correlation_key(CorrelationKey::new("route", route)),
            );
            findings.push(
                Finding::new(
                    "nuclei",
                    Severity::High,
                    "probe",
                    "desc",
                    format!("https://example.test{route}"),
                )
                .with_location(ObservationLocation::Runtime {
                    uri: format!("https://example.test{route}"),
                    route: Some(route.to_string()),
                    parameter: None,
                })
                .with_cwe(cwe),
            );
        }
        let correlation = correlate_attack_paths(&findings);
        assert_eq!(correlation.paths.len(), 2);
        correlation
    }

    #[test]
    fn json_and_text_preserve_the_canonical_contract() {
        let correlation = reachable_correlation();
        let json = render_attack_paths_json(&correlation).expect("render JSON");
        let restored: AttackPathCorrelation = serde_json::from_str(&json).expect("decode JSON");
        assert_eq!(restored, correlation);
        let text = format_attack_paths(&correlation);
        assert!(text.contains(&correlation.paths[0].identity.value));
        assert!(text.contains("Canonical record:"));
    }

    #[test]
    fn terminal_and_mermaid_outputs_neutralize_control_and_syntax_injection() {
        let hostile = "evil\u{1b}[31m\"]\nclick node callback";
        let text = safe_inline(hostile);
        let label = mermaid_label(hostile);
        assert!(!text.contains('\u{1b}'));
        assert!(!label.contains('\u{1b}'));
        assert!(!label.contains('\n'));
        assert!(!label.contains('"'));
        assert!(!label.contains('\\'));
        let mermaid = render_attack_paths_mermaid(&reachable_correlation())
            .expect("render canonical Mermaid");
        assert!(mermaid.starts_with("flowchart LR"));
    }

    #[test]
    fn json_projection_redacts_mutated_secret_values() {
        let redacted = safe_string("api_key=fixture-secret");
        assert!(!redacted.contains("fixture-secret"));
        assert!(redacted.contains("REDACTED"));
    }

    #[test]
    fn every_projection_rejects_a_tampered_path() {
        let mut correlation = reachable_correlation();
        correlation.paths[0].state = crate::engine::attack_path::AttackPathState::Reproduced;
        assert!(render_attack_paths_json(&correlation).is_err());
        assert!(format_attack_paths(&correlation).contains("report unavailable"));
        assert!(render_attack_paths_mermaid(&correlation).is_err());
    }

    #[test]
    fn correlation_projection_checks_path_and_gap_order_independently() {
        let ordered = two_path_correlation();
        assert!(validate_correlation(&ordered).is_ok());

        let mut reversed = ordered.clone();
        reversed.paths.reverse();
        assert!(validate_correlation(&reversed).is_err());
        let mut duplicate = ordered;
        duplicate.paths[1] = duplicate.paths[0].clone();
        assert!(validate_correlation(&duplicate).is_err());

        let mut gaps = reachable_correlation();
        gaps.status = AttackPathCorrelationStatus::Incomplete;
        gaps.gaps = vec![
            AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::FindingLimitExceeded,
                finding_identity: None,
            },
            AttackPathCorrelationGap {
                kind: AttackPathCorrelationGapKind::PathLimitExceeded,
                finding_identity: None,
            },
        ];
        gaps.gaps.sort();
        assert!(validate_correlation(&gaps).is_ok());
        gaps.gaps.reverse();
        assert!(validate_correlation(&gaps).is_err());
        gaps.gaps[1] = gaps.gaps[0].clone();
        assert!(validate_correlation(&gaps).is_err());
    }
}
