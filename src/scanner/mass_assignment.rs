//! Mass assignment scanner module.
//!
//! Detects mass assignment (over-posting) vulnerabilities by injecting extra
//! privileged fields (`role`, `isAdmin`, `price`, etc.) into POST/PUT JSON
//! request bodies and checking if they are accepted or reflected.

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects mass assignment (over-posting) vulnerabilities.
#[derive(Debug)]
pub struct MassAssignmentModule;

#[async_trait]
impl ScanModule for MassAssignmentModule {
    fn name(&self) -> &'static str {
        "Mass Assignment Detection"
    }

    fn id(&self) -> &'static str {
        "mass_assignment"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect mass assignment via extra privileged field injection in JSON bodies"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        test_mass_assignment(ctx, url, &mut findings).await?;

        Ok(findings)
    }
}

/// Privileged fields to inject for mass assignment testing.
const PRIVILEGED_FIELDS: &[(&str, &str, &str)] = &[
    ("role", "\"admin\"", "Role escalation"),
    ("isAdmin", "true", "Admin flag"),
    ("is_admin", "true", "Admin flag (snake_case)"),
    ("admin", "true", "Admin boolean"),
    ("is_staff", "true", "Staff flag"),
    ("is_superuser", "true", "Superuser flag"),
    ("permissions", "[\"admin\"]", "Permissions array"),
    ("price", "0", "Price manipulation"),
    ("discount", "100", "Discount manipulation"),
    ("verified", "true", "Account verification bypass"),
    ("email_verified", "true", "Email verification bypass"),
    ("active", "true", "Account activation bypass"),
];

/// Check if a privileged field name appears in the response, suggesting
/// the server accepted or processed the injected field.
fn check_field_reflected(body: &str, field_name: &str) -> bool {
    let lower = body.to_lowercase();
    let field_lower = field_name.to_lowercase();

    // Check for JSON key reflection: "field_name":
    lower.contains(&format!("\"{field_lower}\":"))
        || lower.contains(&format!("\"{field_lower}\" :"))
}

/// Test mass assignment by injecting privileged fields.
async fn test_mass_assignment(
    ctx: &ScanContext,
    url_str: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    // Get baseline POST response
    let Ok(baseline) = ctx
        .http_client
        .post(url_str)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
    else {
        return Ok(());
    };

    let baseline_body = baseline.text().await.unwrap_or_default();

    // Test each privileged field
    for &(field_name, field_value, description) in PRIVILEGED_FIELDS {
        // Skip if field already naturally appears in baseline
        if check_field_reflected(&baseline_body, field_name) {
            continue;
        }

        let payload = format!("{{\"{field_name}\":{field_value}}}");

        let Ok(response) = ctx
            .http_client
            .post(url_str)
            .header("Content-Type", "application/json")
            .body(payload.clone())
            .send()
            .await
        else {
            continue;
        };

        let resp_body = response.text().await.unwrap_or_default();

        if check_field_reflected(&resp_body, field_name) {
            let severity = if field_name.contains("admin")
                || field_name.contains("role")
                || field_name.contains("superuser")
                || field_name.contains("permission")
            {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(
                Finding::new(
                    "mass_assignment",
                    severity,
                    format!("Mass Assignment: {description} via `{field_name}`"),
                    format!(
                        "The server accepted and reflected the privileged field \
                         `{field_name}` when injected into a JSON POST body. This \
                         suggests the application binds request data to internal \
                         objects without proper field filtering ({description}).",
                    ),
                    url_str,
                )
                .with_evidence(format!(
                    "Payload: {payload} | Field `{field_name}` reflected in response"
                ))
                .with_remediation(
                    "Use allowlists to specify which fields can be mass-assigned. \
                     Never bind raw request data to internal models. Use DTOs \
                     (Data Transfer Objects) to control which fields are accepted.",
                )
                .with_owasp("A04:2021 Insecure Design")
                .with_cwe(915)
                .with_confidence(0.6),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests for the mass assignment scanner module.

    /// Verify module metadata.
    #[test]
    fn test_module_metadata_mass_assignment() {
        let module = MassAssignmentModule;
        assert_eq!(module.id(), "mass_assignment");
        assert_eq!(module.name(), "Mass Assignment Detection");
        assert_eq!(module.category(), ModuleCategory::Scanner);
        assert!(!module.description().is_empty());
    }

    /// Verify privileged fields database is non-empty.
    #[test]
    fn test_privileged_fields_not_empty() {
        assert!(!PRIVILEGED_FIELDS.is_empty());
        for (i, &(name, val, desc)) in PRIVILEGED_FIELDS.iter().enumerate() {
            assert!(!name.is_empty(), "field {i} has empty name");
            assert!(!val.is_empty(), "field {i} has empty value");
            assert!(!desc.is_empty(), "field {i} has empty description");
        }
    }

    /// Verify field reflection detection.
    #[test]
    fn test_check_field_reflected() {
        assert!(check_field_reflected(r#"{"isAdmin": true, "name": "test"}"#, "isAdmin"));
        assert!(check_field_reflected(r#"{"role":"admin"}"#, "role"));
        assert!(!check_field_reflected("<html><body>Normal</body></html>", "isAdmin"));
    }

    /// Verify fields cover privilege escalation and business logic categories.
    #[test]
    fn test_privileged_fields_coverage() {
        let names: Vec<&str> = PRIVILEGED_FIELDS.iter().map(|&(n, _, _)| n).collect();
        assert!(names.iter().any(|n| n.contains("admin")), "must cover admin fields");
        assert!(names.iter().any(|n| n.contains("role")), "must cover role fields");
        assert!(
            names.iter().any(|n| *n == "price" || *n == "discount"),
            "must cover business logic fields"
        );
    }
}
