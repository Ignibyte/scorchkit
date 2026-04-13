//! MCP resource implementations.
//!
//! Exposes `ScorchKit` project data as read-only browsable MCP resources.
//! Resources complement the tool interface by allowing MCP clients to
//! discover and browse project data without knowing which tools to call.
//!
//! # URI Scheme
//!
//! All resources use the `scorchkit://` protocol prefix:
//!
//! - `scorchkit://projects` — list all projects
//! - `scorchkit://projects/{id}` — single project details
//! - `scorchkit://projects/{id}/scans` — scan history
//! - `scorchkit://projects/{id}/scans/{scan_id}` — single scan
//! - `scorchkit://projects/{id}/findings` — tracked findings
//! - `scorchkit://projects/{id}/findings/{finding_id}` — single finding

use rmcp::model::{
    AnnotateAble, ListResourceTemplatesResult, ListResourcesResult, RawResource,
    RawResourceTemplate, ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
};
use uuid::Uuid;

use super::server::ScorchKitServer;
use crate::storage::{findings, projects, scans};

/// URI prefix for all `ScorchKit` resources.
const URI_PREFIX: &str = "scorchkit://";

/// Parsed resource URI identifying what data to return.
enum ResourceKind {
    /// List all projects.
    Projects,
    /// Single project by UUID.
    Project(Uuid),
    /// All scans for a project.
    ProjectScans(Uuid),
    /// Single scan by project UUID and scan UUID.
    Scan(Uuid, Uuid),
    /// All findings for a project.
    ProjectFindings(Uuid),
    /// Single finding by project UUID and finding UUID.
    Finding(Uuid, Uuid),
}

/// Parse a resource URI into a [`ResourceKind`].
///
/// Returns `None` if the URI does not match the `scorchkit://` scheme
/// or the path segments are not recognized.
fn parse_resource_uri(uri: &str) -> Option<ResourceKind> {
    let path = uri.strip_prefix(URI_PREFIX)?;
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match segments.as_slice() {
        ["projects"] => Some(ResourceKind::Projects),
        ["projects", id] => {
            let uuid = Uuid::parse_str(id).ok()?;
            Some(ResourceKind::Project(uuid))
        }
        ["projects", id, "scans"] => {
            let uuid = Uuid::parse_str(id).ok()?;
            Some(ResourceKind::ProjectScans(uuid))
        }
        ["projects", id, "scans", scan_id] => {
            let project_uuid = Uuid::parse_str(id).ok()?;
            let scan_uuid = Uuid::parse_str(scan_id).ok()?;
            Some(ResourceKind::Scan(project_uuid, scan_uuid))
        }
        ["projects", id, "findings"] => {
            let uuid = Uuid::parse_str(id).ok()?;
            Some(ResourceKind::ProjectFindings(uuid))
        }
        ["projects", id, "findings", finding_id] => {
            let project_uuid = Uuid::parse_str(id).ok()?;
            let finding_uuid = Uuid::parse_str(finding_id).ok()?;
            Some(ResourceKind::Finding(project_uuid, finding_uuid))
        }
        _ => None,
    }
}

/// Build a JSON text resource content for a given URI.
fn json_content(uri: &str, json: &str) -> ResourceContents {
    ResourceContents::text(json, uri).with_mime_type("application/json")
}

/// Build the static list of resource templates.
///
/// Templates describe parameterized URI patterns that clients can
/// fill in to access specific resources.
#[must_use]
fn resource_templates() -> Vec<ResourceTemplate> {
    vec![
        RawResourceTemplate::new("scorchkit://projects/{project_id}", "Project Details")
            .with_description("View a specific security assessment project")
            .with_mime_type("application/json")
            .no_annotation(),
        RawResourceTemplate::new("scorchkit://projects/{project_id}/scans", "Project Scans")
            .with_description("Scan history for a project")
            .with_mime_type("application/json")
            .no_annotation(),
        RawResourceTemplate::new(
            "scorchkit://projects/{project_id}/scans/{scan_id}",
            "Scan Details",
        )
        .with_description("View a specific scan record")
        .with_mime_type("application/json")
        .no_annotation(),
        RawResourceTemplate::new("scorchkit://projects/{project_id}/findings", "Project Findings")
            .with_description("Tracked vulnerability findings for a project")
            .with_mime_type("application/json")
            .no_annotation(),
        RawResourceTemplate::new(
            "scorchkit://projects/{project_id}/findings/{finding_id}",
            "Finding Details",
        )
        .with_description("View a specific vulnerability finding")
        .with_mime_type("application/json")
        .no_annotation(),
    ]
}

/// Convert a [`ScorchError`](crate::engine::error::ScorchError) into an
/// MCP JSON-RPC error for resource operations.
/// This function is used as a function pointer with `map_err(db_error)`,
/// which requires taking ownership of the error value.
#[allow(clippy::needless_pass_by_value)]
fn db_error(e: crate::engine::error::ScorchError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(format!("database error: {e}"), None)
}

/// Verify a project exists, returning a not-found error if absent.
async fn require_project(pool: &sqlx::PgPool, id: Uuid) -> Result<(), rmcp::ErrorData> {
    projects::get_project(pool, id).await.map_err(db_error)?.ok_or_else(|| {
        rmcp::ErrorData::resource_not_found(format!("project '{id}' not found"), None)
    })?;
    Ok(())
}

/// Serialize a value to pretty JSON, mapping errors to MCP internal errors.
fn to_json(value: &impl serde::Serialize) -> Result<String, rmcp::ErrorData> {
    serde_json::to_string_pretty(value)
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))
}

/// Public business logic methods for MCP resources.
impl ScorchKitServer {
    /// List all available resources.
    ///
    /// Returns a static `scorchkit://projects` collection resource plus
    /// one resource per project in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn do_list_resources(&self) -> Result<ListResourcesResult, rmcp::ErrorData> {
        let project_list = projects::list_projects(&self.pool).await.map_err(db_error)?;

        let mut resources: Vec<Resource> =
            vec![RawResource::new("scorchkit://projects", "All Projects")
                .with_description("List of all security assessment projects")
                .with_mime_type("application/json")
                .no_annotation()];

        for project in &project_list {
            let uri = format!("scorchkit://projects/{}", project.id);
            resources.push(
                RawResource::new(&uri, &project.name)
                    .with_description(if project.description.is_empty() {
                        format!("Project: {}", project.name)
                    } else {
                        project.description.clone()
                    })
                    .with_mime_type("application/json")
                    .with_timestamp(project.updated_at),
            );
        }

        Ok(ListResourcesResult::with_all_items(resources))
    }

    /// List all resource templates.
    ///
    /// Returns the static set of URI templates for parameterized
    /// resource access.
    #[must_use]
    pub fn do_list_resource_templates(&self) -> ListResourceTemplatesResult {
        ListResourceTemplatesResult::with_all_items(resource_templates())
    }

    /// Read a resource by URI.
    ///
    /// Parses the URI, fetches the requested data from the database,
    /// and returns it as JSON text content.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid, the requested resource
    /// does not exist, or the database query fails.
    pub async fn do_read_resource(&self, uri: &str) -> Result<ReadResourceResult, rmcp::ErrorData> {
        let kind = parse_resource_uri(uri).ok_or_else(|| {
            rmcp::ErrorData::invalid_params(format!("invalid resource URI: {uri}"), None)
        })?;

        let json = self.read_resource_json(&kind).await?;
        Ok(ReadResourceResult::new(vec![json_content(uri, &json)]))
    }

    /// Fetch the JSON content for a parsed resource kind.
    async fn read_resource_json(&self, kind: &ResourceKind) -> Result<String, rmcp::ErrorData> {
        match kind {
            ResourceKind::Projects => {
                let list = projects::list_projects(&self.pool).await.map_err(db_error)?;
                to_json(&list)
            }
            ResourceKind::Project(id) => {
                let project = projects::get_project(&self.pool, *id)
                    .await
                    .map_err(db_error)?
                    .ok_or_else(|| {
                        rmcp::ErrorData::resource_not_found(
                            format!("project '{id}' not found"),
                            None,
                        )
                    })?;
                let targets =
                    projects::list_targets(&self.pool, project.id).await.map_err(db_error)?;
                let scan_list =
                    scans::list_scans(&self.pool, project.id).await.map_err(db_error)?;
                let finding_list =
                    findings::list_findings(&self.pool, project.id).await.map_err(db_error)?;
                to_json(&serde_json::json!({
                    "project": project,
                    "targets": targets,
                    "scan_count": scan_list.len(),
                    "finding_count": finding_list.len(),
                    "recent_scans": scan_list.iter().take(5).collect::<Vec<_>>(),
                }))
            }
            ResourceKind::ProjectScans(project_id) => {
                require_project(&self.pool, *project_id).await?;
                let list = scans::list_scans(&self.pool, *project_id).await.map_err(db_error)?;
                to_json(&list)
            }
            ResourceKind::Scan(project_id, scan_id) => {
                require_project(&self.pool, *project_id).await?;
                let scan = scans::get_scan(&self.pool, *scan_id)
                    .await
                    .map_err(db_error)?
                    .ok_or_else(|| {
                        rmcp::ErrorData::resource_not_found(
                            format!("scan '{scan_id}' not found"),
                            None,
                        )
                    })?;
                to_json(&scan)
            }
            ResourceKind::ProjectFindings(project_id) => {
                require_project(&self.pool, *project_id).await?;
                let list =
                    findings::list_findings(&self.pool, *project_id).await.map_err(db_error)?;
                to_json(&list)
            }
            ResourceKind::Finding(project_id, finding_id) => {
                require_project(&self.pool, *project_id).await?;
                let finding = findings::get_finding(&self.pool, *finding_id)
                    .await
                    .map_err(db_error)?
                    .ok_or_else(|| {
                        rmcp::ErrorData::resource_not_found(
                            format!("finding '{finding_id}' not found"),
                            None,
                        )
                    })?;
                to_json(&finding)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test suite for resource URI parsing. Verifies that all supported
    /// URI patterns are correctly parsed into [`ResourceKind`] variants
    /// and that invalid URIs return `None`.

    /// Verify `scorchkit://projects` parses to [`ResourceKind::Projects`].
    #[test]
    fn parse_projects_uri() {
        let result = parse_resource_uri("scorchkit://projects");
        assert!(matches!(result, Some(ResourceKind::Projects)));
    }

    /// Verify `scorchkit://projects/{uuid}` parses to [`ResourceKind::Project`].
    #[test]
    fn parse_single_project_uri() {
        let id = Uuid::new_v4();
        let uri = format!("scorchkit://projects/{id}");
        let result = parse_resource_uri(&uri);
        assert!(matches!(result, Some(ResourceKind::Project(parsed_id)) if parsed_id == id));
    }

    /// Verify `scorchkit://projects/{uuid}/scans` parses to
    /// [`ResourceKind::ProjectScans`].
    #[test]
    fn parse_project_scans_uri() {
        let id = Uuid::new_v4();
        let uri = format!("scorchkit://projects/{id}/scans");
        let result = parse_resource_uri(&uri);
        assert!(matches!(result, Some(ResourceKind::ProjectScans(parsed_id)) if parsed_id == id));
    }

    /// Verify `scorchkit://projects/{uuid}/scans/{uuid}` parses to
    /// [`ResourceKind::Scan`] with both UUIDs preserved.
    #[test]
    fn parse_single_scan_uri() {
        let project_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let uri = format!("scorchkit://projects/{project_id}/scans/{scan_id}");
        let result = parse_resource_uri(&uri);
        assert!(
            matches!(result, Some(ResourceKind::Scan(pid, sid)) if pid == project_id && sid == scan_id)
        );
    }

    /// Verify `scorchkit://projects/{uuid}/findings` parses to
    /// [`ResourceKind::ProjectFindings`].
    #[test]
    fn parse_project_findings_uri() {
        let id = Uuid::new_v4();
        let uri = format!("scorchkit://projects/{id}/findings");
        let result = parse_resource_uri(&uri);
        assert!(
            matches!(result, Some(ResourceKind::ProjectFindings(parsed_id)) if parsed_id == id)
        );
    }

    /// Verify `scorchkit://projects/{uuid}/findings/{uuid}` parses to
    /// [`ResourceKind::Finding`] with both UUIDs preserved.
    #[test]
    fn parse_single_finding_uri() {
        let project_id = Uuid::new_v4();
        let finding_id = Uuid::new_v4();
        let uri = format!("scorchkit://projects/{project_id}/findings/{finding_id}");
        let result = parse_resource_uri(&uri);
        assert!(
            matches!(result, Some(ResourceKind::Finding(pid, fid)) if pid == project_id && fid == finding_id)
        );
    }

    /// Verify invalid or unrecognized URIs return `None` instead of
    /// panicking — covers wrong scheme, unknown paths, and invalid UUIDs.
    #[test]
    fn parse_invalid_uri_returns_none() {
        assert!(parse_resource_uri("http://example.com").is_none());
        assert!(parse_resource_uri("scorchkit://unknown").is_none());
        assert!(parse_resource_uri("scorchkit://projects/not-a-uuid").is_none());
        assert!(parse_resource_uri("").is_none());
    }

    /// Verify [`resource_templates`] returns exactly 5 templates
    /// matching the designed URI scheme.
    #[test]
    fn templates_returns_five() {
        let templates = resource_templates();
        assert_eq!(templates.len(), 5, "expected 5 resource templates");
    }

    /// Verify each resource template has all required fields populated:
    /// URI template, name, and description.
    #[test]
    fn templates_have_required_fields() {
        for template in resource_templates() {
            assert!(!template.raw.uri_template.is_empty(), "template URI must not be empty");
            assert!(!template.raw.name.is_empty(), "template name must not be empty");
            assert!(template.raw.description.is_some(), "template description must be set");
        }
    }
}
