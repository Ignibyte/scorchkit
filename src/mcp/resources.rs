//! MCP resource implementations.
//!
//! Exposes `ScorchKit` project data as read-only browsable MCP resources.
//! Resources complement the tool interface by allowing MCP clients to
//! discover and browse project data without knowing which tools to call.
//!
//! # URI Scheme
//!
//! Project resources use the `scorchkit://` protocol prefix. The optional conversation-native
//! workbench uses the MCP Apps `ui://` scheme:
//!
//! - `scorchkit://projects` — list all projects
//! - `scorchkit://projects/{id}` — single project details
//! - `scorchkit://projects/{id}/scans` — scan history
//! - `scorchkit://projects/{id}/scans/{scan_id}` — single scan
//! - `scorchkit://projects/{id}/findings` — tracked findings
//! - `scorchkit://projects/{id}/findings/{finding_id}` — single finding
//! - `ui://scorchkit/conversation-workbench/v1` — self-contained conversation workbench

use rmcp::model::{
    AnnotateAble, JsonObject, ListResourceTemplatesResult, ListResourcesResult, Meta, RawResource,
    RawResourceTemplate, ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
};
use serde_json::Value;
use uuid::Uuid;

use super::server::ScorchKitServer;
use crate::storage::{findings, projects, scans};
use scorchkit_control::{ControlQueryV1, ControlRequestV1, ControlResultV1, PageRequestV1};
use scorchkit_mcp::contract::{CONVERSATION_WORKBENCH_RESOURCE_URI, MCP_UI_RESOURCE_MIME};

/// URI prefix for all `ScorchKit` resources.
const URI_PREFIX: &str = "scorchkit://";

const CONVERSATION_WORKBENCH_HTML: &str = include_str!("conversation-workbench.html");

/// Parsed resource URI identifying what data to return.
enum ResourceKind {
    /// Self-contained optional MCP Apps conversation workbench.
    ConversationWorkbench,
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
/// Returns `None` if the URI is not the exact workbench URI and does not match a recognized
/// `scorchkit://` path.
fn parse_resource_uri(uri: &str) -> Option<ResourceKind> {
    if uri == CONVERSATION_WORKBENCH_RESOURCE_URI {
        return Some(ResourceKind::ConversationWorkbench);
    }
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

fn conversation_workbench_meta() -> Meta {
    let mut csp = JsonObject::new();
    for key in ["connectDomains", "resourceDomains", "frameDomains", "baseUriDomains"] {
        csp.insert(key.to_string(), Value::Array(Vec::new()));
    }
    let mut ui = JsonObject::new();
    ui.insert("prefersBorder".to_string(), Value::Bool(true));
    ui.insert("csp".to_string(), Value::Object(csp));
    let mut meta = JsonObject::new();
    meta.insert("ui".to_string(), Value::Object(ui));
    Meta(meta)
}

fn conversation_workbench_resource() -> Resource {
    let mut resource =
        RawResource::new(CONVERSATION_WORKBENCH_RESOURCE_URI, "ScorchKit Conversation Workbench")
            .with_title("ScorchKit Security Workbench")
            .with_description("Optional posture, finding evidence, triage, and attack-path views")
            .with_mime_type(MCP_UI_RESOURCE_MIME)
            .with_meta(conversation_workbench_meta());
    resource.size = u32::try_from(CONVERSATION_WORKBENCH_HTML.len()).ok();
    resource.no_annotation()
}

fn conversation_workbench_content() -> ResourceContents {
    ResourceContents::text(CONVERSATION_WORKBENCH_HTML, CONVERSATION_WORKBENCH_RESOURCE_URI)
        .with_mime_type(MCP_UI_RESOURCE_MIME)
        .with_meta(conversation_workbench_meta())
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
// JUSTIFICATION: map_err requires this exact by-value function-pointer signature.
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
    /// Always returns the database-free conversation workbench. When a database is attached, also
    /// returns the static `scorchkit://projects` collection and one resource per project.
    ///
    /// # Errors
    ///
    /// Returns an error if an attached database query fails.
    pub async fn do_list_resources(&self) -> Result<ListResourcesResult, rmcp::ErrorData> {
        let mut resources = vec![conversation_workbench_resource()];
        let Some(pool) = self.pool.as_ref() else {
            return Ok(ListResourcesResult::with_all_items(resources));
        };
        let project_list = projects::list_projects(pool).await.map_err(db_error)?;

        resources.push(
            RawResource::new("scorchkit://projects", "All Projects")
                .with_description("List of all security assessment projects")
                .with_mime_type("application/json")
                .no_annotation(),
        );

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

        if matches!(kind, ResourceKind::ConversationWorkbench) {
            return Ok(ReadResourceResult::new(vec![conversation_workbench_content()]));
        }

        let json = self.read_resource_json(&kind).await?;
        Ok(ReadResourceResult::new(vec![json_content(uri, &json)]))
    }

    /// Fetch the JSON content for a parsed resource kind.
    async fn read_resource_json(&self, kind: &ResourceKind) -> Result<String, rmcp::ErrorData> {
        let pool = self.pool.as_ref().ok_or_else(|| {
            rmcp::ErrorData::internal_error(
                "database unavailable: project resources require an attached database",
                None,
            )
        })?;
        match kind {
            ResourceKind::ConversationWorkbench => Err(rmcp::ErrorData::internal_error(
                "conversation workbench must be read through its static resource path",
                None,
            )),
            ResourceKind::Projects => {
                let list = projects::list_projects(pool).await.map_err(db_error)?;
                to_json(&list)
            }
            ResourceKind::Project(id) => {
                let project =
                    projects::get_project(pool, *id).await.map_err(db_error)?.ok_or_else(|| {
                        rmcp::ErrorData::resource_not_found(
                            format!("project '{id}' not found"),
                            None,
                        )
                    })?;
                let targets = projects::list_targets(pool, project.id).await.map_err(db_error)?;
                let scan_list = scans::list_scans(pool, project.id).await.map_err(db_error)?;
                let finding_list =
                    findings::list_findings(pool, project.id).await.map_err(db_error)?;
                to_json(&serde_json::json!({
                    "project": project,
                    "targets": targets,
                    "scan_count": scan_list.len(),
                    "finding_count": finding_list.len(),
                    "recent_scans": scan_list.iter().take(5).collect::<Vec<_>>(),
                }))
            }
            ResourceKind::ProjectScans(project_id) => {
                require_project(pool, *project_id).await?;
                let list = scans::list_scans(pool, *project_id).await.map_err(db_error)?;
                to_json(&list)
            }
            ResourceKind::Scan(project_id, scan_id) => {
                require_project(pool, *project_id).await?;
                let scan =
                    scans::get_scan(pool, *scan_id).await.map_err(db_error)?.ok_or_else(|| {
                        rmcp::ErrorData::resource_not_found(
                            format!("scan '{scan_id}' not found"),
                            None,
                        )
                    })?;
                to_json(&scan)
            }
            ResourceKind::ProjectFindings(project_id) => {
                require_project(pool, *project_id).await?;
                let list = self.control_resource_findings(*project_id).await?;
                to_json(&list)
            }
            ResourceKind::Finding(project_id, finding_id) => {
                require_project(pool, *project_id).await?;
                let belongs_to_project = findings::get_finding(pool, *finding_id)
                    .await
                    .map_err(db_error)?
                    .is_some_and(|finding| finding.project_id == *project_id);
                if !belongs_to_project {
                    return Err(rmcp::ErrorData::resource_not_found(
                        format!("finding '{finding_id}' not found"),
                        None,
                    ));
                }
                let result = self
                    .execute_control(ControlRequestV1::query(
                        ControlQueryV1::GetFinding { id: *finding_id },
                        self.config.engagement.as_ref().map(|engagement| engagement.id),
                    ))
                    .await
                    .map_err(control_resource_error)?;
                let ControlResultV1::Finding(finding) = result else {
                    return Err(rmcp::ErrorData::internal_error(
                        "control service returned an unexpected finding resource",
                        None,
                    ));
                };
                to_json(&finding)
            }
        }
    }

    async fn control_resource_findings(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<scorchkit_control::FindingViewV1>, rmcp::ErrorData> {
        let mut findings = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .execute_control(ControlRequestV1::query(
                    ControlQueryV1::ListFindings {
                        project_id,
                        page: PageRequestV1 {
                            cursor,
                            limit: self.config.control_api.default_page_size,
                        },
                    },
                    self.config.engagement.as_ref().map(|engagement| engagement.id),
                ))
                .await
                .map_err(control_resource_error)?;
            let ControlResultV1::Findings(page) = result else {
                return Err(rmcp::ErrorData::internal_error(
                    "control service returned an unexpected finding resource page",
                    None,
                ));
            };
            findings.extend(page.items);
            if findings.len() > 10_000 {
                return Err(rmcp::ErrorData::internal_error(
                    "finding resource exceeds the bounded 10000-item compatibility limit",
                    None,
                ));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(findings);
            }
        }
    }
}

fn control_resource_error(message: String) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(message, None)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{TimeZone, Utc};
    use scorchkit_control::{
        FindingTriageSubjectViewV1, FindingTriageViewV1, FindingViewV1, PageV1,
    };

    use super::*;

    fn finding_view() -> FindingViewV1 {
        let id = Uuid::from_u128(1);
        let at = Utc.with_ymd_and_hms(2026, 8, 24, 0, 0, 0).single().unwrap_or_else(Utc::now);
        FindingViewV1 {
            id,
            project_id: id,
            scan_id: id,
            fingerprint: "fixture".to_string(),
            identity_schema: "scorchkit.finding-identity/v2".to_string(),
            stable_identity: "a".repeat(64),
            correlation_keys: serde_json::json!([]),
            status: "new".to_string(),
            status_note: None,
            seen_count: 1,
            first_seen: at,
            last_seen: at,
            found_at: at,
            canonical: serde_json::json!({}),
            triage: Box::new(FindingTriageViewV1 {
                schema: "scorchkit.finding-triage/v1".to_string(),
                current_state: "needs_context".to_string(),
                subject: FindingTriageSubjectViewV1 {
                    project_identity: id.to_string(),
                    finding_identity: "a".repeat(64),
                    rule_identity: None,
                    target_identity: "b".repeat(64),
                },
                transitions: Vec::new(),
                correlations: Vec::new(),
                suppressions: Vec::new(),
                active_suppression_ids: Vec::new(),
            }),
        }
    }

    fn finding_pages(page_count: usize, overflow: bool) -> Vec<Result<ControlResultV1, String>> {
        let finding = finding_view();
        let mut pages = (0..page_count)
            .map(|index| {
                Ok(ControlResultV1::Findings(PageV1 {
                    items: vec![finding.clone(); 200],
                    next_cursor: (index + 1 < page_count || overflow)
                        .then(|| format!("page-{}", index + 1)),
                }))
            })
            .collect::<Vec<_>>();
        if overflow {
            pages.push(Ok(ControlResultV1::Findings(PageV1 {
                items: vec![finding],
                next_cursor: None,
            })));
        }
        pages
    }

    // Test suite for resource URI parsing. Verifies that all supported
    // URI patterns are correctly parsed into [`ResourceKind`] variants
    // and that invalid URIs return `None`.

    /// Verify `scorchkit://projects` parses to [`ResourceKind::Projects`].
    #[test]
    fn parse_projects_uri() {
        let result = parse_resource_uri("scorchkit://projects");
        assert!(matches!(result, Some(ResourceKind::Projects)));
    }

    #[test]
    fn parse_conversation_workbench_uri_is_exact() {
        assert!(matches!(
            parse_resource_uri(CONVERSATION_WORKBENCH_RESOURCE_URI),
            Some(ResourceKind::ConversationWorkbench)
        ));
        assert!(parse_resource_uri("ui://scorchkit/conversation-workbench/v2").is_none());
        assert!(parse_resource_uri("ui://scorchkit/conversation-workbench/v1/extra").is_none());
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

    #[test]
    fn control_resource_errors_preserve_safe_messages() {
        let mapped = control_resource_error("safe control failure".to_string());
        assert!(mapped.message.contains("safe control failure"));
    }

    #[tokio::test]
    async fn stateless_server_lists_and_reads_the_self_contained_workbench() {
        let server = ScorchKitServer::new_stateless(Arc::new(crate::config::AppConfig::default()));
        let listed = server.do_list_resources().await.expect("list stateless resources");
        assert_eq!(listed.resources.len(), 1);
        let resource = &listed.resources[0];
        assert_eq!(resource.raw.uri, CONVERSATION_WORKBENCH_RESOURCE_URI);
        assert_eq!(resource.raw.mime_type.as_deref(), Some(MCP_UI_RESOURCE_MIME));
        assert_eq!(resource.raw.size, u32::try_from(CONVERSATION_WORKBENCH_HTML.len()).ok());
        assert!(CONVERSATION_WORKBENCH_HTML.len() < 96 * 1024);

        let metadata = serde_json::to_value(resource).expect("serialize UI resource");
        let ui = &metadata["_meta"]["ui"];
        assert_eq!(ui["prefersBorder"], true);
        for key in ["connectDomains", "resourceDomains", "frameDomains", "baseUriDomains"] {
            assert_eq!(ui["csp"][key], serde_json::json!([]));
        }
        assert!(ui.get("permissions").is_none());

        let read = server
            .do_read_resource(CONVERSATION_WORKBENCH_RESOURCE_URI)
            .await
            .expect("read stateless workbench");
        let ResourceContents::TextResourceContents { uri, mime_type, text, meta } =
            &read.contents[0]
        else {
            panic!("workbench must be a text resource");
        };
        assert_eq!(uri, CONVERSATION_WORKBENCH_RESOURCE_URI);
        assert_eq!(mime_type.as_deref(), Some(MCP_UI_RESOURCE_MIME));
        assert_eq!(text, CONVERSATION_WORKBENCH_HTML);
        assert!(text.starts_with("<!doctype html>"));
        assert!(meta.is_some());
    }

    #[test]
    fn workbench_consumes_the_exact_canonical_projection_paths() {
        for projection in [
            "findings.total_findings",
            "findings.active_findings",
            "findings.resolved_findings",
            "scans.total_scans",
            "scans.scans_last_30_days",
            "raw.appsec",
            "appsec.evidence",
            "appsec.agent_analysis",
        ] {
            assert!(
                CONVERSATION_WORKBENCH_HTML.contains(projection),
                "workbench lost canonical projection path {projection}"
            );
        }
    }

    #[tokio::test]
    async fn finding_resource_accepts_exactly_ten_thousand_and_rejects_one_more() {
        let exact = ScorchKitServer::new_stateless(Arc::new(crate::config::AppConfig::default()))
            .with_control_results(finding_pages(50, false));
        assert_eq!(
            exact
                .control_resource_findings(Uuid::from_u128(1))
                .await
                .expect("exact finding resource bound")
                .len(),
            10_000
        );

        let overflow =
            ScorchKitServer::new_stateless(Arc::new(crate::config::AppConfig::default()))
                .with_control_results(finding_pages(50, true));
        let error = overflow
            .control_resource_findings(Uuid::from_u128(1))
            .await
            .expect_err("finding resource overflow");
        assert!(error.message.contains("10000-item compatibility limit"));
    }
}
