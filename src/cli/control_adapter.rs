//! Shared local CLI adapter over the provider-neutral control service.

use std::sync::Arc;

use uuid::Uuid;

use crate::config::AppConfig;
use crate::control::ControlService;
use crate::engine::error::{Result, ScorchError};
use scorchkit_control::{
    ControlCommandV1, ControlQueryV1, ControlRequestV1, ControlResponseOutcomeV1, ControlResultV1,
    FindingViewV1, PageRequestV1, ProjectViewV1, TargetViewV1,
};

const MAX_COMPATIBILITY_ITEMS: usize = 10_000;

/// Process-local CLI client that has no direct canonical storage reader.
pub(super) struct LocalControlClient {
    service: ControlService,
    engagement_id: Option<Uuid>,
    page_size: u16,
}

impl LocalControlClient {
    #[must_use]
    pub(super) fn new(config: &Arc<AppConfig>, service: ControlService) -> Self {
        Self {
            service,
            engagement_id: config.engagement.as_ref().map(|engagement| engagement.id),
            page_size: config.control_api.default_page_size,
        }
    }

    pub(super) async fn query(&self, query: ControlQueryV1) -> Result<ControlResultV1> {
        let response =
            self.service.execute_local(ControlRequestV1::query(query, self.engagement_id)).await;
        response_result(response.result)
    }

    pub(super) async fn command(&self, command: ControlCommandV1) -> Result<ControlResultV1> {
        let engagement_id = self.engagement_id.ok_or_else(|| {
            ScorchError::Config("control CLI command requires an active engagement".to_string())
        })?;
        let response =
            self.service.execute_local(ControlRequestV1::command(command, engagement_id)).await;
        response_result(response.result)
    }

    pub(super) async fn projects(&self) -> Result<Vec<ProjectViewV1>> {
        let mut values = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .query(ControlQueryV1::ListProjects {
                    page: PageRequestV1 { cursor, limit: self.page_size },
                })
                .await?;
            let ControlResultV1::Projects(page) = result else {
                return Err(unexpected("project page"));
            };
            append_bounded(&mut values, page.items, "project")?;
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(values);
            }
        }
    }

    pub(super) async fn project(&self, reference: &str) -> Result<ProjectViewV1> {
        if let Ok(id) = Uuid::parse_str(reference) {
            let result = self.query(ControlQueryV1::GetProject { id }).await?;
            let ControlResultV1::Project(project) = result else {
                return Err(unexpected("project"));
            };
            return Ok(project);
        }
        self.projects()
            .await?
            .into_iter()
            .find(|project| project.name == reference)
            .ok_or_else(|| ScorchError::Config(format!("project '{reference}' not found")))
    }

    pub(super) async fn targets(&self, project_id: Uuid) -> Result<Vec<TargetViewV1>> {
        let mut values = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .query(ControlQueryV1::ListTargets {
                    project_id,
                    page: PageRequestV1 { cursor, limit: self.page_size },
                })
                .await?;
            let ControlResultV1::Targets(page) = result else {
                return Err(unexpected("target page"));
            };
            append_bounded(&mut values, page.items, "target")?;
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(values);
            }
        }
    }

    pub(super) async fn findings(&self, project_id: Uuid) -> Result<Vec<FindingViewV1>> {
        let mut values = Vec::new();
        let mut cursor = None;
        loop {
            let result = self
                .query(ControlQueryV1::ListFindings {
                    project_id,
                    page: PageRequestV1 { cursor, limit: self.page_size },
                })
                .await?;
            let ControlResultV1::Findings(page) = result else {
                return Err(unexpected("finding page"));
            };
            append_bounded(&mut values, page.items, "finding")?;
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Ok(values);
            }
        }
    }
}

fn response_result(outcome: ControlResponseOutcomeV1) -> Result<ControlResultV1> {
    match outcome {
        ControlResponseOutcomeV1::Success(result) => Ok(*result),
        ControlResponseOutcomeV1::Error(error) => Err(ScorchError::Config(error.to_string())),
    }
}

fn append_bounded<T>(values: &mut Vec<T>, page: Vec<T>, resource: &str) -> Result<()> {
    if values.len().saturating_add(page.len()) > MAX_COMPATIBILITY_ITEMS {
        return Err(ScorchError::Config(format!(
            "control {resource} result exceeds the CLI compatibility limit"
        )));
    }
    values.extend(page);
    Ok(())
}

#[cfg(test)]
pub(super) fn append_bounded_for_test<T>(
    values: &mut Vec<T>,
    page: Vec<T>,
    resource: &str,
) -> Result<()> {
    append_bounded(values, page, resource)
}

fn unexpected(resource: &str) -> ScorchError {
    ScorchError::Config(format!("control service returned an unexpected {resource} result"))
}
