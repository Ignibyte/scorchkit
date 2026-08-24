//! Project CRUD operations and target management.
//!
//! Provides functions to create, read, update, and delete projects,
//! as well as manage the targets associated with each project.

use sqlx::PgPool;
use uuid::Uuid;

use super::models::{Project, ProjectTarget};
use crate::engine::error::{Result, ScorchError};

/// Create a new project with the given name and description.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn create_project(pool: &PgPool, name: &str, description: &str) -> Result<Project> {
    sqlx::query_as::<_, Project>(
        "INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING *",
    )
    .bind(name)
    .bind(description)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("create project: {e}")))
}

/// Get a project by its unique ID.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_project(pool: &PgPool, id: Uuid) -> Result<Option<Project>> {
    sqlx::query_as::<_, Project>("SELECT * FROM projects WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get project: {e}")))
}

/// List all projects, ordered by creation date (newest first).
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_projects(pool: &PgPool) -> Result<Vec<Project>> {
    sqlx::query_as::<_, Project>("SELECT * FROM projects ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("list projects: {e}")))
}

/// List a bounded stable project page after an optional project cursor.
///
/// # Errors
///
/// Returns an error for an unknown cursor, invalid limit, or database failure.
pub async fn list_projects_page(
    pool: &PgPool,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<Project>> {
    let limit = bounded_page_limit(limit)?;
    let cursor = if let Some(id) = after {
        Some(
            sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>, Uuid)>(
                "SELECT created_at, id FROM projects WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|error| ScorchError::Database(format!("load project cursor: {error}")))?
            .ok_or_else(|| ScorchError::Database("project cursor was not found".to_string()))?,
        )
    } else {
        None
    };
    sqlx::query_as::<_, Project>(
        "SELECT * FROM projects \
         WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2)) \
         ORDER BY created_at DESC, id DESC LIMIT $3",
    )
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map(|value| value.1))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list project page: {error}")))
}

/// Update a project's name and description.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn update_project(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    description: &str,
) -> Result<Option<Project>> {
    sqlx::query_as::<_, Project>(
        "UPDATE projects SET name = $2, description = $3, updated_at = now() \
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .fetch_optional(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("update project: {e}")))
}

/// Delete a project and all associated data (cascades).
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn delete_project(pool: &PgPool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("delete project: {e}")))?;
    Ok(result.rows_affected() > 0)
}

/// Add a target URL to a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn add_target(
    pool: &PgPool,
    project_id: Uuid,
    url: &str,
    label: &str,
) -> Result<ProjectTarget> {
    sqlx::query_as::<_, ProjectTarget>(
        "INSERT INTO project_targets (project_id, url, label) \
         VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(project_id)
    .bind(url)
    .bind(label)
    .fetch_one(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("add target: {e}")))
}

/// Remove a target from a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn remove_target(pool: &PgPool, project_id: Uuid, target_id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM project_targets WHERE project_id = $1 AND id = $2")
        .bind(project_id)
        .bind(target_id)
        .execute(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("remove target: {e}")))?;
    Ok(result.rows_affected() > 0)
}

/// Get a project by its unique name.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn get_project_by_name(pool: &PgPool, name: &str) -> Result<Option<Project>> {
    sqlx::query_as::<_, Project>("SELECT * FROM projects WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(|e| ScorchError::Database(format!("get project by name: {e}")))
}

/// List all targets for a project.
///
/// # Errors
///
/// Returns an error if the database query fails.
pub async fn list_targets(pool: &PgPool, project_id: Uuid) -> Result<Vec<ProjectTarget>> {
    sqlx::query_as::<_, ProjectTarget>(
        "SELECT * FROM project_targets WHERE project_id = $1 \
         ORDER BY created_at",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await
    .map_err(|e| ScorchError::Database(format!("list targets: {e}")))
}

/// Read one project target by parent and ID.
///
/// # Errors
///
/// Returns an error when the database read fails.
pub async fn get_target(
    pool: &PgPool,
    project_id: Uuid,
    target_id: Uuid,
) -> Result<Option<ProjectTarget>> {
    sqlx::query_as::<_, ProjectTarget>(
        "SELECT * FROM project_targets WHERE project_id = $1 AND id = $2",
    )
    .bind(project_id)
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("get project target: {error}")))
}

/// List a bounded stable target page after an optional target cursor.
///
/// # Errors
///
/// Returns an error for an unknown parent cursor, invalid limit, or database failure.
pub async fn list_targets_page(
    pool: &PgPool,
    project_id: Uuid,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<ProjectTarget>> {
    let limit = bounded_page_limit(limit)?;
    let cursor = if let Some(id) = after {
        Some(
            sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>, Uuid)>(
                "SELECT created_at, id FROM project_targets WHERE project_id = $1 AND id = $2",
            )
            .bind(project_id)
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|error| ScorchError::Database(format!("load target cursor: {error}")))?
            .ok_or_else(|| ScorchError::Database("target cursor was not found".to_string()))?,
        )
    } else {
        None
    };
    sqlx::query_as::<_, ProjectTarget>(
        "SELECT * FROM project_targets \
         WHERE project_id = $1 \
           AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3)) \
         ORDER BY created_at, id LIMIT $4",
    )
    .bind(project_id)
    .bind(cursor.map(|value| value.0))
    .bind(cursor.map(|value| value.1))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|error| ScorchError::Database(format!("list target page: {error}")))
}

fn bounded_page_limit(limit: usize) -> Result<i64> {
    if !(1..=201).contains(&limit) {
        return Err(ScorchError::Database("control storage page limit must be 1-201".to_string()));
    }
    i64::try_from(limit)
        .map_err(|_| ScorchError::Database("control storage page limit overflow".to_string()))
}
