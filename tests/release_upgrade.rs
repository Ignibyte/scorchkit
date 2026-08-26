//! Upgrade and snapshot-restore qualification from the v2.1.0 release boundary.

#![cfg(feature = "storage")]

use std::{error::Error, ffi::OsString, io, path::Path, process::Command};

use scorchkit::engine::triage::FindingTriageTransition;
use sha2::{Digest, Sha256};
use sqlx::{Executor, PgPool, Row};

const LEGACY_SCHEMA: &str = include_str!("fixtures/release/v2.1.0/schema.sql");
const LEGACY_SEED: &str = include_str!("fixtures/release/v2.1.0/seed.sql");
const FAILURE_SQL: &str = include_str!("fixtures/release/v2.1.0/failure.sql");

const LEGACY_IDENTITY_QUERY: &str = r"
SELECT jsonb_build_object(
    'project_id', project.id::text,
    'project_settings', project.settings,
    'target_id', target.id::text,
    'target_url', target.url,
    'schedule_id', schedule.id::text,
    'scan_id', scan.id::text,
    'scan_summary', scan.summary,
    'finding_id', finding.id::text,
    'fingerprint', finding.fingerprint,
    'raw_finding', finding.raw_finding,
    'evidence', finding.evidence,
    'status', finding.status,
    'status_note', finding.status_note,
    'confidence', finding.confidence,
    'seen_count', finding.seen_count
)
FROM projects AS project
JOIN project_targets AS target ON target.project_id = project.id
JOIN scan_schedules AS schedule ON schedule.project_id = project.id
JOIN scan_records AS scan ON scan.project_id = project.id
JOIN tracked_findings AS finding ON finding.scan_id = scan.id
WHERE project.id = '11111111-1111-4111-8111-111111111111'
";

fn other_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn scoped_database_url(base: &str, database: &str) -> Result<String, Box<dyn Error>> {
    let mut parsed = url::Url::parse(base)?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(other_error("DATABASE_URL is not PostgreSQL").into());
    }
    parsed.set_path(&format!("/{database}"));
    Ok(parsed.to_string())
}

fn postgres_tool_url(
    base: &str,
    database: &str,
) -> Result<(String, Option<String>), Box<dyn Error>> {
    let mut parsed = url::Url::parse(&scoped_database_url(base, database)?)?;
    let password = parsed.password().map(str::to_owned);
    if password.is_some() {
        parsed
            .set_password(None)
            .map_err(|()| other_error("could not remove the database password"))?;
    }
    Ok((parsed.to_string(), password))
}

fn validate_database_name(name: &str, suffix: &str) -> Result<(), Box<dyn Error>> {
    let expected = format!("scorchkit_release_{suffix}_");
    if !name.starts_with(&expected)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(other_error("refusing an unsafe disposable database name").into());
    }
    Ok(())
}

async fn create_database(admin: &PgPool, name: &str, suffix: &str) -> Result<(), Box<dyn Error>> {
    validate_database_name(name, suffix)?;
    let sql = format!("CREATE DATABASE \"{name}\"");
    sqlx::query(sqlx::AssertSqlSafe(sql)).execute(admin).await?;
    Ok(())
}

async fn cleanup_databases(
    admin: &PgPool,
    names: &[String],
    suffix: &str,
) -> Result<(), Box<dyn Error>> {
    for name in names {
        validate_database_name(name, suffix)?;
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(name)
        .execute(admin)
        .await?;
        let sql = format!("DROP DATABASE IF EXISTS \"{name}\"");
        sqlx::query(sqlx::AssertSqlSafe(sql)).execute(admin).await?;
    }
    Ok(())
}

fn run_postgres_tool(
    program: &str,
    args: &[OsString],
    password: Option<&str>,
    expect_success: bool,
) -> Result<(), Box<dyn Error>> {
    let path = std::env::var_os("PATH").ok_or_else(|| other_error("PATH is unavailable"))?;
    let mut command = Command::new(program);
    command.env_clear().env("PATH", path).env("PGCONNECT_TIMEOUT", "5").args(args);
    if let Some(password) = password {
        command.env("PGPASSWORD", password);
    }
    let status = command.status().map_err(|_| other_error(format!("{program} is unavailable")))?;
    if status.success() != expect_success {
        return Err(other_error(format!("{program} returned an unexpected status")).into());
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, Box<dyn Error>> {
    let bytes = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

async fn legacy_identity(pool: &PgPool) -> Result<serde_json::Value, Box<dyn Error>> {
    let value =
        sqlx::query_scalar::<_, serde_json::Value>(LEGACY_IDENTITY_QUERY).fetch_one(pool).await?;
    Ok(value)
}

async fn create_legacy_snapshot(
    legacy_url: &str,
    legacy_tool_url: &str,
    password: Option<&str>,
    snapshot: &Path,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let pool = scorchkit::storage::connect(legacy_url).await?;
    pool.execute(LEGACY_SCHEMA).await?;
    pool.execute(LEGACY_SEED).await?;
    let identity = legacy_identity(&pool).await?;
    drop(pool);
    run_postgres_tool(
        "pg_dump",
        &[
            "--format=custom".into(),
            "--no-owner".into(),
            "--no-privileges".into(),
            "--file".into(),
            snapshot.as_os_str().to_owned(),
            "--dbname".into(),
            legacy_tool_url.into(),
        ],
        password,
        true,
    )?;
    Ok(identity)
}

async fn verify_forward_upgrade(
    legacy_url: &str,
    before: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let pool = scorchkit::storage::connect(legacy_url).await?;
    scorchkit::storage::migrate::run_migrations(&pool).await?;
    if legacy_identity(&pool).await? != *before {
        return Err(other_error("v2.1.0 canonical identities or histories changed").into());
    }
    let migrated_finding = sqlx::query(
        "SELECT stable_identity, identity_schema FROM tracked_findings \
         WHERE id = '44444444-4444-4444-8444-444444444444'",
    )
    .fetch_one(&pool)
    .await?;
    let migrated_identity = migrated_finding.try_get::<String, _>("stable_identity")?;
    if migrated_identity != "legacy:release-fixture-fingerprint"
        || migrated_finding.try_get::<String, _>("identity_schema")?
            != "scorchkit.finding-identity/legacy-v1"
    {
        return Err(
            other_error("legacy finding identity was not migrated deterministically").into()
        );
    }
    let triage = sqlx::query(
        "SELECT finding.triage_state, finding.status, transition.transition_identity, \
                transition.transition_schema, transition.sequence, transition.from_state, \
                transition.to_state, transition.actor_kind, transition.actor_identity, \
                transition.observed_at, transition.raw_transition \
         FROM tracked_findings AS finding \
         INNER JOIN finding_triage_transitions AS transition \
             ON transition.tracked_finding_id = finding.id AND transition.sequence = 1 \
         WHERE finding.id = '44444444-4444-4444-8444-444444444444'",
    )
    .fetch_one(&pool)
    .await?;
    let raw_transition = triage.try_get::<serde_json::Value, _>("raw_transition")?;
    let transition: FindingTriageTransition = serde_json::from_value(raw_transition.clone())?;
    transition.validate()?;
    if triage.try_get::<String, _>("triage_state")? != "validated"
        || triage.try_get::<String, _>("status")? != "acknowledged"
        || triage.try_get::<String, _>("transition_identity")? != transition.identity
        || triage.try_get::<String, _>("transition_schema")?
            != "scorchkit.finding-triage-transition/v1"
        || triage.try_get::<i32, _>("sequence")? != 1
        || triage.try_get::<Option<String>, _>("from_state")?.is_some()
        || triage.try_get::<String, _>("to_state")? != "validated"
        || triage.try_get::<String, _>("actor_kind")? != "system"
        || triage.try_get::<String, _>("actor_identity")? != "migration/v1"
        || triage.try_get::<chrono::DateTime<chrono::Utc>, _>("observed_at")?.timestamp_micros()
            != transition.observed_at.timestamp_micros()
        || transition.finding_identity != migrated_identity
        || serde_json::to_value(&transition)? != raw_transition
    {
        return Err(other_error("legacy finding triage history was not seeded canonically").into());
    }
    let current_tables = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pg_class WHERE relname IN \
         ('scan_jobs', 'finding_evidence', 'attack_paths', 'webhook_deliveries', \
          'finding_triage_transitions', 'finding_correlation_decisions', \
          'finding_suppressions')",
    )
    .fetch_one(&pool)
    .await?;
    if current_tables != 7 {
        return Err(other_error("current release tables were not installed").into());
    }
    let migration_state = sqlx::query(
        "SELECT count(*) AS migration_count, max(version) AS latest_version \
         FROM _sqlx_migrations WHERE success",
    )
    .fetch_one(&pool)
    .await?;
    if migration_state.try_get::<i64, _>("migration_count")? != 14
        || migration_state.try_get::<Option<i64>, _>("latest_version")? != Some(14)
    {
        return Err(other_error("current migration ledger is incomplete").into());
    }
    Ok(())
}

async fn inject_failed_rehearsal(
    failure_url: &str,
    failure_tool_url: &str,
    password: Option<&str>,
    failure_file: &Path,
) -> Result<(), Box<dyn Error>> {
    let pool = scorchkit::storage::connect(failure_url).await?;
    pool.execute(LEGACY_SCHEMA).await?;
    pool.execute(LEGACY_SEED).await?;
    drop(pool);
    run_postgres_tool(
        "psql",
        &[
            "--no-psqlrc".into(),
            "--set".into(),
            "ON_ERROR_STOP=1".into(),
            "--dbname".into(),
            failure_tool_url.into(),
            "--file".into(),
            failure_file.as_os_str().to_owned(),
        ],
        password,
        false,
    )?;
    let pool = scorchkit::storage::connect(failure_url).await?;
    let marker_exists = sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('public.release_failure_marker') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    if !marker_exists {
        return Err(
            other_error("psql failed before the intended rehearsal marker committed").into()
        );
    }
    Ok(())
}

async fn restore_and_verify(
    restore_url: &str,
    restore_tool_url: &str,
    password: Option<&str>,
    snapshot: &Path,
    snapshot_digest: &str,
    before: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    if sha256(snapshot)? != snapshot_digest {
        return Err(other_error("snapshot digest changed before restore").into());
    }
    run_postgres_tool(
        "pg_restore",
        &[
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-privileges".into(),
            "--dbname".into(),
            restore_tool_url.into(),
            snapshot.as_os_str().to_owned(),
        ],
        password,
        true,
    )?;
    if sha256(snapshot)? != snapshot_digest {
        return Err(other_error("snapshot digest changed during restore").into());
    }
    let pool = scorchkit::storage::connect(restore_url).await?;
    let restored = legacy_identity(&pool).await?;
    if restored != *before {
        return Err(other_error("restored v2.1.0 identities or histories changed").into());
    }
    if restored.pointer("/project_settings/engagement/id")
        != Some(&serde_json::json!("engagement-v2-release-fixture"))
        || restored.pointer("/scan_summary/job/id")
            != Some(&serde_json::json!("job-v2-release-fixture"))
        || restored.pointer("/scan_summary/evidence/id")
            != Some(&serde_json::json!("evidence-v2-release-fixture"))
        || restored.pointer("/raw_finding/history/1/state")
            != Some(&serde_json::json!("acknowledged"))
    {
        return Err(other_error("restored nested identity/history contract is incomplete").into());
    }
    let restored_migrations = sqlx::query(
        "SELECT count(*) AS migration_count, max(version) AS latest_version \
         FROM _sqlx_migrations WHERE success",
    )
    .fetch_one(&pool)
    .await?;
    if restored_migrations.try_get::<i64, _>("migration_count")? != 4
        || restored_migrations.try_get::<Option<i64>, _>("latest_version")? != Some(4)
    {
        return Err(other_error("restored database is not at the exact v2.1.0 ledger").into());
    }
    let unexpected_current_tables = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pg_class WHERE relname IN \
         ('scan_jobs', 'finding_evidence', 'attack_paths', 'webhook_deliveries')",
    )
    .fetch_one(&pool)
    .await?;
    if unexpected_current_tables != 0 {
        return Err(other_error("restored database retained post-v2.1.0 tables").into());
    }
    Ok(())
}

async fn exercise_upgrade(
    database_url: &str,
    password: Option<&str>,
    names: &[String],
    suffix: &str,
) -> Result<(), Box<dyn Error>> {
    let legacy_name = &names[0];
    let failure_name = &names[1];
    let restore_name = &names[2];
    let legacy_url = scoped_database_url(database_url, legacy_name)?;
    let failure_url = scoped_database_url(database_url, failure_name)?;
    let restore_url = scoped_database_url(database_url, restore_name)?;
    let legacy_tool_url = postgres_tool_url(database_url, legacy_name)?.0;
    let failure_tool_url = postgres_tool_url(database_url, failure_name)?.0;
    let restore_tool_url = postgres_tool_url(database_url, restore_name)?.0;
    let temporary = tempfile::tempdir()?;
    let snapshot = temporary.path().join("v2.1.0.dump");
    let failure_file = temporary.path().join("failure.sql");
    std::fs::write(&failure_file, FAILURE_SQL)?;

    let before = create_legacy_snapshot(&legacy_url, &legacy_tool_url, password, &snapshot).await?;
    let snapshot_digest = sha256(&snapshot)?;
    if snapshot_digest.len() != 64 {
        return Err(other_error("snapshot digest is malformed").into());
    }
    verify_forward_upgrade(&legacy_url, &before).await?;
    inject_failed_rehearsal(&failure_url, &failure_tool_url, password, &failure_file).await?;
    restore_and_verify(
        &restore_url,
        &restore_tool_url,
        password,
        &snapshot,
        &snapshot_digest,
        &before,
    )
    .await?;
    validate_database_name(legacy_name, suffix)?;
    validate_database_name(failure_name, suffix)?;
    validate_database_name(restore_name, suffix)?;
    Ok(())
}

#[test]
fn current_config_loader_accepts_the_v2_1_fixture() -> Result<(), Box<dyn Error>> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/release/v2.1.0/config.toml");
    let config = scorchkit::config::AppConfig::load(Some(&path))?;
    assert_eq!(config.scan.timeout_seconds, 420);
    assert_eq!(config.scan.max_concurrent_modules, 3);
    assert_eq!(config.scan.profile, "standard");
    assert!(!config.scan.follow_redirects);
    assert_eq!(config.database.max_connections, 7);
    assert!(!config.database.migrate_on_startup);
    assert_eq!(config.report.output_dir, Path::new("release-fixture-reports"));
    assert!(config.report.include_evidence);
    assert!(!config.report.include_remediation);
    Ok(())
}

#[test]
fn postgres_tool_urls_remove_only_the_password() -> Result<(), Box<dyn Error>> {
    let base = "postgresql://release-user:secret@localhost:5432/source?sslmode=require";
    let sqlx = scoped_database_url(base, "destination")?;
    let (tool, password) = postgres_tool_url(base, "destination")?;
    assert!(sqlx.contains("release-user:secret@localhost:5432/destination"));
    assert!(tool.contains("release-user@localhost:5432/destination"));
    assert!(!tool.contains("secret"));
    assert!(tool.ends_with("?sslmode=require"));
    assert_eq!(password.as_deref(), Some("secret"));
    Ok(())
}

#[tokio::test]
async fn v2_1_database_upgrades_and_failed_rehearsal_restores_separately(
) -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping release upgrade/restore integration test");
        return Ok(());
    };
    for program in ["pg_dump", "pg_restore", "psql"] {
        if Command::new(program).arg("--version").output().is_err() {
            return Err(
                other_error(format!("required PostgreSQL tool is unavailable: {program}")).into()
            );
        }
    }

    let suffix = uuid::Uuid::new_v4().simple().to_string()[..12].to_owned();
    if suffix.len() != 12 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(other_error("generated database suffix is unsafe").into());
    }
    let names = vec![
        format!("scorchkit_release_{suffix}_legacy"),
        format!("scorchkit_release_{suffix}_failure"),
        format!("scorchkit_release_{suffix}_restore"),
    ];
    let admin_url = scoped_database_url(&database_url, "postgres")?;
    let password = postgres_tool_url(&database_url, "postgres")?.1;
    let admin = scorchkit::storage::connect(&admin_url).await?;
    let mut attempted_names = Vec::with_capacity(names.len());
    let result = async {
        for name in &names {
            attempted_names.push(name.clone());
            create_database(&admin, name, &suffix).await?;
        }
        exercise_upgrade(&database_url, password.as_deref(), &names, &suffix).await
    }
    .await;
    let cleanup = cleanup_databases(&admin, &attempted_names, &suffix).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(other_error(format!(
            "upgrade rehearsal failed: {primary}; cleanup also failed: {cleanup}"
        ))
        .into()),
    }
}
