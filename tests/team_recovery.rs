//! Black-box recovery-manifest integrity contracts.

#![cfg(feature = "team")]

use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use scorchkit::control_contract::{TeamRecoveryObjectV1, TEAM_OBJECT_SCHEMA_V1};
use scorchkit::engine::observation::sha256_hex;
use scorchkit::team::{create_recovery_manifest, verify_recovery_manifest, RecoveryInput};
use sqlx::{PgPool, Row};
use uuid::Uuid;

fn envelope(cell_id: &str, object_id: &str, key_id: &str) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": TEAM_OBJECT_SCHEMA_V1,
        "cellId": cell_id,
        "objectId": object_id,
        "kind": "evidence",
        "plaintextBytes": 8,
        "keyId": key_id,
        "createdAt": "2023-11-14T22:13:20Z",
        "expiresAt": "2023-12-14T22:13:20Z",
        "nonce": base64::engine::general_purpose::STANDARD.encode([1_u8; 12]),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode([2_u8; 24]),
    }))
}

fn input() -> Result<RecoveryInput, serde_json::Error> {
    let object_id = "b".repeat(64);
    let ciphertext = envelope("alpha", &object_id, "primary")?;
    Ok(RecoveryInput {
        cell_id: "alpha".into(),
        organization_id: "org-alpha".into(),
        project_id: Uuid::from_u128(1),
        engagement_id: Uuid::from_u128(2),
        database_identity_sha256: "a".repeat(64),
        migration_versions: (1..=14).collect(),
        database_snapshot: b"postgres custom snapshot".to_vec(),
        objects: vec![(
            TeamRecoveryObjectV1 {
                object_id,
                ciphertext_sha256: sha256_hex(&ciphertext),
                stored_bytes: u64::try_from(ciphertext.len()).unwrap_or(u64::MAX),
                key_id: "primary".into(),
            },
            ciphertext,
        )],
        created_at: DateTime::<Utc>::UNIX_EPOCH + chrono::Duration::seconds(1_700_000_000),
    })
}

#[test]
fn recovery_rejects_same_destination_and_every_changed_input_class() {
    let input = input().expect("input envelope");
    let manifest = create_recovery_manifest(&input).expect("manifest");
    verify_recovery_manifest(&manifest, &input, &"c".repeat(64)).expect("exact backup");
    assert!(verify_recovery_manifest(&manifest, &input, &"a".repeat(64)).is_err());

    let mut snapshot = input.clone();
    snapshot.database_snapshot.push(b'!');
    assert!(verify_recovery_manifest(&manifest, &snapshot, &"c".repeat(64)).is_err());
    let mut object = input.clone();
    object.objects[0].1.push(b'!');
    assert!(verify_recovery_manifest(&manifest, &object, &"c".repeat(64)).is_err());
    let mut migrations = input.clone();
    migrations.migration_versions.pop();
    assert!(verify_recovery_manifest(&manifest, &migrations, &"c".repeat(64)).is_err());
    let mut timestamp = input.clone();
    timestamp.created_at += chrono::Duration::seconds(1);
    assert!(verify_recovery_manifest(&manifest, &timestamp, &"c".repeat(64)).is_err());
    let mut identity = input;
    identity.project_id = Uuid::from_u128(3);
    assert!(verify_recovery_manifest(&manifest, &identity, &"c".repeat(64)).is_err());
}

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
    let expected = format!("scorchkit_team_recovery_{suffix}_");
    if !name.starts_with(&expected)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(other_error("refusing an unsafe disposable recovery database name").into());
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
             WHERE datname = $1 AND backend_type = 'client backend' \
               AND pid <> pg_backend_pid()",
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
) -> Result<(), Box<dyn Error>> {
    let path = std::env::var_os("PATH").ok_or_else(|| other_error("PATH is unavailable"))?;
    let mut command = Command::new(program);
    command.env_clear().env("PATH", path).env("PGCONNECT_TIMEOUT", "5").args(args);
    if let Some(password) = password {
        command.env("PGPASSWORD", password);
    }
    if !command.status()?.success() {
        return Err(other_error(format!("{program} returned an unexpected status")).into());
    }
    Ok(())
}

async fn database_identity(pool: &PgPool) -> Result<String, Box<dyn Error>> {
    let row = sqlx::query(
        "SELECT (pg_control_system()).system_identifier::text AS system_identifier, \
         oid::text AS database_oid, datname AS database_name \
         FROM pg_database WHERE datname = current_database()",
    )
    .fetch_one(pool)
    .await?;
    Ok(sha256_hex(
        format!(
            "{}\0{}\0{}",
            row.get::<String, _>("system_identifier"),
            row.get::<String, _>("database_oid"),
            row.get::<String, _>("database_name")
        )
        .as_bytes(),
    ))
}

async fn exercise_restore(
    base: &str,
    names: &[String],
    snapshot: &Path,
) -> Result<(), Box<dyn Error>> {
    let source_url = scoped_database_url(base, &names[0])?;
    let destination_url = scoped_database_url(base, &names[1])?;
    let source = scorchkit::storage::connect(&source_url).await?;
    scorchkit::storage::migrate::run_migrations(&source).await?;
    let project = scorchkit::storage::projects::create_project(
        &source,
        "recovery-project",
        "recovery fixture",
    )
    .await?;
    let source_identity = database_identity(&source).await?;
    let migrations = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&source)
    .await?;
    source.close().await;

    let (source_tool_url, password) = postgres_tool_url(base, &names[0])?;
    run_postgres_tool(
        "pg_dump",
        &[
            OsString::from("--format=custom"),
            OsString::from("--no-owner"),
            OsString::from("--no-privileges"),
            OsString::from("--file"),
            snapshot.as_os_str().to_owned(),
            OsString::from(source_tool_url),
        ],
        password.as_deref(),
    )?;
    let snapshot_bytes = std::fs::read(snapshot)?;
    let object_id = "d".repeat(64);
    let ciphertext = envelope("recovery", &object_id, "primary")?;
    let input = RecoveryInput {
        cell_id: "recovery".into(),
        organization_id: "org-recovery".into(),
        project_id: project.id,
        engagement_id: Uuid::new_v4(),
        database_identity_sha256: source_identity,
        migration_versions: migrations,
        database_snapshot: snapshot_bytes,
        objects: vec![(
            TeamRecoveryObjectV1 {
                object_id,
                ciphertext_sha256: sha256_hex(&ciphertext),
                stored_bytes: u64::try_from(ciphertext.len()).unwrap_or(u64::MAX),
                key_id: "primary".into(),
            },
            ciphertext,
        )],
        created_at: Utc::now(),
    };
    let manifest = create_recovery_manifest(&input)?;
    let destination = scorchkit::storage::connect(&destination_url).await?;
    let destination_identity = database_identity(&destination).await?;
    destination.close().await;
    verify_recovery_manifest(&manifest, &input, &destination_identity)?;

    let (destination_tool_url, destination_password) = postgres_tool_url(base, &names[1])?;
    run_postgres_tool(
        "pg_restore",
        &[
            OsString::from("--exit-on-error"),
            OsString::from("--no-owner"),
            OsString::from("--no-privileges"),
            OsString::from("--dbname"),
            OsString::from(destination_tool_url),
            snapshot.as_os_str().to_owned(),
        ],
        destination_password.as_deref(),
    )?;
    verify_recovery_manifest(&manifest, &input, &destination_identity)?;
    let restored = scorchkit::storage::connect(&destination_url).await?;
    let restored_project: Uuid =
        sqlx::query_scalar("SELECT id FROM projects").fetch_one(&restored).await?;
    assert_eq!(restored_project, project.id);
    assert_eq!(database_identity(&restored).await?, destination_identity);
    restored.close().await;
    Ok(())
}

#[tokio::test]
async fn postgres_snapshot_is_verified_before_and_after_distinct_restore(
) -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping team recovery integration test");
        return Ok(());
    };
    for program in ["pg_dump", "pg_restore"] {
        if Command::new(program).arg("--version").output().is_err() {
            return Err(
                other_error(format!("required PostgreSQL tool is unavailable: {program}")).into()
            );
        }
    }
    let suffix = Uuid::new_v4().simple().to_string()[..12].to_owned();
    let names = vec![
        format!("scorchkit_team_recovery_{suffix}_source"),
        format!("scorchkit_team_recovery_{suffix}_destination"),
    ];
    let directory = tempfile::tempdir()?;
    let snapshot = directory.path().join("team.dump");
    let admin_url = scoped_database_url(&database_url, "postgres")?;
    let admin = scorchkit::storage::connect(&admin_url).await?;
    let mut attempted = Vec::with_capacity(names.len());
    let result = Box::pin(async {
        for name in &names {
            attempted.push(name.clone());
            create_database(&admin, name, &suffix).await?;
        }
        exercise_restore(&database_url, &names, &snapshot).await
    })
    .await;
    let cleanup = cleanup_databases(&admin, &attempted, &suffix).await;
    admin.close().await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(other_error(format!(
            "team recovery failed: {primary}; cleanup also failed: {cleanup}"
        ))
        .into()),
    }
}
