//! Real two-cell qualification for the optional authenticated team profile.

#![cfg(feature = "team")]

use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use scorchkit::config::{
    AppConfig, TeamCellConfig, TeamKeyReferenceConfig, TeamPrincipalBindingConfig, TeamQuotaConfig,
    TeamRetentionConfig, TeamServiceConfig, TeamTlsTermination,
};
use scorchkit::control_contract::{
    ControlCommandV1, ControlErrorCodeV1, ControlQueryV1, ControlRequestV1,
    ControlResponseOutcomeV1, ControlResultV1, PageRequestV1, TeamAuditOutcomeV1, TeamObjectKindV1,
    TeamRecoveryObjectV1, TeamRoleV1, TEAM_OBJECT_SCHEMA_V1,
};
use scorchkit::engine::observation::sha256_hex;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::team::{create_recovery_manifest, RecoveryInput, TeamService, TeamSession};
use sqlx::{PgPool, Row};
use uuid::Uuid;

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

fn validate_database_name(name: &str, suffix: &str) -> Result<(), Box<dyn Error>> {
    let expected = format!("scorchkit_team_{suffix}_");
    if !name.starts_with(&expected)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(other_error("refusing an unsafe disposable team database name").into());
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

struct EnvironmentRestore(Vec<(String, Option<OsString>)>);

impl EnvironmentRestore {
    fn set(values: &[(&str, String)]) -> Self {
        let mut previous = Vec::with_capacity(values.len());
        for (name, value) in values {
            previous.push(((*name).to_string(), std::env::var_os(name)));
            std::env::set_var(name, value);
        }
        Self(previous)
    }
}

impl Drop for EnvironmentRestore {
    fn drop(&mut self) {
        for (name, previous) in self.0.drain(..) {
            if let Some(value) = previous {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }
}

async fn provision_project(database_url: &str, name: &str) -> Result<Uuid, Box<dyn Error>> {
    let pool = scorchkit::storage::connect(database_url).await?;
    scorchkit::storage::migrate::run_migrations(&pool).await?;
    let project = scorchkit::storage::projects::create_project(&pool, name, "team fixture").await?;
    pool.close().await;
    Ok(project.id)
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

fn recovery_envelope(
    cell_id: &str,
    object_id: &str,
    key_id: &str,
) -> Result<Vec<u8>, serde_json::Error> {
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

fn engagement(name: &str, root: &std::path::Path) -> Result<Engagement, Box<dyn Error>> {
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(root)?)
        .allow_scope(
            ScopeRule::parse(&format!("{name}.example.test"))
                .ok_or_else(|| other_error("fixture web scope is invalid"))?,
        )
        .allow_capability(Capability::LocalState)
        .allow_capability(Capability::DastScan)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe);
    Ok(Engagement::new(format!("team {name}"), policy))
}

fn cell(
    id: &str,
    project_id: Uuid,
    root: &std::path::Path,
    database_environment: &str,
    key_environment: &str,
) -> Result<TeamCellConfig, Box<dyn Error>> {
    Ok(TeamCellConfig {
        cell_id: id.into(),
        organization_id: format!("org-{id}"),
        project_id,
        engagement: engagement(id, root)?,
        database_url_env: database_environment.into(),
        object_root: root.into(),
        write_key_id: "primary".into(),
        keys: vec![
            TeamKeyReferenceConfig { key_id: "primary".into(), key_env: key_environment.into() },
            TeamKeyReferenceConfig {
                key_id: "secondary".into(),
                key_env: format!("{key_environment}_SECONDARY"),
            },
        ],
        quotas: TeamQuotaConfig {
            max_active_jobs: 2,
            max_journal_events: 32,
            max_event_bytes: 16_384,
            max_subscribers: 2,
            default_page_size: 20,
            max_requests_per_minute: 100,
            max_object_bytes: 4_096,
            max_objects: 8,
            max_storage_bytes: 16_384,
        },
        retention: TeamRetentionConfig { object_days: 30 },
    })
}

fn request(query: ControlQueryV1, engagement_id: Uuid) -> ControlRequestV1 {
    ControlRequestV1::query(query, Some(engagement_id))
}

fn reserve_loopback_address() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn team_config(
    bind: SocketAddr,
    cells: Vec<TeamCellConfig>,
    bindings: Vec<TeamPrincipalBindingConfig>,
) -> Arc<AppConfig> {
    Arc::new(AppConfig {
        team: Some(TeamServiceConfig {
            bind: Some(bind),
            tls_termination: Some(TeamTlsTermination::TrustedReverseProxy),
            allowed_hosts: vec!["security.example.test".into()],
            allowed_origins: vec!["https://security.example.test".into()],
            max_body_bytes: 8_192,
            max_response_bytes: 1_048_576,
            max_concurrent_requests: 8,
            cells,
            bindings,
        }),
        ..AppConfig::default()
    })
}

fn fixture_bindings() -> Vec<TeamPrincipalBindingConfig> {
    vec![
        TeamPrincipalBindingConfig {
            subject: "alpha-reader".into(),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Reader,
            token_env: "SCORCHKIT_TEAM_TEST_ALPHA_READER".into(),
        },
        TeamPrincipalBindingConfig {
            subject: "alpha-operator".into(),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Operator,
            token_env: "SCORCHKIT_TEAM_TEST_ALPHA_OPERATOR".into(),
        },
        TeamPrincipalBindingConfig {
            subject: "alpha-admin".into(),
            cell_id: "alpha".into(),
            role: TeamRoleV1::Administrator,
            token_env: "SCORCHKIT_TEAM_TEST_ALPHA_ADMIN".into(),
        },
        TeamPrincipalBindingConfig {
            subject: "beta-reader".into(),
            cell_id: "beta".into(),
            role: TeamRoleV1::Reader,
            token_env: "SCORCHKIT_TEAM_TEST_BETA_READER".into(),
        },
    ]
}

async fn exercise_two_cells(
    base_url: &str,
    names: &[String],
    roots: &[tempfile::TempDir],
) -> Result<(), Box<dyn Error>> {
    let alpha_url = scoped_database_url(base_url, &names[0])?;
    let beta_url = scoped_database_url(base_url, &names[1])?;
    let alpha_project = provision_project(&alpha_url, "alpha-project").await?;
    let beta_project = provision_project(&beta_url, "beta-project").await?;
    let alpha_reader_token = "a".repeat(32);
    let alpha_operator_token = "b".repeat(32);
    let alpha_admin_token = "c".repeat(32);
    let beta_reader_token = "d".repeat(32);
    let _environment = EnvironmentRestore::set(&[
        ("SCORCHKIT_TEAM_TEST_ALPHA_DATABASE", alpha_url.clone()),
        ("SCORCHKIT_TEAM_TEST_BETA_DATABASE", beta_url.clone()),
        (
            "SCORCHKIT_TEAM_TEST_ALPHA_KEY",
            base64::engine::general_purpose::STANDARD.encode([11_u8; 32]),
        ),
        (
            "SCORCHKIT_TEAM_TEST_ALPHA_KEY_SECONDARY",
            base64::engine::general_purpose::STANDARD.encode([12_u8; 32]),
        ),
        (
            "SCORCHKIT_TEAM_TEST_BETA_KEY",
            base64::engine::general_purpose::STANDARD.encode([22_u8; 32]),
        ),
        (
            "SCORCHKIT_TEAM_TEST_BETA_KEY_SECONDARY",
            base64::engine::general_purpose::STANDARD.encode([23_u8; 32]),
        ),
        ("SCORCHKIT_TEAM_TEST_ALPHA_READER", alpha_reader_token.clone()),
        ("SCORCHKIT_TEAM_TEST_ALPHA_OPERATOR", alpha_operator_token.clone()),
        ("SCORCHKIT_TEAM_TEST_ALPHA_ADMIN", alpha_admin_token.clone()),
        ("SCORCHKIT_TEAM_TEST_BETA_READER", beta_reader_token.clone()),
    ]);
    let cells = vec![
        cell(
            "alpha",
            alpha_project,
            roots[0].path(),
            "SCORCHKIT_TEAM_TEST_ALPHA_DATABASE",
            "SCORCHKIT_TEAM_TEST_ALPHA_KEY",
        )?,
        cell(
            "beta",
            beta_project,
            roots[1].path(),
            "SCORCHKIT_TEAM_TEST_BETA_DATABASE",
            "SCORCHKIT_TEAM_TEST_BETA_KEY",
        )?,
    ];
    let bind = reserve_loopback_address()?;
    let config = team_config(bind, cells, fixture_bindings());
    let service = TeamService::from_app_config(Arc::clone(&config)).await?;
    let debug = format!("{service:?}");
    assert!(debug.contains("TeamService"));
    assert!(debug.contains("binding_count: 4"));
    assert!(!debug.contains(&alpha_reader_token));
    assert!(Box::pin(TeamService::from_app_config(Arc::clone(&config))).await.is_err());
    let (rotation_object_id, old_rotation_digest) = Box::pin(assert_cell_boundaries(
        &service,
        [&alpha_reader_token, &alpha_operator_token, &alpha_admin_token, &beta_reader_token],
        [alpha_project, beta_project],
        &alpha_url,
        roots,
    ))
    .await?;
    drop(service);
    let rotated_config = Box::pin(qualify_rotation_and_recovery(
        &config,
        roots[0].path(),
        &alpha_url,
        &alpha_admin_token,
        &rotation_object_id,
        &old_rotation_digest,
    ))
    .await?;
    Box::pin(assert_http_boundary(rotated_config, bind, &alpha_reader_token)).await?;
    Ok(())
}

async fn qualify_rotation_and_recovery(
    config: &Arc<AppConfig>,
    root: &std::path::Path,
    database_url: &str,
    administrator_token: &str,
    object_id: &str,
    old_digest: &str,
) -> Result<Arc<AppConfig>, Box<dyn Error>> {
    let old_rotation_path =
        root.join(&object_id[..2]).join(format!("{object_id}.{old_digest}.object"));
    let retired_ciphertext = std::fs::read(&old_rotation_path)?;
    let mut rotated_config = (**config).clone();
    rotated_config
        .team
        .as_mut()
        .ok_or_else(|| other_error("team fixture config disappeared"))?
        .cells[0]
        .write_key_id = "secondary".into();
    let rotated_config = Arc::new(rotated_config);
    let rotated_service = TeamService::from_app_config(Arc::clone(&rotated_config)).await?;
    let rotated_admin = rotated_service
        .authenticate(administrator_token)
        .ok_or_else(|| other_error("missing rotated alpha admin"))?;
    let rotated = rotated_admin.rotate_object(Uuid::new_v4(), object_id).await?;
    assert_eq!(rotated.key_id, "secondary");
    let alpha_pool = scorchkit::storage::connect(database_url).await?;
    let new_rotation_digest: String =
        sqlx::query_scalar("SELECT ciphertext_sha256 FROM team_objects WHERE object_id = $1")
            .bind(object_id)
            .fetch_one(&alpha_pool)
            .await?;
    assert_ne!(new_rotation_digest, old_digest);
    assert!(!old_rotation_path.exists());
    let pending_deletions: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM team_object_deletions")
            .fetch_one(&alpha_pool)
            .await?;
    assert_eq!(pending_deletions, 0);
    let (_, rotated_plaintext) = rotated_admin.read_object(Uuid::new_v4(), object_id).await?;
    assert_eq!(rotated_plaintext.as_slice(), b"rotation evidence");
    let (pending_audit_request, interrupted_temporary, trim_deletion) = seed_interrupted_recovery(
        &alpha_pool,
        &rotated_admin,
        root,
        object_id,
        old_digest,
        &retired_ciphertext,
    )
    .await?;
    alpha_pool.close().await;
    drop(rotated_admin);
    drop(rotated_service);
    assert!(TeamService::from_app_config(Arc::clone(&rotated_config)).await.is_err());
    let trim_pool = scorchkit::storage::connect(database_url).await?;
    let (trim_object, trim_digest) = trim_deletion;
    sqlx::query(
        "DELETE FROM team_object_deletions WHERE object_id = $1 AND ciphertext_sha256 = $2",
    )
    .bind(trim_object)
    .bind(trim_digest)
    .execute(&trim_pool)
    .await?;
    trim_pool.close().await;
    let recovered_service = TeamService::from_app_config(Arc::clone(&rotated_config)).await?;
    assert!(!old_rotation_path.exists());
    assert!(!interrupted_temporary.exists());
    let recovered_pool = scorchkit::storage::connect(database_url).await?;
    let recovered_deletions: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM team_object_deletions")
            .fetch_one(&recovered_pool)
            .await?;
    assert_eq!(recovered_deletions, 0);
    let recovered_admin = recovered_service
        .authenticate(administrator_token)
        .ok_or_else(|| other_error("missing recovered alpha admin"))?;
    let recovered_audit = recovered_admin.read_audit(Uuid::new_v4(), 0, 200).await?;
    assert!(recovered_audit.iter().any(|event| {
        event.request_id == pending_audit_request
            && event.outcome == TeamAuditOutcomeV1::OutcomeUnknown
    }));
    recovered_pool.close().await;
    drop(recovered_admin);
    drop(recovered_service);
    Ok(rotated_config)
}

async fn seed_interrupted_recovery(
    pool: &PgPool,
    administrator: &TeamSession,
    root: &std::path::Path,
    object_id: &str,
    old_digest: &str,
    retired_ciphertext: &[u8],
) -> Result<(Uuid, std::path::PathBuf, (String, String)), Box<dyn Error>> {
    let old_rotation_path =
        root.join(&object_id[..2]).join(format!("{object_id}.{old_digest}.object"));
    std::fs::write(old_rotation_path, retired_ciphertext)?;
    let interrupted_temporary = root.join(format!(".{object_id}.{}.tmp", Uuid::new_v4()));
    std::fs::write(&interrupted_temporary, b"interrupted encrypted staging bytes")?;

    let pending_audit_request = Uuid::new_v4();
    sqlx::query("INSERT INTO team_request_ids (request_id) VALUES ($1)")
        .bind(pending_audit_request)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO team_audit_events \
         (request_id, cell_id, organization_id, project_id, engagement_id, subject, role, action, outcome) \
         VALUES ($1, 'alpha', 'org-alpha', $2, $3, 'alpha-admin', 'administrator', \
                 'fixture.interrupted', 'pending')",
    )
    .bind(pending_audit_request)
    .bind(administrator.principal().project_id)
    .bind(administrator.principal().engagement_id)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO team_object_deletions (object_id, ciphertext_sha256) VALUES ($1, $2)")
        .bind(object_id)
        .bind(old_digest)
        .execute(pool)
        .await?;

    let mut trim_deletion = None;
    for index in 0..16 {
        let dummy_object = sha256_hex(format!("dummy object {index}").as_bytes());
        let dummy_digest = sha256_hex(format!("dummy ciphertext {index}").as_bytes());
        sqlx::query(
            "INSERT INTO team_object_deletions (object_id, ciphertext_sha256) VALUES ($1, $2)",
        )
        .bind(&dummy_object)
        .bind(&dummy_digest)
        .execute(pool)
        .await?;
        trim_deletion = Some((dummy_object, dummy_digest));
    }
    let trim_deletion = trim_deletion.ok_or_else(|| other_error("missing overflow deletion"))?;
    Ok((pending_audit_request, interrupted_temporary, trim_deletion))
}

async fn assert_http_boundary(
    config: Arc<AppConfig>,
    bind: SocketAddr,
    token: &str,
) -> Result<(), Box<dyn Error>> {
    let task = tokio::spawn(scorchkit::team::transport::serve(config));
    let client = reqwest::Client::builder().no_proxy().build()?;
    let url = format!("http://{bind}/v1/team/description");
    let mut unauthenticated = None;
    for _ in 0..20 {
        match client.get(&url).header(reqwest::header::HOST, "security.example.test").send().await {
            Ok(response) => {
                unauthenticated = Some(response);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    let unauthenticated =
        unauthenticated.ok_or_else(|| other_error("team HTTP listener did not become ready"))?;
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);
    let wrong_host = client.get(&url).bearer_auth(token).send().await?;
    assert_eq!(wrong_host.status(), reqwest::StatusCode::FORBIDDEN);
    let body_on_get = client
        .get(&url)
        .header(reqwest::header::HOST, "security.example.test")
        .bearer_auth(token)
        .body("unexpected")
        .send()
        .await?;
    assert_eq!(body_on_get.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let response = client
        .get(&url)
        .header(reqwest::header::HOST, "security.example.test")
        .header(reqwest::header::ORIGIN, "https://security.example.test")
        .header("x-scorchkit-subject", "spoofed")
        .header("x-scorchkit-role", "administrator")
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response: scorchkit::control_contract::TeamControlResponseV1 = response.json().await?;
    assert_eq!(response.principal.subject, "alpha-reader");
    assert_eq!(response.principal.role, TeamRoleV1::Reader);
    let engagement_id = response.principal.engagement_id;
    assert_http_control_routes(&client, bind, token, engagement_id).await?;
    assert_http_object_routes(&client, bind, token).await?;
    task.abort();
    let _ = task.await;
    Ok(())
}

async fn assert_http_control_routes(
    client: &reqwest::Client,
    bind: SocketAddr,
    token: &str,
    engagement_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let description_url = format!("http://{bind}/v1/team/description?unexpected=1");
    let queried_description = client
        .get(description_url)
        .header(reqwest::header::HOST, "security.example.test")
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(queried_description.status(), reqwest::StatusCode::NOT_FOUND);

    let control_url = format!("http://{bind}/v1/team/control");
    let missing_content_type = client
        .post(&control_url)
        .header(reqwest::header::HOST, "security.example.test")
        .bearer_auth(token)
        .body("{}")
        .send()
        .await?;
    assert_eq!(missing_content_type.status(), reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let invalid_control = client
        .post(&control_url)
        .header(reqwest::header::HOST, "security.example.test")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .bearer_auth(token)
        .body("not json")
        .send()
        .await?;
    assert_eq!(invalid_control.status(), reqwest::StatusCode::BAD_REQUEST);
    let describe = ControlRequestV1::query(ControlQueryV1::Describe, Some(engagement_id));
    let valid_control = client
        .post(&control_url)
        .header(reqwest::header::HOST, "security.example.test")
        .bearer_auth(token)
        .json(&describe)
        .send()
        .await?;
    assert_eq!(valid_control.status(), reqwest::StatusCode::OK);

    let request_id = Uuid::new_v4().to_string();
    let audit = client
        .get(format!("http://{bind}/v1/team/audit?after=0&limit=1"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", &request_id)
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(audit.status(), reqwest::StatusCode::FORBIDDEN);

    let retention = client
        .post(format!("http://{bind}/v1/team/retention"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", Uuid::new_v4().to_string())
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(retention.status(), reqwest::StatusCode::FORBIDDEN);
    Ok(())
}

async fn assert_http_object_routes(
    client: &reqwest::Client,
    bind: SocketAddr,
    token: &str,
) -> Result<(), Box<dyn Error>> {
    let put = client
        .put(format!("http://{bind}/v1/team/objects/evidence"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", Uuid::new_v4().to_string())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .bearer_auth(token)
        .body("denied")
        .send()
        .await?;
    assert_eq!(put.status(), reqwest::StatusCode::FORBIDDEN);

    let unknown_kind = client
        .put(format!("http://{bind}/v1/team/objects/unknown"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", Uuid::new_v4().to_string())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .bearer_auth(token)
        .body("denied")
        .send()
        .await?;
    assert_eq!(unknown_kind.status(), reqwest::StatusCode::NOT_FOUND);

    let missing_object = "a".repeat(64);
    let get_object = client
        .get(format!("http://{bind}/v1/team/objects/{missing_object}"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", Uuid::new_v4().to_string())
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(get_object.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let rotate = client
        .post(format!("http://{bind}/v1/team/objects/{missing_object}/rotate"))
        .header(reqwest::header::HOST, "security.example.test")
        .header("x-scorchkit-request-id", Uuid::new_v4().to_string())
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(rotate.status(), reqwest::StatusCode::FORBIDDEN);

    let unknown = client
        .get(format!("http://{bind}/v1/team/unknown"))
        .header(reqwest::header::HOST, "security.example.test")
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
    Ok(())
}

async fn assert_cell_boundaries(
    service: &TeamService,
    tokens: [&str; 4],
    projects: [Uuid; 2],
    alpha_url: &str,
    roots: &[tempfile::TempDir],
) -> Result<(String, String), Box<dyn Error>> {
    let [alpha_project, beta_project] = projects;
    assert!(service.authenticate(&"z".repeat(32)).is_none());
    let alpha_reader =
        service.authenticate(tokens[0]).ok_or_else(|| other_error("missing alpha reader"))?;
    let alpha_operator =
        service.authenticate(tokens[1]).ok_or_else(|| other_error("missing alpha operator"))?;
    let alpha_admin =
        service.authenticate(tokens[2]).ok_or_else(|| other_error("missing alpha admin"))?;
    let beta_reader =
        service.authenticate(tokens[3]).ok_or_else(|| other_error("missing beta reader"))?;
    assert_eq!(alpha_reader.principal().project_id, alpha_project);
    assert_eq!(beta_reader.principal().project_id, beta_project);
    let session_debug = format!("{alpha_reader:?}");
    assert!(session_debug.contains("TeamSession"));
    assert!(session_debug.contains("alpha-reader"));
    assert!(!session_debug.contains(tokens[0]));

    assert_query_scope_boundaries(&alpha_reader, [alpha_project, beta_project]).await?;
    assert_command_scope_boundaries(&alpha_operator, [alpha_project, beta_project]).await;
    assert_duplicate_request_admission(&alpha_reader, alpha_project).await;

    let first = alpha_reader.execute_control(request(
        ControlQueryV1::GetProject { id: alpha_project },
        alpha_reader.principal().engagement_id,
    ));
    let second = alpha_operator.execute_control(request(
        ControlQueryV1::GetProject { id: alpha_project },
        alpha_operator.principal().engagement_id,
    ));
    let (first, second) = tokio::join!(first, second);
    assert!(matches!(first.result, ControlResponseOutcomeV1::Success(_)));
    assert!(matches!(second.result, ControlResponseOutcomeV1::Success(_)));

    assert_object_and_audit_boundaries(
        &alpha_reader,
        &alpha_operator,
        &alpha_admin,
        &beta_reader,
        alpha_url,
        roots[0].path(),
    )
    .await
}

async fn assert_query_scope_boundaries(
    reader: &TeamSession,
    projects: [Uuid; 2],
) -> Result<(), Box<dyn Error>> {
    let [alpha_project, beta_project] = projects;
    let page = PageRequestV1 { cursor: None, limit: 20 };
    let mut nil_request =
        request(ControlQueryV1::GetProject { id: alpha_project }, reader.principal().engagement_id);
    nil_request.request_id = Uuid::nil();
    let nil_response = reader.execute_control(nil_request).await;
    assert!(matches!(
        nil_response.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::InvalidRequest
    ));

    let alpha_projects = reader
        .execute_control(request(
            ControlQueryV1::ListProjects { page: page.clone() },
            reader.principal().engagement_id,
        ))
        .await;
    let ControlResponseOutcomeV1::Success(result) = alpha_projects.result else {
        return Err(other_error("alpha project query failed").into());
    };
    let ControlResultV1::Projects(projects) = *result else {
        return Err(other_error("alpha project query returned wrong shape").into());
    };
    assert_eq!(projects.items.len(), 1);
    assert_eq!(projects.items[0].id, alpha_project);

    let wrong_queries = vec![
        ControlQueryV1::GetProject { id: beta_project },
        ControlQueryV1::ListTargets { project_id: beta_project, page: page.clone() },
        ControlQueryV1::ListFindings { project_id: beta_project, page },
        ControlQueryV1::GetProjectReport { project_id: beta_project },
    ];
    for query in wrong_queries {
        let response =
            reader.execute_control(request(query, reader.principal().engagement_id)).await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error)
                if error.code == ControlErrorCodeV1::NotFound
        ));
    }
    Ok(())
}

async fn assert_command_scope_boundaries(operator: &TeamSession, projects: [Uuid; 2]) {
    let [alpha_project, beta_project] = projects;
    let lifecycle = vec![
        ControlCommandV1::CreateProject { name: "forbidden".into(), description: String::new() },
        ControlCommandV1::DeleteProject { id: alpha_project },
    ];
    for command in lifecycle {
        let response = operator
            .execute_control(ControlRequestV1::command(command, operator.principal().engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error)
                if error.code == ControlErrorCodeV1::PolicyDenied
        ));
    }

    let wrong_cell = vec![
        ControlCommandV1::AddTarget {
            project_id: beta_project,
            url: "https://alpha.example.test/".into(),
            label: "wrong cell".into(),
        },
        ControlCommandV1::RemoveTarget { project_id: beta_project, target_id: Uuid::new_v4() },
    ];
    for command in wrong_cell {
        let response = operator
            .execute_control(ControlRequestV1::command(command, operator.principal().engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error)
                if error.code == ControlErrorCodeV1::NotFound
        ));
    }

    for (target, expected) in [
        ("not a URL", ControlErrorCodeV1::InvalidRequest),
        ("https://alpha.example.test/", ControlErrorCodeV1::NotFound),
    ] {
        let command = ControlCommandV1::StartJob {
            target: target.into(),
            profile: "quick".into(),
            modules: None,
            skip: Vec::new(),
        };
        let response = operator
            .execute_control(ControlRequestV1::command(command, operator.principal().engagement_id))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error) if error.code == expected
        ));
    }
}

async fn assert_duplicate_request_admission(reader: &TeamSession, project_id: Uuid) {
    let mut duplicate_request =
        request(ControlQueryV1::GetProject { id: project_id }, reader.principal().engagement_id);
    duplicate_request.request_id = Uuid::new_v4();
    let first = reader.execute_control(duplicate_request.clone()).await;
    assert!(matches!(first.result, ControlResponseOutcomeV1::Success(_)));
    let second = reader.execute_control(duplicate_request).await;
    assert!(matches!(
        second.result,
        ControlResponseOutcomeV1::Error(ref error) if error.code == ControlErrorCodeV1::Conflict
    ));
}

struct ObjectFixtures {
    primary: String,
    rotation: String,
    expired: String,
    metadata: String,
}

async fn seed_object_fixtures(
    reader: &TeamSession,
    operator: &TeamSession,
    other_cell_reader: &TeamSession,
    root: &std::path::Path,
) -> Result<ObjectFixtures, Box<dyn Error>> {
    assert!(reader
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"reader denied")
        .await
        .is_err());
    assert!(operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, &[0_u8; 4_097])
        .await
        .is_err());
    let primary = operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"cell-local evidence")
        .await?;
    let rotation = operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"rotation evidence")
        .await?;
    let expired =
        operator.put_object(Uuid::new_v4(), TeamObjectKindV1::Report, b"expired report").await?;
    let maximum = vec![0_u8; 4_096];
    let maximum_view =
        operator.put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, &maximum).await?;
    assert_eq!(maximum_view.plaintext_bytes, 4_096);
    assert!(operator.put_object(Uuid::new_v4(), TeamObjectKindV1::Report, &maximum).await.is_err());
    let metadata = operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"immutable metadata")
        .await?;
    let (_, plaintext) = reader.read_object(Uuid::new_v4(), &primary.object_id).await?;
    assert_eq!(plaintext.as_slice(), b"cell-local evidence");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o750))?;
        assert!(reader.read_object(Uuid::new_v4(), &primary.object_id).await.is_err());
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    assert!(other_cell_reader.read_object(Uuid::new_v4(), &primary.object_id).await.is_err());
    Ok(ObjectFixtures {
        primary: primary.object_id,
        rotation: rotation.object_id,
        expired: expired.object_id,
        metadata: metadata.object_id,
    })
}

async fn assert_object_and_audit_boundaries(
    alpha_reader: &TeamSession,
    alpha_operator: &TeamSession,
    alpha_admin: &TeamSession,
    beta_reader: &TeamSession,
    alpha_url: &str,
    alpha_root: &std::path::Path,
) -> Result<(String, String), Box<dyn Error>> {
    let objects =
        seed_object_fixtures(alpha_reader, alpha_operator, beta_reader, alpha_root).await?;
    let alpha_pool = scorchkit::storage::connect(alpha_url).await?;
    sqlx::query(
        "UPDATE team_objects SET plaintext_bytes = plaintext_bytes + 1 WHERE object_id = $1",
    )
    .bind(&objects.metadata)
    .execute(&alpha_pool)
    .await?;
    assert!(alpha_operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"immutable metadata")
        .await
        .is_err());
    sqlx::query("UPDATE team_objects SET plaintext_bytes = $2 WHERE object_id = $1")
        .bind(&objects.metadata)
        .bind(18_i64)
        .execute(&alpha_pool)
        .await?;
    let ciphertext_sha256: String =
        sqlx::query_scalar("SELECT ciphertext_sha256 FROM team_objects WHERE object_id = $1")
            .bind(&objects.primary)
            .fetch_one(&alpha_pool)
            .await?;
    let rotation_digest: String =
        sqlx::query_scalar("SELECT ciphertext_sha256 FROM team_objects WHERE object_id = $1")
            .bind(&objects.rotation)
            .fetch_one(&alpha_pool)
            .await?;
    let object_path = alpha_root
        .join(&objects.primary[..2])
        .join(format!("{}.{ciphertext_sha256}.object", objects.primary));
    let mut stored = std::fs::read(&object_path)?;
    assert!(!stored.windows(19).any(|window| window == b"cell-local evidence"));
    stored[0] ^= 1;
    std::fs::write(object_path, stored)?;
    assert!(alpha_reader.read_object(Uuid::new_v4(), &objects.primary).await.is_err());

    assert_retention_and_capacity(
        alpha_operator,
        alpha_admin,
        &alpha_pool,
        alpha_root,
        &objects.expired,
    )
    .await?;

    assert!(alpha_reader.read_audit(Uuid::new_v4(), 0, 200).await.is_err());
    assert!(alpha_admin.read_audit(Uuid::new_v4(), 0, 0).await.is_err());
    assert!(alpha_admin.read_audit(Uuid::new_v4(), 0, 201).await.is_err());
    let audit = alpha_admin.read_audit(Uuid::new_v4(), 0, 200).await?;
    assert!(audit.iter().all(|event| {
        event.cell_id == "alpha"
            && event.organization_id == "org-alpha"
            && event.project_id == alpha_reader.principal().project_id
            && event.engagement_id == alpha_reader.principal().engagement_id
    }));
    assert!(audit.iter().any(|event| event.action == "object.put"));
    assert!(audit
        .iter()
        .any(|event| event.outcome == scorchkit::control_contract::TeamAuditOutcomeV1::Pending));
    assert!(audit
        .iter()
        .any(|event| event.outcome == scorchkit::control_contract::TeamAuditOutcomeV1::Succeeded));

    let project_count: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM projects").fetch_one(&alpha_pool).await?;
    assert_eq!(project_count, 1);
    assert_recovery_attribution(alpha_admin, &alpha_pool).await?;
    assert_identity_integrity(alpha_reader, &alpha_pool).await?;
    assert_audit_projection_integrity(alpha_admin, &alpha_pool).await?;
    assert!(sqlx::query("UPDATE team_audit_events SET action = 'tampered'")
        .execute(&alpha_pool)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM team_cell_identity").execute(&alpha_pool).await.is_err());
    alpha_pool.close().await;
    Ok((objects.rotation, rotation_digest))
}

async fn assert_retention_and_capacity(
    operator: &TeamSession,
    administrator: &TeamSession,
    pool: &PgPool,
    root: &std::path::Path,
    expired_object: &str,
) -> Result<(), Box<dyn Error>> {
    let digest: String =
        sqlx::query_scalar("SELECT ciphertext_sha256 FROM team_objects WHERE object_id = $1")
            .bind(expired_object)
            .fetch_one(pool)
            .await?;
    let path = root.join(&expired_object[..2]).join(format!("{expired_object}.{digest}.object"));
    sqlx::query(
        "UPDATE team_objects SET created_at = now() - interval '2 days', \
         expires_at = now() - interval '1 day' WHERE object_id = $1",
    )
    .bind(expired_object)
    .execute(pool)
    .await?;
    assert_eq!(administrator.apply_retention(Uuid::new_v4()).await?, 1);
    assert!(!path.exists());

    let (mut count, mut bytes): (i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint, coalesce(sum(plaintext_bytes), 0)::bigint FROM team_objects",
    )
    .fetch_one(pool)
    .await?;
    let mut fill_index = 1_u8;
    while count < 8 {
        let slots = usize::try_from(8 - count)?;
        let remaining = usize::try_from(16_384 - bytes)?;
        let size = 4_096.min(remaining - (slots - 1));
        let payload = vec![fill_index; size];
        operator.put_object(Uuid::new_v4(), TeamObjectKindV1::ExtensionArtifact, &payload).await?;
        count += 1;
        bytes += i64::try_from(size)?;
        fill_index = fill_index.saturating_add(1);
    }
    assert_eq!((count, bytes), (8, 16_384));
    assert!(operator
        .put_object(Uuid::new_v4(), TeamObjectKindV1::Evidence, b"capacity exhausted")
        .await
        .is_err());
    let persisted: (i64, i64) = sqlx::query_as(
        "SELECT count(*)::bigint, coalesce(sum(plaintext_bytes), 0)::bigint FROM team_objects",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(persisted, (8, 16_384));
    Ok(())
}

async fn assert_recovery_attribution(
    administrator: &TeamSession,
    pool: &PgPool,
) -> Result<(), Box<dyn Error>> {
    let object_id = "e".repeat(64);
    let ciphertext = recovery_envelope("alpha", &object_id, "primary")?;
    let input = RecoveryInput {
        cell_id: "alpha".into(),
        organization_id: "org-alpha".into(),
        project_id: administrator.principal().project_id,
        engagement_id: administrator.principal().engagement_id,
        database_identity_sha256: database_identity(pool).await?,
        migration_versions: (1..=14).collect(),
        database_snapshot: b"team recovery attribution fixture".to_vec(),
        objects: vec![(
            TeamRecoveryObjectV1 {
                object_id,
                ciphertext_sha256: sha256_hex(&ciphertext),
                stored_bytes: u64::try_from(ciphertext.len())?,
                key_id: "primary".into(),
            },
            ciphertext,
        )],
        created_at: DateTime::<Utc>::UNIX_EPOCH + chrono::Duration::seconds(1_700_000_000),
    };
    let manifest = create_recovery_manifest(&input)?;
    let destination = "f".repeat(64);
    administrator.verify_recovery(Uuid::new_v4(), &manifest, &input, &destination).await?;

    let cases: &[fn(&mut scorchkit::control_contract::TeamRecoveryManifestV1)] = &[
        |value| value.cell_id = "beta".into(),
        |value| value.organization_id = "org-beta".into(),
        |value| value.project_id = Uuid::new_v4(),
        |value| value.engagement_id = Uuid::new_v4(),
        |value| value.database_identity_sha256 = "d".repeat(64),
    ];
    for mutate in cases {
        let mut changed = manifest.clone();
        mutate(&mut changed);
        assert!(administrator
            .verify_recovery(Uuid::new_v4(), &changed, &input, &destination)
            .await
            .is_err());
    }
    Ok(())
}

async fn assert_identity_integrity(
    reader: &TeamSession,
    pool: &PgPool,
) -> Result<(), Box<dyn Error>> {
    sqlx::query("ALTER TABLE team_cell_identity DISABLE TRIGGER team_cell_identity_immutable")
        .execute(pool)
        .await?;
    for (column, corrupt, exact, uuid_value) in [
        ("cell_id", "corrupt-cell".to_string(), "alpha".to_string(), false),
        ("organization_id", "corrupt-organization".to_string(), "org-alpha".to_string(), false),
        (
            "engagement_id",
            Uuid::new_v4().to_string(),
            reader.principal().engagement_id.to_string(),
            true,
        ),
    ] {
        let parameter = if uuid_value { "$1::uuid" } else { "$1" };
        let update =
            format!("UPDATE team_cell_identity SET {column} = {parameter} WHERE singleton");
        sqlx::query(sqlx::AssertSqlSafe(update.clone())).bind(&corrupt).execute(pool).await?;
        let response = reader
            .execute_control(request(
                ControlQueryV1::GetProject { id: reader.principal().project_id },
                reader.principal().engagement_id,
            ))
            .await;
        assert!(matches!(
            response.result,
            ControlResponseOutcomeV1::Error(ref error)
                if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
        ));
        sqlx::query(sqlx::AssertSqlSafe(update)).bind(exact).execute(pool).await?;
    }
    sqlx::query("ALTER TABLE team_cell_identity ENABLE TRIGGER team_cell_identity_immutable")
        .execute(pool)
        .await?;

    let extra =
        scorchkit::storage::projects::create_project(pool, "corrupt-count", "fixture").await?;
    let response = reader
        .execute_control(request(
            ControlQueryV1::GetProject { id: reader.principal().project_id },
            reader.principal().engagement_id,
        ))
        .await;
    assert!(matches!(
        response.result,
        ControlResponseOutcomeV1::Error(ref error)
            if error.code == ControlErrorCodeV1::CanonicalProjectionMismatch
    ));
    assert!(scorchkit::storage::projects::delete_project(pool, extra.id).await?);
    Ok(())
}

async fn assert_audit_projection_integrity(
    administrator: &TeamSession,
    pool: &PgPool,
) -> Result<(), Box<dyn Error>> {
    let principal = administrator.principal();
    let cases = [
        (
            "corrupt-cell".to_string(),
            principal.organization_id.clone(),
            principal.project_id,
            principal.engagement_id,
        ),
        (
            principal.cell_id.clone(),
            "corrupt-organization".to_string(),
            principal.project_id,
            principal.engagement_id,
        ),
        (
            principal.cell_id.clone(),
            principal.organization_id.clone(),
            Uuid::new_v4(),
            principal.engagement_id,
        ),
        (
            principal.cell_id.clone(),
            principal.organization_id.clone(),
            principal.project_id,
            Uuid::new_v4(),
        ),
    ];
    for (cell_id, organization_id, project_id, engagement_id) in cases {
        let after: i64 =
            sqlx::query_scalar("SELECT coalesce(max(sequence), 0)::bigint FROM team_audit_events")
                .fetch_one(pool)
                .await?;
        let corrupt_request = Uuid::new_v4();
        sqlx::query("INSERT INTO team_request_ids (request_id) VALUES ($1)")
            .bind(corrupt_request)
            .execute(pool)
            .await?;
        sqlx::query(
            "INSERT INTO team_audit_events \
             (request_id, cell_id, organization_id, project_id, engagement_id, subject, role, action, outcome) \
             VALUES ($1, $2, $3, $4, $5, $6, 'administrator', 'fixture.corrupt', 'failed')",
        )
        .bind(corrupt_request)
        .bind(cell_id)
        .bind(organization_id)
        .bind(project_id)
        .bind(engagement_id)
        .bind(&principal.subject)
        .execute(pool)
        .await?;
        assert!(administrator
            .read_audit(Uuid::new_v4(), u64::try_from(after)?, 200)
            .await
            .is_err());
        sqlx::query("ALTER TABLE team_audit_events DISABLE TRIGGER team_audit_events_append_only")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM team_audit_events WHERE request_id = $1")
            .bind(corrupt_request)
            .execute(pool)
            .await?;
        sqlx::query("ALTER TABLE team_audit_events ENABLE TRIGGER team_audit_events_append_only")
            .execute(pool)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn two_real_cells_isolate_identity_rbac_objects_and_audit() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("scorchkit=warn"))
        .with_test_writer()
        .try_init();
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set — skipping team-service integration test");
        return Ok(());
    };
    let suffix = Uuid::new_v4().simple().to_string()[..12].to_owned();
    let names =
        vec![format!("scorchkit_team_{suffix}_alpha"), format!("scorchkit_team_{suffix}_beta")];
    let roots = vec![tempfile::tempdir()?, tempfile::tempdir()?];
    #[cfg(unix)]
    for root in &roots {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let admin_url = scoped_database_url(&database_url, "postgres")?;
    let admin = scorchkit::storage::connect(&admin_url).await?;
    let mut attempted = Vec::with_capacity(names.len());
    let result = Box::pin(async {
        for name in &names {
            attempted.push(name.clone());
            create_database(&admin, name, &suffix).await?;
        }
        Box::pin(exercise_two_cells(&database_url, &names, &roots)).await
    })
    .await;
    let cleanup = cleanup_databases(&admin, &attempted, &suffix).await;
    admin.close().await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(other_error(format!(
            "team-service qualification failed: {primary}; cleanup also failed: {cleanup}"
        ))
        .into()),
    }
}
