//! Explicit build-host integration checks for the pinned ZAP application DAST runtime.

use std::sync::Arc;

use httpmock::prelude::*;
use scorchkit::application_dast::{ApplicationDastRequest, ApplicationDastSchemaRequest};
use scorchkit::config::{AppConfig, DastPersonaConfig, DastVerificationConfig};
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::facade::Engine;
use scorchkit::{ApplicationDastProfile, ApplicationDastSchemaKind};

fn pinned_zap_path() -> Result<String, std::env::VarError> {
    std::env::var("SCORCHKIT_ZAP_PATH")
}

fn config_with_zap() -> Result<AppConfig, std::env::VarError> {
    let mut config = AppConfig::default();
    config.tools.zap = Some(pinned_zap_path()?);
    config.tools.chromedriver = Some(
        std::env::var("SCORCHKIT_CHROMEDRIVER_PATH").unwrap_or_else(|_| "chromedriver".to_string()),
    );
    config.dast.timeout_seconds = 180;
    config.dast.spider_minutes = 1;
    config.dast.client_spider_minutes = 1;
    config.dast.active_scan_minutes = 1;
    Ok(config)
}

fn engine(config: AppConfig, local_scope: Option<ScopeRule>, credentials: bool) -> Option<Engine> {
    let mut policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::parse("127.0.0.1")?)
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::Intrusive);
    if let Some(scope) = local_scope {
        policy = policy.allow_scope(scope).allow_capability(Capability::LocalState);
    }
    if credentials {
        policy = policy
            .allow_capability(Capability::CredentialUse)
            .allow_effect(EffectClass::CredentialTest);
    }
    Some(Engine::for_engagement(
        Arc::new(config),
        Arc::new(Engagement::new("pinned ZAP loopback integration", policy)),
    ))
}

#[tokio::test]
#[ignore = "requires the checksum-verified build-host ZAP 2.17.0 runtime"]
async fn pinned_zap_imports_an_openapi_schema_under_the_authorized_base() {
    let server = MockServer::start_async().await;
    let root = server
        .mock_async(|when, then| {
            when.method(GET).path("/app");
            then.status(200).body("<a href=\"/app/users\">users</a>");
        })
        .await;
    let users = server
        .mock_async(|when, then| {
            when.method(GET).path("/app/users");
            then.status(200).json_body(serde_json::json!({"users": []}));
        })
        .await;
    let directory = tempfile::tempdir().expect("temporary schema directory");
    let schema_path = directory.path().join("openapi.yaml");
    let schema = br"openapi: 3.0.3
info:
  title: loopback
  version: 1.0.0
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        '200':
          description: ok
";
    std::fs::write(&schema_path, schema).expect("write schema");
    let request = ApplicationDastRequest {
        target: server.url("/app"),
        profile: ApplicationDastProfile::Passive,
        include_anonymous: true,
        personas: Vec::new(),
        schemas: vec![ApplicationDastSchemaRequest {
            kind: ApplicationDastSchemaKind::OpenApi,
            path: schema_path,
            sha256: scorchkit::engine::observation::sha256_hex(schema),
            endpoint: None,
        }],
    };
    let result = engine(
        config_with_zap().expect("set SCORCHKIT_ZAP_PATH to the pinned ZAP launcher"),
        Some(ScopeRule::path_prefix(directory.path()).expect("schema scope")),
        false,
    )
    .expect("loopback scope")
    .application_dast(&request)
    .await
    .expect("application DAST result");
    let assessment = result.application_dast.expect("DAST assessment");
    let assessment_json =
        serde_json::to_string_pretty(&assessment).expect("serialize DAST assessment");
    let route = assessment.personas[0]
        .routes
        .iter()
        .find(|route| route.operation_id.as_deref() == Some("listUsers"))
        .unwrap_or_else(|| panic!("schema operation coverage: {assessment_json}"));
    assert_eq!(route.route, "/app/users");
    assert!(route.observed);
    assert!(root.calls_async().await > 0);
    assert!(users.calls_async().await > 0);
}

#[tokio::test]
#[ignore = "requires the checksum-verified build-host ZAP 2.17.0 runtime"]
async fn pinned_zap_verifies_header_authentication_without_plan_secrets() {
    let server = MockServer::start_async().await;
    let root = server
        .mock_async(|when, then| {
            when.method(GET).path("/app").header("X-Session", "header-fixture-secret");
            then.status(200).body("<a href=\"/app/account\">account</a>");
        })
        .await;
    let account = server
        .mock_async(|when, then| {
            when.method(GET).path("/app/account").header("X-Session", "header-fixture-secret");
            then.status(200).body("Account");
        })
        .await;
    let mut config = config_with_zap().expect("set SCORCHKIT_ZAP_PATH to the pinned ZAP launcher");
    config.dast.personas.insert(
        "user".to_string(),
        DastPersonaConfig::Header {
            header_name: "X-Session".to_string(),
            value_env: "SCORCHKIT_ZAP_HEADER_SECRET".to_string(),
            verification: DastVerificationConfig {
                url: server.url("/app/account"),
                expected_status: 200,
                logged_in_regex: "Account".to_string(),
                logged_out_regex: "Sign in".to_string(),
                max_logged_out: 0,
            },
        },
    );
    let request = ApplicationDastRequest {
        target: server.url("/app"),
        profile: ApplicationDastProfile::Passive,
        include_anonymous: false,
        personas: vec!["user".to_string()],
        schemas: Vec::new(),
    };
    let result = engine(config, None, true)
        .expect("loopback scope")
        .application_dast(&request)
        .await
        .expect("header DAST result");
    let assessment = result.application_dast.expect("DAST assessment");
    let assessment_json =
        serde_json::to_string_pretty(&assessment).expect("serialize DAST assessment");
    assert_eq!(
        assessment.personas[0].authentication,
        scorchkit::ApplicationDastAuthenticationState::Verified,
        "{assessment_json}"
    );
    assert!(!serde_json::to_string(&assessment)
        .expect("assessment JSON")
        .contains("header-fixture-secret"));
    assert!(root.calls_async().await > 0);
    assert!(account.calls_async().await > 0);
}

#[tokio::test]
#[ignore = "requires the checksum-verified build-host ZAP 2.17.0 runtime and headless Chrome"]
async fn pinned_zap_verifies_browser_authentication_on_loopback() {
    let server = MockServer::start_async().await;
    let root = server
        .mock_async(|when, then| {
            when.method(GET).path("/app").header("Cookie", "session=browser-fixture-session");
            then.status(200).body("<a href=\"/app/account\">account</a>");
        })
        .await;
    let login_page = server
        .mock_async(|when, then| {
            when.method(GET).path("/app/login");
            then.status(200).body(
                "<!doctype html><html><body><form method=\"post\" action=\"/app/login\"><label for=\"username\">Username</label><input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\"><label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\"><button id=\"login\" type=\"submit\">Sign in</button></form></body></html>",
            );
        })
        .await;
    let login = server
        .mock_async(|when, then| {
            when.method(POST)
                .path("/app/login")
                .body_includes("username=fixture-user")
                .body_includes("password=browser-fixture-secret");
            then.status(302).header("Location", "/app/account").header(
                "Set-Cookie",
                "session=browser-fixture-session; Path=/app; HttpOnly; SameSite=Lax",
            );
        })
        .await;
    let account_with_session = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/app/account")
                .header("Cookie", "session=browser-fixture-session");
            then.status(200).body("Account");
        })
        .await;
    let logged_out = server
        .mock_async(|when, then| {
            when.method(GET).path("/app/account").header_missing("Cookie");
            then.status(200).body("Sign in");
        })
        .await;
    let mut config = config_with_zap().expect("set SCORCHKIT_ZAP_PATH to the pinned ZAP launcher");
    config.dast.personas.insert(
        "browser".to_string(),
        DastPersonaConfig::Browser {
            login_url: server.url("/app/login"),
            username_env: "SCORCHKIT_ZAP_BROWSER_USER".to_string(),
            password_env: "SCORCHKIT_ZAP_BROWSER_PASSWORD".to_string(),
            verification: DastVerificationConfig {
                url: server.url("/app/account"),
                expected_status: 200,
                logged_in_regex: "Account".to_string(),
                logged_out_regex: "Sign in".to_string(),
                max_logged_out: 32,
            },
        },
    );
    let request = ApplicationDastRequest {
        target: server.url("/app"),
        profile: ApplicationDastProfile::Passive,
        include_anonymous: false,
        personas: vec!["browser".to_string()],
        schemas: Vec::new(),
    };
    let result = engine(config, None, true)
        .expect("loopback scope")
        .application_dast(&request)
        .await
        .expect("browser DAST result");
    let assessment = result.application_dast.expect("DAST assessment");
    let assessment_json =
        serde_json::to_string_pretty(&assessment).expect("serialize DAST assessment");
    let login_page_calls = login_page.calls_async().await;
    let login_calls = login.calls_async().await;
    let root_calls = root.calls_async().await;
    let account_with_session_calls = account_with_session.calls_async().await;
    let logged_out_calls = logged_out.calls_async().await;
    assert_eq!(
        assessment.personas[0].authentication,
        scorchkit::ApplicationDastAuthenticationState::Verified,
        "{assessment_json}\nlogin_page={login_page_calls} login={login_calls} root={root_calls} account_with_session={account_with_session_calls} logged_out={logged_out_calls}"
    );
    let encoded = serde_json::to_string(&assessment).expect("assessment JSON");
    assert!(!encoded.contains("fixture-user"));
    assert!(!encoded.contains("browser-fixture-secret"));
    assert!(!encoded.contains("browser-fixture-session"));
    assert!(login_page_calls > 0);
    assert!(login_calls > 0);
    assert!(root_calls > 0);
    assert!(account_with_session_calls > 0);
    assert!(logged_out_calls <= 32);
}
