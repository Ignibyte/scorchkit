use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use scorchkit::config::AppConfig;
use scorchkit::runner::orchestrator::Orchestrator;
use scorchkit::{Capability, EffectClass, Engagement, EngagementPolicy, Engine, ScopeRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires the checksum-verified Nuclei 3.11.1 binary"]
async fn signed_collection_runs_against_loopback_with_exact_execution_evidence() {
    let binary = std::env::var("SCORCHKIT_NUCLEI_BIN")
        .unwrap_or_else(|_| "/mnt/fast/scorchkit/tools/nuclei/v3.11.1/nuclei".to_string());
    assert!(std::path::Path::new(&binary).is_file(), "missing pinned Nuclei binary");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("Nuclei request timeout")
            .expect("accept Nuclei request");
        let mut request = vec![0_u8; 8 * 1024];
        let read = stream.read(&mut request).await.expect("read request");
        assert!(
            String::from_utf8_lossy(&request[..read])
                .starts_with("GET /scorchkit-nuclei-fixture HTTP/1.1"),
            "unexpected request"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\nscorchkit-trusted-nuclei",
            )
            .await
            .expect("write response");
    });

    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/nuclei")
        .canonicalize()
        .expect("fixture root");
    let manifest = fixture_root.join("collection.json");
    let mut config = AppConfig::default();
    config.tools.nuclei = Some(binary);
    config.nuclei.collection_manifest = Some(manifest);
    config.scan.follow_redirects = false;

    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
        .allow_scope(ScopeRule::path_prefix(&fixture_root).expect("fixture scope"))
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    let engine = Engine::for_engagement(
        Arc::new(config),
        Arc::new(Engagement::new("trusted Nuclei loopback", policy)),
    );
    let context =
        engine.dast_context(&format!("http://{address}"), "thorough").expect("authorized context");
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_default_modules();
    orchestrator.filter_by_ids(&["nuclei".to_string()]);
    let result = orchestrator.run(true).await.expect("trusted Nuclei scan");
    server.await.expect("loopback server");

    assert_eq!(
        result.execution_status,
        scorchkit::engine::scan_result::ScanExecutionStatus::Complete,
        "{}",
        serde_json::to_string_pretty(&result).expect("result JSON")
    );
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.adapter_executions.len(), 1);
    let assessment = &result.adapter_executions[0];
    assert_eq!(assessment.status, scorchkit::AdapterExecutionStatus::Complete);
    assert_eq!(assessment.tool_version.as_deref(), Some("3.11.1"));
    assert_eq!(assessment.inputs.len(), 1);
    assert_eq!(assessment.inputs[0].signer_identity.as_deref(), Some("scorchkit-test-signer"));
}
