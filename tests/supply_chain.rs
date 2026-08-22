use std::sync::Arc;

use scorchkit::config::AppConfig;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::{Engine, ProviderSnapshotState, SupplyChainCoverageStatus, SupplyChainTargetKind};

fn local_engine(
    target: &std::path::Path,
    cache: &std::path::Path,
) -> scorchkit::engine::error::Result<Engine> {
    let mut config = AppConfig::default();
    config.supply_chain.cache_root = cache.to_path_buf();
    config.tools.syft = Some("/fixture/missing-syft".to_string());
    config.tools.osv_scanner = Some("/fixture/missing-osv-scanner".to_string());
    config.tools.grype = Some("/fixture/missing-grype".to_string());
    config.tools.trivy = Some("/fixture/missing-trivy".to_string());
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::path_prefix(target)?)
        .allow_scope(ScopeRule::path_prefix(cache)?)
        .allow_capability(Capability::CodeScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::LocalState)
        .allow_effect(EffectClass::Passive);
    Ok(Engine::for_engagement(
        Arc::new(config),
        Arc::new(Engagement::new("local supply-chain fixture", policy)),
    ))
}

#[cfg(unix)]
fn make_private(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn make_private(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::metadata(path)?;
    Ok(())
}

#[tokio::test]
async fn public_artifact_scan_preserves_explicit_kind_and_incomplete_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir().expect("fixture root");
    let cache = root.path().join("cache");
    std::fs::create_dir(&cache).expect("cache root");
    make_private(&cache)?;
    let sbom = root.path().join("application.cdx.json");
    std::fs::write(
        &sbom,
        r#"{
          "bomFormat":"CycloneDX",
          "specVersion":"1.6",
          "version":1,
          "components":[{
            "type":"library",
            "bom-ref":"pkg:npm/lodash@4.17.20",
            "name":"lodash",
            "version":"4.17.20",
            "purl":"pkg:npm/lodash@4.17.20"
          }],
          "dependencies":[{"ref":"pkg:npm/lodash@4.17.20"}]
        }"#,
    )
    .expect("SBOM fixture");

    let result = local_engine(&sbom, &cache)?
        .supply_chain_scan_with_profile(
            &sbom,
            SupplyChainTargetKind::CycloneDxSbom,
            "standard",
            Some("fixture-revision".to_string()),
        )
        .await
        .expect("local artifact result");

    let assessment = result.supply_chain.expect("canonical supply-chain evidence");
    assert_eq!(assessment.target.kind, SupplyChainTargetKind::CycloneDxSbom);
    assert_eq!(assessment.target.revision.as_deref(), Some("fixture-revision"));
    assert_eq!(assessment.coverage_status, SupplyChainCoverageStatus::Incomplete);
    assert!(assessment.sbom.is_some());
    assert!(assessment.gaps.iter().any(|gap| gap.component.as_deref() == Some("grype")));
    Ok(())
}

#[test]
fn public_cache_status_distinguishes_missing_snapshots() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir().expect("fixture root");
    let target = root.path().join("target");
    let cache = root.path().join("cache");
    std::fs::create_dir(&target).expect("target root");
    std::fs::create_dir(&cache).expect("cache root");
    make_private(&cache)?;
    let statuses = local_engine(&target, &cache)?.supply_chain_cache_status()?;
    assert_eq!(statuses.len(), 3);
    assert!(statuses.iter().all(|snapshot| snapshot.state == ProviderSnapshotState::Missing));
    Ok(())
}

#[tokio::test]
async fn explicit_target_shape_is_rejected_before_local_state_is_created(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir().expect("fixture root");
    let target = root.path().join("artifact.bin");
    let cache = root.path().join("cache");
    std::fs::write(&target, b"artifact").expect("target file");
    std::fs::create_dir(&cache).expect("cache root");
    make_private(&cache)?;
    let error = local_engine(&target, &cache)?
        .supply_chain_scan_with_profile(
            &target,
            SupplyChainTargetKind::DirectoryArtifact,
            "standard",
            None,
        )
        .await
        .expect_err("file cannot be reinterpreted as a directory artifact");
    assert!(error.to_string().contains("requires a directory"));
    assert!(!cache.join("runs").exists());
    Ok(())
}
