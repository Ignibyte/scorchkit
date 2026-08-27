use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use scorchkit::config::{ExtensionConfig, ExtensionTrustKeyConfig};
use scorchkit::extension::{
    CatalogLifecycle, ExtensionAdapterV1, ExtensionApprovalV1, ExtensionBudgetsV1,
    ExtensionCapabilityV1, ExtensionCatalogPayloadV1, ExtensionCatalogReleaseV1,
    ExtensionCatalogRevocationV1, ExtensionCompatibilityV1, ExtensionConformanceV1,
    ExtensionManifestV1, ExtensionModuleV1, ExtensionPermissionsV1, ExtensionReleaseProvenanceV1,
    ExtensionRuntimeV1, SignedExtensionCatalogV1, EXTENSION_ABI_V1,
    EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1, EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1,
    EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1, EXTENSION_MANIFEST_SCHEMA_V1, EXTENSION_PROTOCOL_V1,
};
use scorchkit::{runner::orchestrator::Orchestrator, Engine};
use scorchkit::{Capability, EffectClass, Engagement, EngagementPolicy, ScopeRule};
use scorchkit_core::{
    sha256_hex, AdapterOutputContract, AdapterTargetKind, LifecycleStage, ModuleOutcomeReason,
    ModuleOutcomeStatus, ProvenanceStrategy, SecurityDomain, TemporaryArtifactPolicy,
};

struct Fixture {
    catalog_path: PathBuf,
    config: ExtensionConfig,
    engagement: Engagement,
    signing_key: Ed25519KeyPair,
    payload: ExtensionCatalogPayloadV1,
}

fn module_bytes(abi: u32) -> Result<Vec<u8>, wat::Error> {
    wat::parse_str(format!(
        r#"(module
            (memory (export "memory") 1)
            (func (export "scorchkit_abi_version") (result i32) i32.const {abi})
            (func (export "scorchkit_reserve_input") (param i32) (result i32) i32.const 1024)
            (func (export "scorchkit_run") (param i32) (result i64) i64.const 1)
        )"#
    ))
}

fn manifest(module: &[u8], version: &str, module_file: &str) -> ExtensionManifestV1 {
    ExtensionManifestV1 {
        schema_version: EXTENSION_MANIFEST_SCHEMA_V1.to_string(),
        id: "fixture.extension".to_string(),
        name: "Fixture extension".to_string(),
        description: "Signed catalog integration fixture".to_string(),
        version: version.to_string(),
        compatibility: ExtensionCompatibilityV1 {
            minimum_engine_version: "3.0.0".to_string(),
            maximum_engine_version_exclusive: "4.0.0".to_string(),
        },
        module: ExtensionModuleV1 {
            runtime: ExtensionRuntimeV1::Wasm32UnknownUnknown,
            protocol_version: EXTENSION_PROTOCOL_V1.to_string(),
            abi_version: EXTENSION_ABI_V1,
            file: module_file.to_string(),
            sha256: sha256_hex(module),
        },
        input_schema: "fixture.input/v1".to_string(),
        output_schema: "fixture.output/v1".to_string(),
        adapter: ExtensionAdapterV1 {
            security_domain: SecurityDomain::ApplicationRuntime,
            lifecycle_stage: LifecycleStage::Runtime,
            target_kinds: vec![AdapterTargetKind::WebApplication],
            strongest_effect: EffectClass::ActiveSafe,
            output_contract: AdapterOutputContract::Json,
            provenance: ProvenanceStrategy::PluginDefinition,
            temporary_artifacts: TemporaryArtifactPolicy::None,
        },
        capabilities: vec![ExtensionCapabilityV1::NetworkHttp],
        budgets: ExtensionBudgetsV1 {
            timeout_ms: 5_000,
            fuel: 1_000_000,
            memory_bytes: 4 * 1024 * 1024,
            input_bytes: 64 * 1024,
            output_bytes: 64 * 1024,
            effects: 4,
            artifact_bytes: 64 * 1024,
            artifacts: 4,
        },
    }
}

fn release(
    root: &Path,
    release_id: &str,
    version: &str,
    manifest_file: &str,
    module_file: &str,
) -> Result<ExtensionCatalogReleaseV1, Box<dyn std::error::Error>> {
    let module = module_bytes(EXTENSION_ABI_V1)?;
    fs::write(root.join(module_file), &module)?;
    let manifest = manifest(&module, version, module_file);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(root.join(manifest_file), &manifest_bytes)?;
    let permissions =
        ExtensionPermissionsV1::from_manifest(&manifest, vec!["http://127.0.0.1".to_string()]);
    let permissions_sha256 = sha256_hex(&serde_json::to_vec(&permissions)?);
    Ok(ExtensionCatalogReleaseV1 {
        release_id: release_id.to_string(),
        extension_id: manifest.id,
        version: version.to_string(),
        manifest_file: manifest_file.to_string(),
        manifest_sha256: sha256_hex(&manifest_bytes),
        module_sha256: sha256_hex(&module),
        permissions,
        permissions_sha256,
        provenance: ExtensionReleaseProvenanceV1 {
            source: "local deterministic fixture".to_string(),
            revision: format!("revision-{version}"),
            build_sha256: sha256_hex(format!("build-{version}").as_bytes()),
        },
        conformance: ExtensionConformanceV1 {
            suite: "scorchkit.extension-conformance/v1".to_string(),
            passed: true,
            report_sha256: sha256_hex(format!("report-{version}").as_bytes()),
        },
    })
}

fn write_catalog(
    path: &Path,
    signing_key: &Ed25519KeyPair,
    payload: &ExtensionCatalogPayloadV1,
) -> Result<(), Box<dyn std::error::Error>> {
    write_catalog_with_key(path, signing_key, "fixture.key", payload)
}

fn write_catalog_with_key(
    path: &Path,
    signing_key: &Ed25519KeyPair,
    key_id: &str,
    payload: &ExtensionCatalogPayloadV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let mut signed = EXTENSION_CATALOG_SIGNATURE_DOMAIN_V1.to_vec();
    signed.extend_from_slice(&payload_bytes);
    let envelope = SignedExtensionCatalogV1 {
        schema_version: EXTENSION_CATALOG_ENVELOPE_SCHEMA_V1.to_string(),
        key_id: key_id.to_string(),
        payload_sha256: sha256_hex(&payload_bytes),
        payload_base64: base64::engine::general_purpose::STANDARD.encode(&payload_bytes),
        signature_base64: base64::engine::general_purpose::STANDARD
            .encode(signing_key.sign(&signed).as_ref()),
    };
    fs::write(path, serde_json::to_vec_pretty(&envelope)?)?;
    Ok(())
}

fn approve_inspected(
    lifecycle: &CatalogLifecycle<'_>,
    catalog_path: &Path,
    release_id: &str,
) -> Result<ExtensionApprovalV1, Box<dyn std::error::Error>> {
    let preview = lifecycle.inspect(catalog_path, release_id)?;
    Ok(lifecycle.approve(
        catalog_path,
        release_id,
        &preview.payload_sha256,
        &preview.permission_diff_sha256,
    )?)
}

fn inspect_error_after(
    mutate: impl FnOnce(&mut Fixture) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    mutate(&mut fixture)?;
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    match lifecycle.inspect(&fixture.catalog_path, "fixture.release-1") {
        Ok(_) => Err("mutated signed catalog was accepted".into()),
        Err(error) => Ok(error.to_string()),
    }
}

#[test]
fn accepted_catalog_sequence_cannot_be_replayed_into_approval_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let original = fixture.payload.clone();
    fixture.payload.sequence = 2;
    fixture.payload.releases.push(release(
        directory.path(),
        "fixture.release-2",
        "1.1.0",
        "release-2.json",
        "release-2.wasm",
    )?);
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-2")?;

    write_catalog(&fixture.catalog_path, &fixture.signing_key, &original)?;
    let replay = lifecycle.inspect(&fixture.catalog_path, "fixture.release-1")?;
    let error = lifecycle
        .approve(
            &fixture.catalog_path,
            "fixture.release-1",
            &replay.payload_sha256,
            &replay.permission_diff_sha256,
        )
        .expect_err("older signed sequence must not enter approval state");
    assert!(error.to_string().contains("replay"));
    assert_eq!(fs::read_dir(directory.path().join("lifecycle/approvals"))?.count(), 1);
    Ok(())
}

#[test]
fn approval_requires_the_exact_inspected_subject_and_rejects_sequence_equivocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let preview = lifecycle.inspect(&fixture.catalog_path, "fixture.release-1")?;
    let mismatch = lifecycle
        .approve(
            &fixture.catalog_path,
            "fixture.release-1",
            &"f".repeat(64),
            &preview.permission_diff_sha256,
        )
        .expect_err("unreviewed payload must not be approved");
    assert!(mismatch.to_string().contains("does not match"));

    lifecycle.approve(
        &fixture.catalog_path,
        "fixture.release-1",
        &preview.payload_sha256,
        &preview.permission_diff_sha256,
    )?;
    fixture.payload.valid_until = "2098-01-01T00:00:00Z".to_string();
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let equivocated = lifecycle.inspect(&fixture.catalog_path, "fixture.release-1")?;
    let error = lifecycle
        .approve(
            &fixture.catalog_path,
            "fixture.release-1",
            &equivocated.payload_sha256,
            &equivocated.permission_diff_sha256,
        )
        .expect_err("one sequence must not own two payloads");
    assert!(error.to_string().contains("equivocation"));
    assert_eq!(fs::read_dir(directory.path().join("lifecycle/approvals"))?.count(), 1);
    Ok(())
}

#[test]
fn orphaned_approval_cannot_activate_without_committed_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    let state_path = directory.path().join("lifecycle/state.json");
    fs::write(
        state_path,
        serde_json::to_vec_pretty(&scorchkit::extension::ExtensionLifecycleStateV1::default())?,
    )?;

    let error = lifecycle
        .activate(&approval.approval_id)
        .expect_err("orphaned approval record must not activate");
    assert!(error.to_string().contains("not committed"));
    Ok(())
}

#[test]
fn uncommitted_approval_cannot_borrow_another_approval_transition(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    fixture.payload.releases.push(release(
        directory.path(),
        "fixture.release-2",
        "1.1.0",
        "release-2.json",
        "release-2.wasm",
    )?);
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    let second = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-2")?;
    let state_path = directory.path().join("lifecycle/state.json");
    let mut state: scorchkit::extension::ExtensionLifecycleStateV1 =
        serde_json::from_slice(&fs::read(&state_path)?)?;
    state.transitions.truncate(1);
    fs::write(&state_path, serde_json::to_vec_pretty(&state)?)?;

    let error = lifecycle
        .activate(&second.approval_id)
        .expect_err("a neighboring approval transition must not authorize this approval");
    assert!(error.to_string().contains("not committed"));
    Ok(())
}

#[test]
fn active_pointer_must_reconstruct_from_append_preserved_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;
    let state_path = directory.path().join("lifecycle/state.json");
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&state_path)?)?;
    state["active"]["fixture.extension"] = serde_json::Value::String("f".repeat(64));
    fs::write(state_path, serde_json::to_vec_pretty(&state)?)?;

    let error = lifecycle.status().expect_err("unlinked active pointer must fail closed");
    assert!(error.to_string().contains("pointers"));
    Ok(())
}

#[test]
fn rotated_key_can_revoke_the_key_bound_to_an_active_approval(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let next_key = Ed25519KeyPair::from_seed_unchecked(&[8_u8; 32])
        .map_err(|_| "rotated Ed25519 fixture key was rejected")?;
    fixture.config.trust_keys.push(ExtensionTrustKeyConfig {
        key_id: "next".to_string(),
        publisher_id: "fixture.publisher".to_string(),
        public_key_base64: base64::engine::general_purpose::STANDARD
            .encode(next_key.public_key().as_ref()),
    });
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;

    fixture.payload.sequence = 2;
    fixture.payload.revocations.push(ExtensionCatalogRevocationV1 {
        release_id: None,
        key_id: Some("fixture.key".to_string()),
        reason: "publisher key rotation".to_string(),
    });
    write_catalog_with_key(&fixture.catalog_path, &next_key, "next", &fixture.payload)?;
    let error = lifecycle.load_active().expect_err("revoked approval key must deny");
    assert!(error.to_string().contains("revoked"));
    assert_eq!(lifecycle.status()?.active.get("fixture.extension"), Some(&approval.approval_id));
    Ok(())
}

#[test]
fn active_loading_checks_catalog_id_publisher_and_sequence_independently(
) -> Result<(), Box<dyn std::error::Error>> {
    {
        let directory = tempfile::tempdir()?;
        let mut fixture = fixture(directory.path())?;
        let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
        let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
        lifecycle.activate(&approval.approval_id)?;
        fixture.payload.catalog_id = "other.catalog".to_string();
        write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
        let error = lifecycle.load_active().expect_err("catalog identity drift must deny");
        assert!(error.to_string().contains("regressed or changed"));
    }
    {
        let directory = tempfile::tempdir()?;
        let mut fixture = fixture(directory.path())?;
        let other_key = Ed25519KeyPair::from_seed_unchecked(&[9_u8; 32])
            .map_err(|_| "alternate publisher key was rejected")?;
        fixture.config.trust_keys.push(ExtensionTrustKeyConfig {
            key_id: "other.key".to_string(),
            publisher_id: "other.publisher".to_string(),
            public_key_base64: base64::engine::general_purpose::STANDARD
                .encode(other_key.public_key().as_ref()),
        });
        let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
        let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
        lifecycle.activate(&approval.approval_id)?;
        fixture.payload.publisher_id = "other.publisher".to_string();
        write_catalog_with_key(&fixture.catalog_path, &other_key, "other.key", &fixture.payload)?;
        let error = lifecycle.load_active().expect_err("publisher identity drift must deny");
        assert!(error.to_string().contains("regressed or changed"));
    }
    {
        let directory = tempfile::tempdir()?;
        let mut fixture = fixture(directory.path())?;
        fixture.payload.sequence = 2;
        write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
        let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
        let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
        lifecycle.activate(&approval.approval_id)?;
        fixture.payload.sequence = 1;
        write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
        let error = lifecycle.load_active().expect_err("catalog sequence regression must deny");
        assert!(error.to_string().contains("regressed or changed"));
    }
    Ok(())
}

fn fixture(root: &Path) -> Result<Fixture, Box<dyn std::error::Error>> {
    let signing_key = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32])
        .map_err(|_| "deterministic Ed25519 fixture key was rejected")?;
    let release = release(root, "fixture.release-1", "1.0.0", "release-1.json", "release-1.wasm")?;
    let payload = ExtensionCatalogPayloadV1 {
        schema_version: EXTENSION_CATALOG_PAYLOAD_SCHEMA_V1.to_string(),
        catalog_id: "fixture.catalog".to_string(),
        publisher_id: "fixture.publisher".to_string(),
        sequence: 1,
        valid_from: "2020-01-01T00:00:00Z".to_string(),
        valid_until: "2099-01-01T00:00:00Z".to_string(),
        releases: vec![release],
        revocations: Vec::new(),
    };
    let catalog_path = root.join("catalog.json");
    write_catalog(&catalog_path, &signing_key, &payload)?;
    let config = ExtensionConfig {
        catalogs: vec![catalog_path.clone()],
        trust_keys: vec![ExtensionTrustKeyConfig {
            key_id: "fixture.key".to_string(),
            publisher_id: "fixture.publisher".to_string(),
            public_key_base64: base64::engine::general_purpose::STANDARD
                .encode(signing_key.public_key().as_ref()),
        }],
        lifecycle_root: Some(root.join("lifecycle")),
        ..ExtensionConfig::default()
    };
    let policy = EngagementPolicy::default()
        .allow_scope(ScopeRule::Exact("127.0.0.1".to_string()))
        .allow_scope(ScopeRule::path_prefix(root)?)
        .allow_capability(Capability::DastScan)
        .allow_capability(Capability::ExternalTool)
        .allow_capability(Capability::LocalState)
        .allow_capability(Capability::ExtensionExecute)
        .allow_effect(EffectClass::Passive)
        .allow_effect(EffectClass::ActiveSafe)
        .allow_effect(EffectClass::Intrusive);
    let engagement = Engagement::new("catalog-fixture", policy);
    Ok(Fixture { catalog_path, config, engagement, signing_key, payload })
}

#[tokio::test]
async fn revocation_added_after_registration_denies_before_worker_start(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;

    let engine = Engine::for_engagement(
        std::sync::Arc::new(scorchkit::config::AppConfig {
            extensions: fixture.config.clone(),
            ..scorchkit::config::AppConfig::default()
        }),
        std::sync::Arc::new(fixture.engagement.clone()),
    );
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_default_modules();
    orchestrator.filter_by_ids(&["fixture.extension".to_string()]);

    fixture.payload.sequence = 2;
    fixture.payload.revocations.push(ExtensionCatalogRevocationV1 {
        release_id: Some("fixture.release-1".to_string()),
        key_id: None,
        reason: "revoked after registration".to_string(),
    });
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;

    let result = orchestrator.run(true).await?;
    assert_eq!(result.module_outcomes.len(), 1);
    assert_eq!(result.module_outcomes[0].status, ModuleOutcomeStatus::Failed);
    assert!(matches!(
        result.module_outcomes[0].reason.as_ref(),
        Some(ModuleOutcomeReason::ExecutionFailed { message }) if message.contains("revoked")
    ));
    Ok(())
}

#[tokio::test]
async fn catalog_and_explicit_registration_share_one_global_identity_namespace(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;
    fixture.config.manifests.push(directory.path().join("release-1.json"));

    let engine = Engine::for_engagement(
        std::sync::Arc::new(scorchkit::config::AppConfig {
            extensions: fixture.config,
            ..scorchkit::config::AppConfig::default()
        }),
        std::sync::Arc::new(fixture.engagement),
    );
    let context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut orchestrator = Orchestrator::new(context);
    orchestrator.register_default_modules();
    let error = orchestrator.run(true).await.expect_err("duplicate global extension identity");
    assert!(error.to_string().contains("duplicate extension module identity"));
    Ok(())
}

#[test]
fn signed_release_is_approved_activated_and_reopened_offline(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);

    let preview = lifecycle.inspect(&fixture.catalog_path, "fixture.release-1")?;
    assert_eq!(preview.extension_id, "fixture.extension");
    assert!(preview.permission_changes.iter().all(|change| change.widened));
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;
    fs::remove_file(&fixture.catalog_path)?;

    let active = lifecycle.load_active()?;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].manifest.version, "1.0.0");
    assert_eq!(lifecycle.status()?.active.get("fixture.extension"), Some(&approval.approval_id));
    Ok(())
}

#[cfg(unix)]
#[test]
fn dangling_catalog_symlink_is_invalid_present_state_not_offline(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;
    fs::remove_file(&fixture.catalog_path)?;
    symlink(directory.path().join("missing-catalog.json"), &fixture.catalog_path)?;

    let error = lifecycle
        .load_active()
        .expect_err("present symlink must not bypass current-catalog validation");
    assert!(error.to_string().contains("regular non-symlink file"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn lifecycle_files_are_owner_private_and_public_state_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;
    let root = directory.path().join("lifecycle");
    let state_path = root.join("state.json");
    let approval_path = root.join("approvals").join(format!("{}.json", approval.approval_id));
    for path in [&root, &root.join("approvals")] {
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o077, 0);
    }
    for path in [&state_path, &root.join(".lifecycle.lock"), &approval_path] {
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o077, 0);
    }

    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o644))?;
    let error = lifecycle.status().expect_err("public lifecycle state must fail closed");
    assert!(error.to_string().contains("not private"));
    Ok(())
}

#[test]
fn trusted_revocation_blocks_activation_but_preserves_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    fixture.payload.sequence = 2;
    fixture.payload.revocations.push(ExtensionCatalogRevocationV1 {
        release_id: Some("fixture.release-1".to_string()),
        key_id: None,
        reason: "fixture withdrawal".to_string(),
    });
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;

    let error = lifecycle.activate(&approval.approval_id).expect_err("revocation must deny");
    assert!(error.to_string().contains("revoked"));
    let status = lifecycle.status()?;
    assert!(status.active.is_empty());
    assert_eq!(status.transitions.len(), 1);
    Ok(())
}

#[test]
fn failed_upgrade_health_keeps_the_previous_active_pointer(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    fixture.payload.releases.push(release(
        directory.path(),
        "fixture.release-2",
        "1.1.0",
        "release-2.json",
        "release-2.wasm",
    )?);
    let incompatible_module = module_bytes(99)?;
    fs::write(directory.path().join("release-2.wasm"), &incompatible_module)?;
    let incompatible_manifest = manifest(&incompatible_module, "1.1.0", "release-2.wasm");
    let incompatible_manifest_bytes = serde_json::to_vec_pretty(&incompatible_manifest)?;
    fs::write(directory.path().join("release-2.json"), &incompatible_manifest_bytes)?;
    let incompatible_release =
        fixture.payload.releases.last_mut().ok_or("second release missing")?;
    incompatible_release.manifest_sha256 = sha256_hex(&incompatible_manifest_bytes);
    incompatible_release.module_sha256 = sha256_hex(&incompatible_module);
    incompatible_release.permissions = ExtensionPermissionsV1::from_manifest(
        &incompatible_manifest,
        incompatible_release.permissions.network_endpoints.clone(),
    );
    incompatible_release.permissions_sha256 =
        sha256_hex(&serde_json::to_vec(&incompatible_release.permissions)?);
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let first = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&first.approval_id)?;
    let second = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-2")?;

    let error = lifecycle
        .activate(&second.approval_id)
        .expect_err("unsupported signed ABI must fail activation health");
    assert!(error.to_string().contains("ABI is unsupported"));
    assert_eq!(lifecycle.status()?.active.get("fixture.extension"), Some(&first.approval_id));
    Ok(())
}

#[test]
fn explicit_rollback_reactivates_only_the_named_prior_approval(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    fixture.payload.releases.push(release(
        directory.path(),
        "fixture.release-2",
        "1.1.0",
        "release-2.json",
        "release-2.wasm",
    )?);
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let first = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&first.approval_id)?;
    let second = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-2")?;
    lifecycle.activate(&second.approval_id)?;

    lifecycle.rollback("fixture.extension", &first.approval_id)?;
    let status = lifecycle.status()?;
    assert_eq!(status.active.get("fixture.extension"), Some(&first.approval_id));
    assert_eq!(status.transitions.last().map(|value| value.action.as_str()), Some("rollback"));
    assert!(lifecycle.rollback("other.extension", &first.approval_id).is_err());
    Ok(())
}

#[test]
fn modified_immutable_approval_is_rejected_before_activation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    let path =
        directory.path().join("lifecycle/approvals").join(format!("{}.json", approval.approval_id));
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    value["permission_diff_sha256"] = serde_json::Value::String("f".repeat(64));
    fs::write(path, serde_json::to_vec_pretty(&value)?)?;

    let error = lifecycle.activate(&approval.approval_id).expect_err("modified approval");
    assert!(error.to_string().contains("integrity"));
    assert!(lifecycle.status()?.active.is_empty());
    Ok(())
}

#[test]
fn signature_and_publisher_tampering_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let fixture = fixture(directory.path())?;
    let mut envelope: SignedExtensionCatalogV1 =
        serde_json::from_slice(&fs::read(&fixture.catalog_path)?)?;
    let replacement = if envelope.signature_base64.starts_with('A') { "B" } else { "A" };
    envelope.signature_base64.replace_range(..1, replacement);
    fs::write(&fixture.catalog_path, serde_json::to_vec_pretty(&envelope)?)?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    assert!(lifecycle.inspect(&fixture.catalog_path, "fixture.release-1").is_err());

    let mut wrong_publisher = fixture.payload;
    wrong_publisher.publisher_id = "other.publisher".to_string();
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &wrong_publisher)?;
    let error = lifecycle
        .inspect(&fixture.catalog_path, "fixture.release-1")
        .expect_err("publisher mismatch must deny");
    assert!(error.to_string().contains("publisher"));
    Ok(())
}

#[test]
fn catalog_validity_checks_order_start_and_end_as_independent_boundaries(
) -> Result<(), Box<dyn std::error::Error>> {
    let reversed = inspect_error_after(|fixture| {
        fixture.payload.valid_from = "2099-01-01T00:00:00Z".to_string();
        fixture.payload.valid_until = "2020-01-01T00:00:00Z".to_string();
        Ok(())
    })?;
    assert!(reversed.contains("validity interval"));
    let future = inspect_error_after(|fixture| {
        fixture.payload.valid_from = "2098-01-01T00:00:00Z".to_string();
        Ok(())
    })?;
    assert!(future.contains("validity interval"));
    let expired = inspect_error_after(|fixture| {
        fixture.payload.valid_until = "2021-01-01T00:00:00Z".to_string();
        Ok(())
    })?;
    assert!(expired.contains("validity interval"));
    Ok(())
}

#[test]
fn release_verification_checks_every_artifact_identity_and_permission_clause(
) -> Result<(), Box<dyn std::error::Error>> {
    for mutate in [
        |release: &mut ExtensionCatalogReleaseV1| release.manifest_sha256 = "f".repeat(64),
        |release: &mut ExtensionCatalogReleaseV1| release.module_sha256 = "f".repeat(64),
        |release: &mut ExtensionCatalogReleaseV1| {
            release.extension_id = "other.extension".to_string();
        },
        |release: &mut ExtensionCatalogReleaseV1| release.version = "9.9.9".to_string(),
    ] {
        let error = inspect_error_after(|fixture| {
            mutate(&mut fixture.payload.releases[0]);
            Ok(())
        })?;
        assert!(error.contains("artifact identity"), "unexpected error: {error}");
    }

    let mismatch = inspect_error_after(|fixture| {
        let release = &mut fixture.payload.releases[0];
        release.permissions.budgets.timeout_ms += 1;
        release.permissions_sha256 = sha256_hex(&serde_json::to_vec(&release.permissions)?);
        Ok(())
    })?;
    assert!(mismatch.contains("permissions do not match"));

    let missing_capability = inspect_error_after(|fixture| {
        let root = fixture.catalog_path.parent().ok_or("catalog fixture has no parent")?;
        let module = fs::read(root.join("release-1.wasm"))?;
        let mut changed_manifest = manifest(&module, "1.0.0", "release-1.wasm");
        changed_manifest.capabilities.clear();
        let manifest_bytes = serde_json::to_vec_pretty(&changed_manifest)?;
        fs::write(root.join("release-1.json"), &manifest_bytes)?;
        let release = &mut fixture.payload.releases[0];
        release.manifest_sha256 = sha256_hex(&manifest_bytes);
        release.permissions = ExtensionPermissionsV1::from_manifest(
            &changed_manifest,
            vec!["http://127.0.0.1".to_string()],
        );
        release.permissions_sha256 = sha256_hex(&serde_json::to_vec(&release.permissions)?);
        Ok(())
    })?;
    assert!(missing_capability.contains("permissions do not match"));
    Ok(())
}

#[tokio::test]
async fn runtime_revocation_check_accepts_exact_sequence_and_rejects_equal_sequence_equivocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut fixture = fixture(directory.path())?;
    let lifecycle = CatalogLifecycle::new(&fixture.config, &fixture.engagement);
    let approval = approve_inspected(&lifecycle, &fixture.catalog_path, "fixture.release-1")?;
    lifecycle.activate(&approval.approval_id)?;

    let engine = Engine::for_engagement(
        std::sync::Arc::new(scorchkit::config::AppConfig {
            extensions: fixture.config.clone(),
            ..scorchkit::config::AppConfig::default()
        }),
        std::sync::Arc::new(fixture.engagement.clone()),
    );
    let exact_context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut exact = Orchestrator::new(exact_context);
    exact.register_default_modules();
    exact.filter_by_ids(&["fixture.extension".to_string()]);
    let changed_context = engine.dast_context("http://127.0.0.1/", "standard")?;
    let mut changed = Orchestrator::new(changed_context);
    changed.register_default_modules();
    changed.filter_by_ids(&["fixture.extension".to_string()]);

    let exact_result = exact.run(true).await?;
    assert_eq!(exact_result.module_outcomes.len(), 1);
    assert!(!format!("{:?}", exact_result.module_outcomes[0].reason).contains("equivocation"));

    fixture.payload.valid_until = "2098-01-01T00:00:00Z".to_string();
    write_catalog(&fixture.catalog_path, &fixture.signing_key, &fixture.payload)?;
    let changed_result = changed.run(true).await?;
    assert!(matches!(
        changed_result.module_outcomes[0].reason.as_ref(),
        Some(ModuleOutcomeReason::ExecutionFailed { message }) if message.contains("equivocation")
    ));
    Ok(())
}

#[test]
fn catalog_cli_propagates_lifecycle_errors_instead_of_reporting_success(
) -> Result<(), Box<dyn std::error::Error>> {
    Command::cargo_bin("scorchkit")?.args(["catalog", "status"]).assert().failure();
    Ok(())
}
