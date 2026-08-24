use tokio::io::{stdin, stdout};
use wasmi::{
    CompilationMode, Config, EnforcedLimits, Engine, ExternType, Linker, Module, Store,
    StoreLimits, StoreLimitsBuilder,
};

use scorchkit_core::sha256_hex;
use scorchkit_extension::{
    ExtensionInvocationV1, ExtensionTurnInputV1, ExtensionTurnOutputV1, EXTENSION_ABI_V1,
    EXTENSION_PROTOCOL_V1, MAX_EXTENSION_MODULE_BYTES,
};

use crate::engine::error::{Result, ScorchError};

use super::runtime::{read_json_frame, read_raw, write_json_frame, WorkerStartV1};

const MAX_EXTENSION_TABLE_ELEMENTS: usize = 10_000;

#[derive(Debug)]
struct WorkerState {
    limits: StoreLimits,
}

// JUSTIFICATION: Worker setup and the turn loop share one Wasmi store whose lifetime cannot be
// separated without hiding the exact resource and ABI validation sequence.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_stdio() -> Result<()> {
    let mut input = stdin();
    let mut output = stdout();
    let start: WorkerStartV1 = read_json_frame(&mut input, 512 * 1024).await?;
    if start.schema_version != "scorchkit.extension-worker-start/v1" {
        return Err(protocol_error("unsupported worker start schema"));
    }
    start.manifest.validate().map_err(|_| protocol_error("worker received an invalid manifest"))?;
    start
        .manifest
        .require_compatible_engine(env!("CARGO_PKG_VERSION"))
        .map_err(|_| protocol_error("worker received an incompatible manifest"))?;
    validate_invocation(&start.invocation, &start.manifest)?;
    let module_bytes = read_raw(&mut input, start.module_bytes, MAX_EXTENSION_MODULE_BYTES).await?;
    if sha256_hex(&module_bytes) != start.manifest.module.sha256 {
        return Err(protocol_error("worker module digest mismatch"));
    }

    let mut config = Config::default();
    config
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .enforced_limits(EnforcedLimits::strict())
        .set_max_recursion_depth(256)
        .set_max_stack_height(1024 * 1024)
        .set_max_cached_stacks(0)
        .wasm_multi_memory(false)
        .wasm_memory64(false)
        .wasm_tail_call(false);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, &module_bytes[..])
        .map_err(|_| protocol_error("extension module validation failed"))?;
    if module.imports().next().is_some() {
        return Err(protocol_error("extension module imports are forbidden"));
    }
    validate_exports(&module)?;
    let memory_limit = usize::try_from(start.manifest.budgets.memory_bytes)
        .map_err(|_| protocol_error("extension memory limit is unsupported"))?;
    let state = WorkerState {
        limits: StoreLimitsBuilder::new()
            .memory_size(memory_limit)
            .table_elements(MAX_EXTENSION_TABLE_ELEMENTS)
            .memories(1)
            .tables(1)
            .instances(1)
            .trap_on_grow_failure(true)
            .build(),
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(start.manifest.budgets.fuel)
        .map_err(|_| protocol_error("extension fuel setup failed"))?;
    let linker = Linker::new(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|_| protocol_error("extension instantiation failed"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| protocol_error("extension must export one memory"))?;
    let abi = instance
        .get_typed_func::<(), u32>(&store, "scorchkit_abi_version")
        .map_err(|_| protocol_error("extension ABI version export is invalid"))?;
    if abi.call(&mut store, ()).map_err(|_| protocol_error("extension ABI call failed"))?
        != EXTENSION_ABI_V1
    {
        return Err(protocol_error("extension ABI version is unsupported"));
    }
    let reserve = instance
        .get_typed_func::<u32, u32>(&store, "scorchkit_reserve_input")
        .map_err(|_| protocol_error("extension input export is invalid"))?;
    let run = instance
        .get_typed_func::<u32, u64>(&store, "scorchkit_run")
        .map_err(|_| protocol_error("extension run export is invalid"))?;

    let mut turn = ExtensionTurnInputV1::Start(start.invocation);
    loop {
        let turn_bytes = serde_json::to_vec(&turn)
            .map_err(|_| protocol_error("cannot encode extension turn"))?;
        if u64::try_from(turn_bytes.len()).unwrap_or(u64::MAX) > start.manifest.budgets.input_bytes
        {
            return Err(protocol_error("extension turn input exceeds its manifest"));
        }
        let length = u32::try_from(turn_bytes.len())
            .map_err(|_| protocol_error("extension turn input is too large"))?;
        let pointer = reserve
            .call(&mut store, length)
            .map_err(|_| protocol_error("extension input reservation trapped"))?;
        if pointer == 0 && !turn_bytes.is_empty() {
            return Err(protocol_error("extension input reservation failed"));
        }
        memory
            .write(
                &mut store,
                usize::try_from(pointer)
                    .map_err(|_| protocol_error("extension input pointer is invalid"))?,
                &turn_bytes,
            )
            .map_err(|_| protocol_error("extension input memory range is invalid"))?;
        let packed =
            run.call(&mut store, length).map_err(|_| protocol_error("extension turn trapped"))?;
        let output_pointer = u32::try_from(packed >> 32)
            .map_err(|_| protocol_error("extension output pointer is invalid"))?;
        let output_length = u32::try_from(packed & u64::from(u32::MAX))
            .map_err(|_| protocol_error("extension output length is invalid"))?;
        if output_length == 0 || u64::from(output_length) > start.manifest.budgets.output_bytes {
            return Err(protocol_error("extension output length is outside its manifest"));
        }
        let mut output_bytes = vec![
            0_u8;
            usize::try_from(output_length).map_err(|_| protocol_error(
                "extension output length is unsupported"
            ))?
        ];
        memory
            .read(
                &store,
                usize::try_from(output_pointer)
                    .map_err(|_| protocol_error("extension output pointer is unsupported"))?,
                &mut output_bytes,
            )
            .map_err(|_| protocol_error("extension output memory range is invalid"))?;
        let guest_output: ExtensionTurnOutputV1 = serde_json::from_slice(&output_bytes)
            .map_err(|_| protocol_error("extension output is malformed"))?;
        write_json_frame(
            &mut output,
            &guest_output,
            usize::try_from(start.manifest.budgets.output_bytes)
                .map_err(|_| protocol_error("extension output limit is unsupported"))?,
        )
        .await?;
        match guest_output {
            ExtensionTurnOutputV1::EffectRequest(_) => {
                turn = read_json_frame(
                    &mut input,
                    usize::try_from(start.manifest.budgets.input_bytes)
                        .map_err(|_| protocol_error("extension input limit is unsupported"))?,
                )
                .await?;
                if !matches!(turn, ExtensionTurnInputV1::EffectResult(_)) {
                    return Err(protocol_error("worker expected one effect result"));
                }
            }
            ExtensionTurnOutputV1::Complete(_) | ExtensionTurnOutputV1::Failure(_) => return Ok(()),
        }
    }
}

fn validate_exports(module: &Module) -> Result<()> {
    let memory_exports =
        module.exports().filter(|export| matches!(export.ty(), ExternType::Memory(_))).count();
    if memory_exports != 1 || !matches!(module.get_export("memory"), Some(ExternType::Memory(_))) {
        return Err(protocol_error("extension must export exactly one named memory"));
    }
    for name in ["scorchkit_abi_version", "scorchkit_reserve_input", "scorchkit_run"] {
        if !matches!(module.get_export(name), Some(ExternType::Func(_))) {
            return Err(protocol_error("extension is missing a required function export"));
        }
    }
    Ok(())
}

fn validate_invocation(
    invocation: &ExtensionInvocationV1,
    manifest: &scorchkit_extension::ExtensionManifestV1,
) -> Result<()> {
    let target = url::Url::parse(&invocation.target)
        .map_err(|_| protocol_error("worker invocation target is invalid"))?;
    if invocation.protocol_version != EXTENSION_PROTOCOL_V1
        || invocation.extension_id != manifest.id
        || invocation.invocation_id.trim().is_empty()
        || invocation.invocation_id.len() > 128
        || !matches!(target.scheme(), "http" | "https")
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err(protocol_error("worker invocation identity is invalid"));
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut input_bytes = 0_u64;
    for input in &invocation.inputs {
        input_bytes = input_bytes
            .checked_add(u64::try_from(input.bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| protocol_error("worker invocation input bytes overflowed"))?;
        if input.id.trim().is_empty()
            || input.id.len() > 128
            || !input.id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b'/')
            })
            || input.media_type.trim().is_empty()
            || input.media_type.len() > 256
            || input.media_type.chars().any(char::is_control)
            || !identities.insert(input.id.as_str())
            || sha256_hex(&input.bytes) != input.sha256
            || input_bytes > manifest.budgets.input_bytes
        {
            return Err(protocol_error("worker invocation input is invalid"));
        }
    }
    Ok(())
}

fn protocol_error(reason: &str) -> ScorchError {
    ScorchError::ToolOutputParse {
        tool: "scorchkit-extension-worker".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use scorchkit_extension::ExtensionInvocationInputV1;

    use super::*;
    use crate::extension::test_support;

    fn module(wat_source: &str) -> Module {
        let bytes = wat::parse_str(wat_source).expect("valid WAT fixture");
        Module::new(&Engine::default(), &bytes[..]).expect("valid Wasm module")
    }

    fn input(id: &str, media_type: &str, bytes: &[u8]) -> ExtensionInvocationInputV1 {
        ExtensionInvocationInputV1 {
            id: id.to_string(),
            media_type: media_type.to_string(),
            sha256: sha256_hex(bytes),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn export_validation_requires_one_memory_with_the_exact_name() {
        let valid = module(
            r#"(module
                (memory (export "memory") 1)
                (func (export "scorchkit_abi_version"))
                (func (export "scorchkit_reserve_input"))
                (func (export "scorchkit_run"))
            )"#,
        );
        assert!(validate_exports(&valid).is_ok());

        let duplicate_memory_export = module(
            r#"(module
                (memory (export "memory") (export "alias") 1)
                (func (export "scorchkit_abi_version"))
                (func (export "scorchkit_reserve_input"))
                (func (export "scorchkit_run"))
            )"#,
        );
        assert!(validate_exports(&duplicate_memory_export).is_err());

        let wrongly_named_memory = module(
            r#"(module
                (memory (export "other") 1)
                (func (export "scorchkit_abi_version"))
                (func (export "scorchkit_reserve_input"))
                (func (export "scorchkit_run"))
            )"#,
        );
        assert!(validate_exports(&wrongly_named_memory).is_err());
    }

    #[test]
    fn invocation_identity_rejects_each_ambiguous_field() {
        let manifest = test_support::manifest(b"module");
        let valid = test_support::invocation();
        assert!(validate_invocation(&valid, &manifest).is_ok());

        let mutations: [fn(&mut ExtensionInvocationV1); 8] = [
            |value| value.protocol_version = "wrong".to_string(),
            |value| value.extension_id = "other.extension".to_string(),
            |value| value.invocation_id.clear(),
            |value| value.invocation_id = "i".repeat(129),
            |value| value.target = "ftp://example.com/fixture".to_string(),
            |value| value.target = "https://user@example.com/fixture".to_string(),
            |value| value.target = "https://user:password@example.com/fixture".to_string(),
            |value| value.target = "https://example.com/fixture#fragment".to_string(),
        ];
        for mutate in mutations {
            let mut invocation = valid.clone();
            mutate(&mut invocation);
            assert!(validate_invocation(&invocation, &manifest).is_err());
        }
        let mut exact = valid;
        exact.invocation_id = "i".repeat(128);
        assert!(validate_invocation(&exact, &manifest).is_ok());
    }

    #[test]
    fn invocation_inputs_enforce_each_identity_digest_and_aggregate_boundary() {
        let mut manifest = test_support::manifest(b"module");
        manifest.budgets.input_bytes = 4;
        let mut valid = test_support::invocation();
        valid.inputs = vec![input(&"i".repeat(128), &"m".repeat(256), b"abcd")];
        assert!(validate_invocation(&valid, &manifest).is_ok());

        let mutations: [fn(&mut ExtensionInvocationInputV1); 7] = [
            |value| value.id.clear(),
            |value| value.id = "i".repeat(129),
            |value| value.id = "INVALID".to_string(),
            |value| value.media_type.clear(),
            |value| value.media_type = "m".repeat(257),
            |value| value.media_type = "text/plain\n".to_string(),
            |value| value.sha256 = "0".repeat(64),
        ];
        for mutate in mutations {
            let mut invocation = valid.clone();
            mutate(&mut invocation.inputs[0]);
            assert!(validate_invocation(&invocation, &manifest).is_err());
        }

        let mut duplicate = test_support::invocation();
        duplicate.inputs =
            vec![input("same", "text/plain", b"a"), input("same", "text/plain", b"b")];
        assert!(validate_invocation(&duplicate, &manifest).is_err());

        let mut overflow = test_support::invocation();
        overflow.inputs =
            vec![input("first", "text/plain", b"abcd"), input("second", "text/plain", b"e")];
        assert!(validate_invocation(&overflow, &manifest).is_err());
    }

    #[test]
    fn worker_loop_pins_protocol_size_and_pointer_guards() {
        let production =
            include_str!("worker.rs").split("#[cfg(test)]").next().expect("production source");
        let compact: String = production.split_whitespace().collect();
        assert!(compact.contains("read_json_frame(&mutinput,512*1024)"));
        assert!(compact.contains(".set_max_stack_height(1024*1024)"));
        assert!(compact.contains(
            "u64::try_from(turn_bytes.len()).unwrap_or(u64::MAX)>start.manifest.budgets.input_bytes"
        ));
        assert!(compact.contains("ifpointer==0&&!turn_bytes.is_empty(){"));
        assert!(compact.contains(
            "ifoutput_length==0||u64::from(output_length)>start.manifest.budgets.output_bytes{"
        ));
        assert!(compact.contains(
            "ifinvocation.protocol_version!=EXTENSION_PROTOCOL_V1||invocation.extension_id!=manifest.id||invocation.invocation_id.trim().is_empty()||invocation.invocation_id.len()>128||!matches!(target.scheme(),\"http\"|\"https\")||target.host_str().is_none()||!target.username().is_empty()||target.password().is_some()||target.fragment().is_some(){"
        ));
        assert!(compact.contains(
            "ifinput.id.trim().is_empty()||input.id.len()>128||!input.id.bytes().all(|byte|{byte.is_ascii_lowercase()||byte.is_ascii_digit()||matches!(byte,b'-'|b'_'|b'.'|b'/')})||input.media_type.trim().is_empty()||input.media_type.len()>256||input.media_type.chars().any(char::is_control)||!identities.insert(input.id.as_str())||sha256_hex(&input.bytes)!=input.sha256||input_bytes>manifest.budgets.input_bytes{"
        ));
    }
}
