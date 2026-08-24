/// Manifest schema identity for isolated extensions.
pub const EXTENSION_MANIFEST_SCHEMA_V1: &str = "scorchkit.extension-manifest/v1";
/// Parent/worker and guest turn protocol identity.
pub const EXTENSION_PROTOCOL_V1: &str = "scorchkit.extension-protocol/v1";
/// Integer guest ABI version returned by `scorchkit_abi_version`.
pub const EXTENSION_ABI_V1: u32 = 1;

pub const MAX_EXTENSION_ID_BYTES: usize = 96;
pub const MAX_EXTENSION_TEXT_BYTES: usize = 4096;
pub const MAX_EXTENSION_MODULE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EXTENSION_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_EXTENSION_INPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_EXTENSION_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_EXTENSION_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EXTENSION_ARTIFACTS: u32 = 128;
pub const MAX_EXTENSION_EFFECTS: u32 = 128;
pub const MAX_EXTENSION_TIMEOUT_MS: u64 = 300_000;
pub const MAX_EXTENSION_FUEL: u64 = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_constants_preserve_the_exact_binary_boundaries() {
        assert_eq!(MAX_EXTENSION_MODULE_BYTES, 8_388_608);
        assert_eq!(MAX_EXTENSION_MEMORY_BYTES, 134_217_728);
        assert_eq!(MAX_EXTENSION_INPUT_BYTES, 4_194_304);
        assert_eq!(MAX_EXTENSION_OUTPUT_BYTES, 4_194_304);
        assert_eq!(MAX_EXTENSION_ARTIFACT_BYTES, 8_388_608);
    }
}
