use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Maximum explicitly registered isolated extensions.
pub const MAX_EXTENSION_REGISTRATIONS: usize = 64;

/// Disabled-by-default isolated extension registrations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionConfig {
    /// Exact manifest paths, in deterministic registration order.
    pub manifests: Vec<PathBuf>,
}

impl ExtensionConfig {
    /// Validate count, duplicates, and nonempty path shape before filesystem access.
    ///
    /// # Errors
    ///
    /// Returns a stable reason when the registration list is oversized or contains an empty or
    /// duplicate manifest path.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.manifests.len() > MAX_EXTENSION_REGISTRATIONS {
            return Err("too many extension manifests");
        }
        for (index, path) in self.manifests.iter().enumerate() {
            if path.as_os_str().is_empty() {
                return Err("extension manifest path is empty");
            }
            if self.manifests[..index].contains(path) {
                return Err("duplicate extension manifest path");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrations_are_explicit_bounded_and_unique() {
        assert!(ExtensionConfig::default().validate().is_ok());
        let at_limit = ExtensionConfig {
            manifests: (0..MAX_EXTENSION_REGISTRATIONS)
                .map(|index| PathBuf::from(format!("{index}.json")))
                .collect(),
        };
        assert!(at_limit.validate().is_ok());
        let duplicate = ExtensionConfig {
            manifests: vec![PathBuf::from("one.json"), PathBuf::from("one.json")],
        };
        assert_eq!(duplicate.validate(), Err("duplicate extension manifest path"));
        let too_many = ExtensionConfig {
            manifests: (0..=MAX_EXTENSION_REGISTRATIONS)
                .map(|index| PathBuf::from(format!("{index}.json")))
                .collect(),
        };
        assert_eq!(too_many.validate(), Err("too many extension manifests"));
    }
}
