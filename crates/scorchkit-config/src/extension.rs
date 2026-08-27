use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Maximum explicitly registered isolated extensions.
pub const MAX_EXTENSION_REGISTRATIONS: usize = 64;
/// Maximum locally configured signed catalogs and publisher trust bindings.
pub const MAX_EXTENSION_CATALOGS: usize = 16;

/// Locally configured Ed25519 key bound to exactly one publisher identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionTrustKeyConfig {
    pub key_id: String,
    pub publisher_id: String,
    pub public_key_base64: String,
}

/// Disabled-by-default isolated extension registrations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionConfig {
    /// Exact manifest paths, in deterministic registration order.
    pub manifests: Vec<PathBuf>,
    /// Exact local signed catalog paths. URLs and discovery are intentionally unsupported.
    pub catalogs: Vec<PathBuf>,
    /// Local trust roots. Catalog payloads cannot enroll or replace these keys.
    pub trust_keys: Vec<ExtensionTrustKeyConfig>,
    /// Exact private local root for immutable approvals and atomic active pointers.
    pub lifecycle_root: Option<PathBuf>,
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
        if self.catalogs.len() > MAX_EXTENSION_CATALOGS
            || self.trust_keys.len() > MAX_EXTENSION_CATALOGS
        {
            return Err("too many extension catalogs or trust keys");
        }
        for (index, path) in self.catalogs.iter().enumerate() {
            if path.as_os_str().is_empty() || self.catalogs[..index].contains(path) {
                return Err("invalid or duplicate extension catalog path");
            }
        }
        for (index, key) in self.trust_keys.iter().enumerate() {
            if !valid_id(&key.key_id)
                || !valid_id(&key.publisher_id)
                || key.public_key_base64.is_empty()
                || key.public_key_base64.len() > 128
                || self.trust_keys[..index].iter().any(|prior| prior.key_id == key.key_id)
            {
                return Err("invalid or duplicate extension trust key");
            }
        }
        if let Some(root) = &self.lifecycle_root {
            if root.as_os_str().is_empty() {
                return Err("extension lifecycle root is empty");
            }
        }
        Ok(())
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust_key(key_id: &str) -> ExtensionTrustKeyConfig {
        ExtensionTrustKeyConfig {
            key_id: key_id.to_string(),
            publisher_id: "publisher.example".to_string(),
            public_key_base64: "a".repeat(44),
        }
    }

    #[test]
    fn registrations_are_explicit_bounded_and_unique() {
        assert!(ExtensionConfig::default().validate().is_ok());
        let at_limit = ExtensionConfig {
            manifests: (0..MAX_EXTENSION_REGISTRATIONS)
                .map(|index| PathBuf::from(format!("{index}.json")))
                .collect(),
            ..ExtensionConfig::default()
        };
        assert!(at_limit.validate().is_ok());
        let duplicate = ExtensionConfig {
            manifests: vec![PathBuf::from("one.json"), PathBuf::from("one.json")],
            ..ExtensionConfig::default()
        };
        assert_eq!(duplicate.validate(), Err("duplicate extension manifest path"));
        let too_many = ExtensionConfig {
            manifests: (0..=MAX_EXTENSION_REGISTRATIONS)
                .map(|index| PathBuf::from(format!("{index}.json")))
                .collect(),
            ..ExtensionConfig::default()
        };
        assert_eq!(too_many.validate(), Err("too many extension manifests"));

        let duplicate_keys = ExtensionConfig {
            trust_keys: vec![
                ExtensionTrustKeyConfig {
                    key_id: "publisher.key".to_string(),
                    publisher_id: "publisher.example".to_string(),
                    public_key_base64: "a".repeat(44),
                },
                ExtensionTrustKeyConfig {
                    key_id: "publisher.key".to_string(),
                    publisher_id: "publisher.example".to_string(),
                    public_key_base64: "b".repeat(44),
                },
            ],
            ..ExtensionConfig::default()
        };
        assert_eq!(duplicate_keys.validate(), Err("invalid or duplicate extension trust key"));

        let duplicate_catalogs = ExtensionConfig {
            catalogs: vec![PathBuf::from("catalog.json"), PathBuf::from("catalog.json")],
            ..ExtensionConfig::default()
        };
        assert_eq!(
            duplicate_catalogs.validate(),
            Err("invalid or duplicate extension catalog path")
        );
    }

    #[test]
    fn catalog_and_trust_configuration_checks_each_exact_boundary() {
        let at_limit = ExtensionConfig {
            catalogs: (0..MAX_EXTENSION_CATALOGS)
                .map(|index| PathBuf::from(format!("catalog-{index}.json")))
                .collect(),
            trust_keys: (0..MAX_EXTENSION_CATALOGS)
                .map(|index| trust_key(&format!("publisher.key-{index}")))
                .collect(),
            lifecycle_root: Some(PathBuf::from("lifecycle")),
            ..ExtensionConfig::default()
        };
        assert_eq!(at_limit.validate(), Ok(()));

        let mut invalid = at_limit.clone();
        invalid.catalogs.push(PathBuf::from("one-too-many.json"));
        assert_eq!(invalid.validate(), Err("too many extension catalogs or trust keys"));
        let mut invalid = at_limit;
        invalid.trust_keys.push(trust_key("publisher.key-overflow"));
        assert_eq!(invalid.validate(), Err("too many extension catalogs or trust keys"));

        let mut invalid =
            ExtensionConfig { catalogs: vec![PathBuf::new()], ..ExtensionConfig::default() };
        assert_eq!(invalid.validate(), Err("invalid or duplicate extension catalog path"));
        invalid.catalogs = vec![PathBuf::from("catalog.json")];
        assert_eq!(invalid.validate(), Ok(()));

        for key in [
            ExtensionTrustKeyConfig { key_id: "INVALID".to_string(), ..trust_key("publisher.key") },
            ExtensionTrustKeyConfig {
                publisher_id: "INVALID".to_string(),
                ..trust_key("publisher.key")
            },
            ExtensionTrustKeyConfig {
                public_key_base64: String::new(),
                ..trust_key("publisher.key")
            },
            ExtensionTrustKeyConfig {
                public_key_base64: "a".repeat(129),
                ..trust_key("publisher.key")
            },
        ] {
            let invalid = ExtensionConfig { trust_keys: vec![key], ..ExtensionConfig::default() };
            assert_eq!(invalid.validate(), Err("invalid or duplicate extension trust key"));
        }

        let valid = ExtensionConfig {
            trust_keys: vec![trust_key("publisher.key")],
            lifecycle_root: Some(PathBuf::from("lifecycle")),
            ..ExtensionConfig::default()
        };
        assert_eq!(valid.validate(), Ok(()));
        let invalid =
            ExtensionConfig { lifecycle_root: Some(PathBuf::new()), ..ExtensionConfig::default() };
        assert_eq!(invalid.validate(), Err("extension lifecycle root is empty"));
    }
}
