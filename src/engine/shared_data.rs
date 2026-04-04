//! Shared data store for inter-module communication.
//!
//! Modules can publish discovered data (URLs, forms, technologies) during
//! their scan, and downstream modules can read it. Thread-safe via
//! `std::sync::RwLock` for concurrent module execution.

use std::collections::HashMap;
use std::sync::RwLock;

/// Well-known keys for shared data.
pub mod keys {
    /// URLs discovered by the crawler module.
    pub const URLS: &str = "urls";
    /// Form endpoint URLs discovered by the crawler.
    pub const FORMS: &str = "forms";
    /// Query parameter names discovered by the crawler.
    pub const PARAMS: &str = "params";
    /// Technology identifiers detected by the tech module.
    pub const TECHNOLOGIES: &str = "technologies";
    /// Subdomains discovered by the subdomain module.
    pub const SUBDOMAINS: &str = "subdomains";
}

/// Thread-safe shared data store for inter-module communication.
///
/// Modules publish discovered data during their scan phase, and downstream
/// modules read it. The store uses `RwLock` for safe concurrent access.
#[derive(Debug, Default)]
pub struct SharedData {
    store: RwLock<HashMap<String, Vec<String>>>,
}

impl SharedData {
    /// Create a new empty shared data store.
    #[must_use]
    pub fn new() -> Self {
        Self { store: RwLock::new(HashMap::new()) }
    }

    /// Publish data under a key, extending any existing entries.
    ///
    /// Thread-safe: acquires a write lock.
    pub fn publish(&self, key: &str, values: Vec<String>) {
        if values.is_empty() {
            return;
        }
        if let Ok(mut store) = self.store.write() {
            store.entry(key.to_string()).or_default().extend(values);
        }
    }

    /// Read all values for a key. Returns an empty vec if the key doesn't exist.
    ///
    /// Thread-safe: acquires a read lock.
    #[must_use]
    pub fn get(&self, key: &str) -> Vec<String> {
        self.store.read().ok().and_then(|s| s.get(key).cloned()).unwrap_or_default()
    }

    /// Check if any data has been published for a key.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.store.read().ok().is_some_and(|s| s.get(key).is_some_and(|v| !v.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify a new SharedData store is empty.
    #[test]
    fn shared_data_starts_empty() {
        let sd = SharedData::new();
        assert!(sd.get(keys::URLS).is_empty());
        assert!(!sd.has(keys::URLS));
    }

    /// Verify publish and get round-trip correctly.
    #[test]
    fn shared_data_publish_and_get() {
        let sd = SharedData::new();
        sd.publish(keys::URLS, vec!["https://a.com".to_string(), "https://b.com".to_string()]);
        let urls = sd.get(keys::URLS);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://a.com".to_string()));
    }

    /// Verify multiple publishes to the same key extend the list.
    #[test]
    fn shared_data_extends_on_multiple_publishes() {
        let sd = SharedData::new();
        sd.publish(keys::URLS, vec!["https://a.com".to_string()]);
        sd.publish(keys::URLS, vec!["https://b.com".to_string()]);
        assert_eq!(sd.get(keys::URLS).len(), 2);
    }

    /// Verify publishing empty values is a no-op.
    #[test]
    fn shared_data_empty_publish_noop() {
        let sd = SharedData::new();
        sd.publish(keys::URLS, Vec::new());
        assert!(!sd.has(keys::URLS));
    }

    /// Verify has() returns true after publish.
    #[test]
    fn shared_data_has_after_publish() {
        let sd = SharedData::new();
        assert!(!sd.has(keys::TECHNOLOGIES));
        sd.publish(keys::TECHNOLOGIES, vec!["nginx".to_string()]);
        assert!(sd.has(keys::TECHNOLOGIES));
    }
}
