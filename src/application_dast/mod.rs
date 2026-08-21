//! Policy-sealed, schema-driven OWASP ZAP application DAST service.

pub(crate) mod orchestrator;
pub(crate) mod parser;
pub(crate) mod plan;
pub(crate) mod request;
pub(crate) mod schema;
pub(crate) mod workspace;

pub use request::{ApplicationDastRequest, ApplicationDastSchemaRequest};

pub(crate) use orchestrator::ApplicationDastOrchestrator;
pub(crate) use plan::{ResolvedPersona, ResolvedPersonaKind};
pub(crate) use schema::{canonical_schema_path, validate_schema};

pub(crate) fn path_is_under(base: &str, candidate: &str) -> bool {
    let base = base.trim_end_matches('/');
    base.is_empty() || candidate == base || candidate.starts_with(&format!("{base}/"))
}

#[cfg(test)]
mod tests {
    use super::path_is_under;

    #[test]
    fn authorized_paths_require_a_segment_boundary() {
        assert!(path_is_under("/app", "/app"));
        assert!(path_is_under("/app/", "/app/account"));
        assert!(!path_is_under("/app", "/application"));
        assert!(path_is_under("/", "/anything"));
    }
}
