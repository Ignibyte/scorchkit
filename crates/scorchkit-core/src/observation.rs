//! Versioned application-security observation, identity, and evidence contracts.

use std::collections::BTreeSet;
use std::fmt::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::evidence::HttpEvidence;

/// Canonical schema emitted for application-security findings.
pub const FINDING_SCHEMA_V2: &str = "scorchkit.finding/v2";
/// Canonical schema emitted for scanner evidence records.
pub const EVIDENCE_SCHEMA_V2: &str = "scorchkit.evidence/v2";
/// Canonical schema emitted for labeled agent analysis records.
pub const AGENT_ANALYSIS_SCHEMA_V1: &str = "scorchkit.agent-analysis/v1";
/// Schema for deterministic finding identities.
pub const FINDING_IDENTITY_SCHEMA_V1: &str = "scorchkit.finding-identity/v1";

/// A one-based source-code region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRegion {
    /// First line in the region.
    pub start_line: u64,
    /// Optional first column in the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u64>,
    /// Optional last line in the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
    /// Optional last column in the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u64>,
}

impl SourceRegion {
    /// Create a source region beginning at `start_line`.
    #[must_use]
    pub const fn new(start_line: u64) -> Self {
        Self { start_line, start_column: None, end_line: None, end_column: None }
    }

    /// Add start/end column and line precision.
    #[must_use]
    pub const fn with_bounds(
        mut self,
        start_column: Option<u64>,
        end_line: Option<u64>,
        end_column: Option<u64>,
    ) -> Self {
        self.start_column = start_column;
        self.end_line = end_line;
        self.end_column = end_column;
        self
    }
}

/// Location of an HTTP parameter without its potentially sensitive value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpParameterIdentity {
    /// Parameter name.
    pub name: String,
    /// Parameter carrier such as `query`, `path`, `header`, `cookie`, or `body`.
    pub location: String,
}

impl HttpParameterIdentity {
    /// Create an HTTP parameter identity.
    #[must_use]
    pub fn new(name: impl Into<String>, location: impl Into<String>) -> Self {
        Self { name: name.into(), location: location.into() }
    }
}

/// Provider-neutral location of an application-security observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationLocation {
    /// Source-code path and optional region.
    Source {
        /// Repository-relative or scanner-reported path.
        path: String,
        /// Precise source region, when the scanner supplied one.
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<SourceRegion>,
    },
    /// Runtime URI, route, and parameter identity.
    Runtime {
        /// Redacted URI reported by the scanner.
        uri: String,
        /// Route identity without query values.
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<String>,
        /// Parameter involved in the observation.
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter: Option<HttpParameterIdentity>,
    },
    /// Software package identity.
    Package {
        /// Package ecosystem such as `cargo`, `npm`, or `pypi`.
        ecosystem: String,
        /// Package name.
        name: String,
        /// Observed package version.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        /// Manifest or lockfile that supplied the observation.
        #[serde(skip_serializing_if = "Option::is_none")]
        manifest_path: Option<String>,
    },
    /// Built artifact identity.
    Artifact {
        /// Artifact URI or path.
        uri: String,
        /// Optional content digest.
        #[serde(skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
    },
    /// Lossless compatibility location whose type cannot be inferred safely.
    Legacy {
        /// Original affected-target value.
        value: String,
    },
}

impl ObservationLocation {
    /// Conservatively infer a location without inventing unavailable precision.
    #[must_use]
    pub fn infer(value: &str) -> Self {
        if let Ok(url) = Url::parse(value) {
            if matches!(url.scheme(), "http" | "https") {
                let route = Some(url.path().to_string());
                let parameter_names: Vec<String> =
                    url.query_pairs().map(|(name, _)| name.into_owned()).collect();
                let parameter = if parameter_names.len() == 1 {
                    parameter_names
                        .into_iter()
                        .next()
                        .map(|name| HttpParameterIdentity::new(name, "query"))
                } else {
                    None
                };
                return Self::Runtime { uri: redact_url(value).0, route, parameter };
            }
        }

        if let Some((path, line)) = value.rsplit_once(':') {
            if !path.is_empty() {
                if let Ok(start_line) = line.parse::<u64>() {
                    return Self::Source {
                        path: path.to_string(),
                        region: Some(SourceRegion::new(start_line)),
                    };
                }
            }
        }

        Self::Legacy { value: value.to_string() }
    }

    /// Redact secret-bearing URI values without changing location identity.
    #[must_use]
    pub fn redacted(self) -> Self {
        match self {
            Self::Runtime { uri, route, parameter } => {
                Self::Runtime { uri: redact_url(&uri).0, route, parameter }
            }
            Self::Artifact { uri, digest } => Self::Artifact { uri: redact_url(&uri).0, digest },
            other => other,
        }
    }

    fn identity_parts(&self) -> Vec<String> {
        match self {
            Self::Source { path, region } => vec![
                "source".to_string(),
                normalize_path(path),
                region.as_ref().map_or_else(String::new, |region| region.start_line.to_string()),
            ],
            Self::Runtime { uri, route, parameter } => {
                let base = Url::parse(uri).map_or_else(
                    |_| uri.to_lowercase(),
                    |url| {
                        let host = url.host_str().unwrap_or_default().to_lowercase();
                        let port = url.port().map_or_else(String::new, |port| format!(":{port}"));
                        format!("{}://{host}{port}{}", url.scheme(), url.path())
                    },
                );
                vec![
                    "runtime".to_string(),
                    base,
                    route.clone().unwrap_or_default(),
                    parameter.as_ref().map_or_else(String::new, |parameter| {
                        format!("{}:{}", parameter.location.to_lowercase(), parameter.name)
                    }),
                ]
            }
            Self::Package { ecosystem, name, version, manifest_path } => vec![
                "package".to_string(),
                ecosystem.to_lowercase(),
                name.to_lowercase(),
                version.clone().unwrap_or_default(),
                manifest_path.as_deref().map(normalize_path).unwrap_or_default(),
            ],
            Self::Artifact { uri, digest } => {
                vec!["artifact".to_string(), uri.clone(), digest.clone().unwrap_or_default()]
            }
            Self::Legacy { value } => vec!["legacy".to_string(), value.trim().to_lowercase()],
        }
    }
}

/// Scanner, rule, configuration, and target-revision provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerProvenance {
    /// Scanner or built-in module identifier.
    pub scanner_id: String,
    /// Scanner version, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_version: Option<String>,
    /// Rule or template identifier, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Rule or template content digest, when reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_digest: Option<String>,
    /// Rule-set, template-set, or configuration identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_identity: Option<String>,
    /// Source revision, image digest, deployment revision, or equivalent target revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_revision: Option<String>,
    /// Time the scanner observation was collected.
    pub collected_at: DateTime<Utc>,
}

impl ScannerProvenance {
    /// Create provenance for a scanner observation.
    #[must_use]
    pub fn new(scanner_id: impl Into<String>, collected_at: DateTime<Utc>) -> Self {
        Self {
            scanner_id: scanner_id.into(),
            scanner_version: None,
            rule_id: None,
            rule_digest: None,
            config_identity: None,
            target_revision: None,
            collected_at,
        }
    }

    /// Attach a scanner version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.scanner_version = Some(version.into());
        self
    }

    /// Attach a rule or template identity and optional digest.
    #[must_use]
    pub fn with_rule(mut self, rule_id: impl Into<String>, digest: Option<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self.rule_digest = digest;
        self
    }

    /// Attach a configuration identity.
    #[must_use]
    pub fn with_config(mut self, identity: impl Into<String>) -> Self {
        self.config_identity = Some(identity.into());
        self
    }

    /// Attach the scanned target revision.
    #[must_use]
    pub fn with_target_revision(mut self, revision: impl Into<String>) -> Self {
        self.target_revision = Some(revision.into());
        self
    }

    fn identity_parts(&self) -> Vec<String> {
        vec![
            self.scanner_id.clone(),
            self.scanner_version.clone().unwrap_or_default(),
            self.rule_id.clone().unwrap_or_default(),
            self.rule_digest.clone().unwrap_or_default(),
            self.config_identity.clone().unwrap_or_default(),
            self.target_revision.clone().unwrap_or_default(),
        ]
    }
}

/// Explicit cross-scanner correlation key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CorrelationKey {
    /// Key namespace such as `cve`, `cwe`, `owasp`, or an organization namespace.
    pub namespace: String,
    /// Namespace-local value.
    pub value: String,
}

impl CorrelationKey {
    /// Create a normalized correlation key.
    #[must_use]
    pub fn new(namespace: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into().trim().to_lowercase(),
            value: value.into().trim().to_string(),
        }
    }
}

/// Stable identity assigned to a canonical finding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingIdentity {
    /// Identity algorithm/schema.
    pub schema: String,
    /// Lowercase hexadecimal SHA-256 digest.
    pub value: String,
}

/// Redaction metadata carried with an evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionMetadata {
    /// Whether at least one value was redacted.
    pub applied: bool,
    /// Sorted names or paths of redacted fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

/// Scanner evidence payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidencePayload {
    /// Redacted scanner text or code excerpt.
    Text {
        /// Evidence content.
        content: String,
    },
    /// Redacted HTTP request/response evidence.
    Http {
        /// Captured HTTP exchange.
        exchange: Box<HttpEvidence>,
    },
    /// Scanner-native structured evidence.
    Structured {
        /// Redacted structured value.
        value: serde_json::Value,
    },
}

/// Immutable, independently identifiable scanner evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Evidence schema.
    pub schema: String,
    /// Deterministic evidence digest.
    pub identity: String,
    /// Scanner provenance specific to this evidence.
    pub provenance: ScannerProvenance,
    /// Redaction state.
    pub redaction: RedactionMetadata,
    /// Typed evidence payload.
    pub payload: EvidencePayload,
}

impl EvidenceRecord {
    /// Build a redacted text evidence record.
    #[must_use]
    pub fn text(content: impl Into<String>, provenance: ScannerProvenance) -> Self {
        let original = content.into();
        let (content, fields) = redact_text_with_fields(&original);
        let payload = EvidencePayload::Text { content };
        Self::build(payload, provenance, fields)
    }

    /// Build a redacted HTTP evidence record.
    #[must_use]
    pub fn http(exchange: HttpEvidence, provenance: ScannerProvenance) -> Self {
        let exchange = exchange.redacted();
        let fields = exchange.redacted_fields().to_vec();
        Self::build(EvidencePayload::Http { exchange: Box::new(exchange) }, provenance, fields)
    }

    /// Redact the payload again and recompute its identity.
    #[must_use]
    pub fn normalized(self) -> Self {
        let provenance = self.provenance.clone();
        self.with_provenance(provenance)
    }

    /// Rebind evidence to more precise scanner provenance and recompute identity.
    #[must_use]
    pub fn with_provenance(self, provenance: ScannerProvenance) -> Self {
        let prior_fields = self.redaction.fields;
        match self.payload {
            EvidencePayload::Text { content } => {
                let (content, fields) = redact_text_with_fields(&content);
                Self::build(
                    EvidencePayload::Text { content },
                    provenance,
                    prior_fields.into_iter().chain(fields).collect(),
                )
            }
            EvidencePayload::Http { exchange } => {
                let exchange = (*exchange).redacted();
                let fields = exchange.redacted_fields().to_vec();
                Self::build(
                    EvidencePayload::Http { exchange: Box::new(exchange) },
                    provenance,
                    prior_fields.into_iter().chain(fields).collect(),
                )
            }
            EvidencePayload::Structured { mut value } => {
                let mut fields = Vec::new();
                redact_json(&mut value, "$", &mut fields);
                Self::build(
                    EvidencePayload::Structured { value },
                    provenance,
                    prior_fields.into_iter().chain(fields).collect(),
                )
            }
        }
    }

    fn build(
        payload: EvidencePayload,
        provenance: ScannerProvenance,
        mut fields: Vec<String>,
    ) -> Self {
        fields.sort();
        fields.dedup();
        let redaction = RedactionMetadata { applied: !fields.is_empty(), fields };
        let payload_json = serde_json::to_value(&payload)
            .map_or_else(|_| "null".to_string(), |value| canonical_json(&value));
        let mut parts = provenance.identity_parts();
        parts.push(payload_json);
        parts.push(serde_json::to_string(&redaction).unwrap_or_default());
        let identity = digest_parts(EVIDENCE_SCHEMA_V2, parts.iter().map(String::as_str));
        Self { schema: EVIDENCE_SCHEMA_V2.to_string(), identity, provenance, redaction, payload }
    }
}

/// Explicitly labeled analysis produced by an agent or model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAnalysisRecord {
    /// Analysis schema.
    pub schema: String,
    /// Deterministic analysis identity.
    pub identity: String,
    /// Provider or agent adapter identity.
    pub provider: String,
    /// Model identity, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Analysis content selected by a trusted consumer.
    pub summary: String,
    /// Evidence identities considered by the analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    /// Time the analysis was produced.
    pub created_at: DateTime<Utc>,
}

impl AgentAnalysisRecord {
    /// Create a labeled analysis record.
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        model: Option<String>,
        summary: impl Into<String>,
        mut evidence_ids: Vec<String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        let provider = provider.into();
        let summary = summary.into();
        evidence_ids.sort();
        evidence_ids.dedup();
        let mut parts = vec![provider.clone(), model.clone().unwrap_or_default(), summary.clone()];
        parts.extend(evidence_ids.iter().cloned());
        let identity = digest_parts(AGENT_ANALYSIS_SCHEMA_V1, parts.iter().map(String::as_str));
        Self {
            schema: AGENT_ANALYSIS_SCHEMA_V1.to_string(),
            identity,
            provider,
            model,
            summary,
            evidence_ids,
            created_at,
        }
    }

    /// Restore the canonical schema and identity after compatibility deserialization.
    #[must_use]
    pub fn normalized(self) -> Self {
        Self::new(self.provider, self.model, self.summary, self.evidence_ids, self.created_at)
    }
}

/// Canonical application-security record embedded in the `Finding` facade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecordV2 {
    /// Finding schema.
    pub schema: String,
    /// Stable cross-scan identity.
    pub identity: FindingIdentity,
    /// Typed affected location.
    pub location: ObservationLocation,
    /// Primary scanner provenance.
    pub provenance: ScannerProvenance,
    /// Explicit cross-scanner correlation keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlation_keys: Vec<CorrelationKey>,
    /// Immutable scanner evidence records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRecord>,
    /// Labeled agent interpretation, separate from scanner evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_analysis: Vec<AgentAnalysisRecord>,
}

impl FindingRecordV2 {
    /// Upgrade a legacy finding facade into the canonical v2 record.
    #[must_use]
    pub fn from_legacy(
        module_id: &str,
        title: &str,
        affected_target: &str,
        cwe_id: Option<u32>,
        collected_at: DateTime<Utc>,
    ) -> Self {
        let mut record = Self {
            schema: FINDING_SCHEMA_V2.to_string(),
            identity: FindingIdentity {
                schema: FINDING_IDENTITY_SCHEMA_V1.to_string(),
                value: String::new(),
            },
            location: ObservationLocation::infer(affected_target),
            provenance: ScannerProvenance::new(module_id, collected_at),
            correlation_keys: Vec::new(),
            evidence: Vec::new(),
            agent_analysis: Vec::new(),
        };
        record.refresh_identity(module_id, title, cwe_id);
        record
    }

    /// Recompute identity after location, provenance, weakness, or correlation changes.
    pub fn refresh_identity(&mut self, module_id: &str, title: &str, cwe_id: Option<u32>) {
        self.schema = FINDING_SCHEMA_V2.to_string();
        self.identity.schema = FINDING_IDENTITY_SCHEMA_V1.to_string();
        self.correlation_keys.sort();
        self.correlation_keys.dedup();

        let mut parts = if self.correlation_keys.is_empty() {
            vec![cwe_id.map_or_else(
                || {
                    self.provenance.rule_id.as_ref().map_or_else(
                        || {
                            format!(
                                "legacy:{}:{}",
                                module_id.to_lowercase(),
                                title.trim().to_lowercase()
                            )
                        },
                        |rule_id| format!("rule:{}", rule_id.trim().to_lowercase()),
                    )
                },
                |cwe| format!("cwe:{cwe}"),
            )]
        } else {
            let mut correlation_parts = vec!["correlation".to_string()];
            for key in &self.correlation_keys {
                correlation_parts.push(key.namespace.clone());
                correlation_parts.push(key.value.clone());
            }
            correlation_parts
        };

        parts.extend(self.location.identity_parts());
        self.identity.value =
            digest_parts(FINDING_IDENTITY_SCHEMA_V1, parts.iter().map(String::as_str));
    }
}

/// Redact sensitive structured or keyed text before it becomes durable evidence.
#[must_use]
pub fn redact_text(input: &str) -> String {
    redact_text_with_fields(input).0
}

/// Redact sensitive URL query values while preserving parameter names.
#[must_use]
pub fn redact_url(input: &str) -> (String, Vec<String>) {
    let Ok(mut url) = Url::parse(input) else {
        return (input.to_string(), Vec::new());
    };
    let pairs: Vec<(String, String)> =
        url.query_pairs().map(|(key, value)| (key.into_owned(), value.into_owned())).collect();
    let fields: Vec<String> = pairs
        .iter()
        .filter(|(key, _)| is_sensitive_key(key))
        .map(|(key, _)| format!("query.{key}"))
        .collect();
    if fields.is_empty() {
        return (input.to_string(), fields);
    }
    url.query_pairs_mut().clear().extend_pairs(pairs.iter().map(|(key, value)| {
        (key.as_str(), if is_sensitive_key(key) { "[REDACTED]" } else { value.as_str() })
    }));
    (url.into(), fields)
}

fn redact_text_with_fields(input: &str) -> (String, Vec<String>) {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
        let mut fields = Vec::new();
        redact_json(&mut value, "$", &mut fields);
        if !fields.is_empty() {
            return (serde_json::to_string(&value).unwrap_or_default(), fields);
        }
    }

    if input.contains('=') {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(input.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let fields: Vec<String> = pairs
            .iter()
            .filter(|(key, _)| is_sensitive_key(key))
            .map(|(key, _)| format!("body.{key}"))
            .collect();
        if !fields.is_empty() {
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs.iter().map(|(key, value)| {
                    (
                        key.as_str(),
                        if is_sensitive_key(key) { "[REDACTED]" } else { value.as_str() },
                    )
                }))
                .finish();
            return (encoded, fields);
        }
    }

    let mut fields = Vec::new();
    let lines = input
        .lines()
        .map(|line| {
            if let Some((key, value)) = line.split_once(':') {
                if is_sensitive_key(key) {
                    fields.push(format!("text.{}", key.trim()));
                    format!("{key}: [REDACTED]")
                } else {
                    format!("{key}:{value}")
                }
            } else if let Some((key, value)) = line.split_once('=') {
                if is_sensitive_key(key) {
                    fields.push(format!("text.{}", key.trim()));
                    format!("{key}=[REDACTED]")
                } else {
                    format!("{key}={value}")
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    (lines, fields)
}

fn redact_json(value: &mut serde_json::Value, path: &str, fields: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if is_sensitive_key(key) {
                    *child = serde_json::Value::String("[REDACTED]".to_string());
                    fields.push(child_path);
                } else {
                    redact_json(child, &child_path, fields);
                }
            }
        }
        serde_json::Value::Array(array) => {
            for (index, child) in array.iter_mut().enumerate() {
                redact_json(child, &format!("{path}[{index}]"), fields);
            }
        }
        _ => {}
    }
}

pub(crate) fn is_sensitive_key(key: &str) -> bool {
    let normalized: String =
        key.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "xapikey"
            | "apikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "secret"
            | "clientsecret"
            | "password"
            | "passwd"
            | "session"
            | "sessionid"
    )
}

fn normalize_path(path: &str) -> String {
    path.trim().replace('\\', "/").trim_start_matches("./").to_string()
}

fn digest_parts<'a>(domain: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    add_hash_part(&mut hasher, domain);
    for part in parts {
        add_hash_part(&mut hasher, part);
    }
    format!("{:x}", hasher.finalize())
}

fn add_hash_part(hasher: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut output = String::from("{");
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                let encoded_key = serde_json::to_string(key).unwrap_or_else(|_| "null".into());
                let _ = write!(output, "{encoded_key}:{}", canonical_json(&object[key]));
            }
            output.push('}');
            output
        }
        serde_json::Value::Array(array) => {
            let mut output = String::from("[");
            for (index, item) in array.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(item));
            }
            output.push(']');
            output
        }
        primitive => serde_json::to_string(primitive).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Return sorted, unique redaction fields.
pub(crate) fn normalized_redaction_fields(fields: impl IntoIterator<Item = String>) -> Vec<String> {
    fields.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_scanner_cwe_and_location_produce_same_identity() {
        let now = Utc::now();
        let semgrep =
            FindingRecordV2::from_legacy("semgrep", "python.eval", "src/app.py:42", Some(95), now);
        let other = FindingRecordV2::from_legacy(
            "codeql",
            "Dynamic code evaluation",
            "src/app.py:42",
            Some(95),
            now,
        );
        assert_eq!(semgrep.identity, other.identity);
    }

    #[test]
    fn explicit_correlation_keys_override_scanner_rule_identity() {
        let now = Utc::now();
        let mut first = FindingRecordV2::from_legacy("one", "a", "artifact.jar", None, now);
        first.correlation_keys.push(CorrelationKey::new("cve", "CVE-2026-0001"));
        first.refresh_identity("one", "a", None);
        let mut second = FindingRecordV2::from_legacy("two", "b", "artifact.jar", None, now);
        second.correlation_keys.push(CorrelationKey::new("cve", "CVE-2026-0001"));
        second.refresh_identity("two", "b", None);
        assert_eq!(first.identity, second.identity);
    }

    #[test]
    fn length_prefixing_prevents_delimiter_collisions() {
        let first = digest_parts("test", ["a|b", "c"]);
        let second = digest_parts("test", ["a", "b|c"]);
        assert_ne!(first, second);
    }

    #[test]
    fn correlation_key_boundaries_are_unambiguous() {
        let now = Utc::now();
        let mut first = FindingRecordV2::from_legacy("one", "a", "artifact.jar", None, now);
        first.correlation_keys.push(CorrelationKey::new("a", "b|c=d"));
        first.refresh_identity("one", "a", None);

        let mut second = FindingRecordV2::from_legacy("two", "b", "artifact.jar", None, now);
        second.correlation_keys.push(CorrelationKey::new("a", "b"));
        second.correlation_keys.push(CorrelationKey::new("c", "d"));
        second.refresh_identity("two", "b", None);

        assert_ne!(first.identity, second.identity);
    }

    #[test]
    fn evidence_identity_is_independent_of_header_map_order() {
        let mut first_headers = std::collections::HashMap::new();
        first_headers.insert("Content-Type".to_string(), "application/json".to_string());
        first_headers.insert("X-Request-ID".to_string(), "123".to_string());
        let mut second_headers = std::collections::HashMap::new();
        second_headers.insert("X-Request-ID".to_string(), "123".to_string());
        second_headers.insert("Content-Type".to_string(), "application/json".to_string());
        let provenance = ScannerProvenance::new("scanner", Utc::now());
        let first = EvidenceRecord::http(
            HttpEvidence::new("GET", "https://example.com", 200)
                .with_request_headers(first_headers),
            provenance.clone(),
        );
        let second = EvidenceRecord::http(
            HttpEvidence::new("GET", "https://example.com", 200)
                .with_request_headers(second_headers),
            provenance,
        );
        assert_eq!(first.identity, second.identity);
    }

    #[test]
    fn evidence_identity_includes_payload_and_scanner_provenance() {
        let now = Utc::now();
        let base = ScannerProvenance::new("scanner", now);
        let enriched = ScannerProvenance::new("scanner", now)
            .with_version("2.0")
            .with_rule("rule-1", Some("sha256:abc".to_string()))
            .with_config("ruleset-7")
            .with_target_revision("commit-123");
        let base_record = EvidenceRecord::text("proof-a", base);
        let changed_provenance = EvidenceRecord::text("proof-a", enriched);
        let changed_payload =
            EvidenceRecord::text("proof-b", ScannerProvenance::new("scanner", now));

        assert_ne!(base_record.identity, changed_provenance.identity);
        assert_ne!(base_record.identity, changed_payload.identity);
    }

    #[test]
    fn source_identity_normalizes_paths_without_collapsing_distinct_files() {
        let now = Utc::now();
        let first =
            FindingRecordV2::from_legacy("semgrep", "rule", "./src\\app.rs:42", Some(95), now);
        let equivalent =
            FindingRecordV2::from_legacy("codeql", "rule", "src/app.rs:42", Some(95), now);
        let different =
            FindingRecordV2::from_legacy("codeql", "rule", "src/other.rs:42", Some(95), now);

        assert_eq!(first.identity, equivalent.identity);
        assert_ne!(first.identity, different.identity);
    }

    #[test]
    fn canonical_json_sorts_nested_objects_and_preserves_array_order() {
        let value = serde_json::json!({
            "z": [3, 2],
            "a": {"d": 4, "b": 2}
        });
        assert_eq!(canonical_json(&value), r#"{"a":{"b":2,"d":4},"z":[3,2]}"#);
    }

    #[test]
    fn redact_text_handles_json_form_and_header_shapes() {
        assert_eq!(
            redact_text(r#"{"user":"alice","password":"secret"}"#),
            r#"{"password":"[REDACTED]","user":"alice"}"#
        );
        let form = redact_text("user=alice&api_key=secret");
        assert!(form.contains("user=alice"));
        assert!(form.contains("api_key=%5BREDACTED%5D"));
        assert_eq!(redact_text("Authorization: Bearer secret"), "Authorization: [REDACTED]");
        assert_eq!(
            redact_text(r#"{"items":[{"password":"secret"},{"name":"safe"}]}"#),
            r#"{"items":[{"password":"[REDACTED]"},{"name":"safe"}]}"#
        );
    }

    #[test]
    fn url_redaction_keeps_names_and_non_sensitive_values() {
        let (url, fields) =
            redact_url("https://example.com/search?q=public&access_token=secret#fragment");
        assert!(url.contains("q=public"));
        assert!(url.contains("access_token=%5BREDACTED%5D"));
        assert!(!url.contains("secret"));
        assert_eq!(fields, vec!["query.access_token"]);
    }

    #[test]
    fn every_typed_location_variant_round_trips() {
        let locations = [
            ObservationLocation::Source {
                path: "src/lib.rs".to_string(),
                region: Some(SourceRegion::new(7)),
            },
            ObservationLocation::Runtime {
                uri: "https://example.com/login".to_string(),
                route: Some("/login".to_string()),
                parameter: Some(HttpParameterIdentity::new("username", "body")),
            },
            ObservationLocation::Package {
                ecosystem: "cargo".to_string(),
                name: "serde".to_string(),
                version: Some("1.0.0".to_string()),
                manifest_path: Some("Cargo.lock".to_string()),
            },
            ObservationLocation::Artifact {
                uri: "oci://registry.example/app".to_string(),
                digest: Some("sha256:abc".to_string()),
            },
            ObservationLocation::Legacy { value: "opaque".to_string() },
        ];
        for location in locations {
            let encoded = serde_json::to_string(&location).expect("serialize location");
            let restored: ObservationLocation =
                serde_json::from_str(&encoded).expect("deserialize location");
            assert_eq!(location, restored);
        }
    }
}
