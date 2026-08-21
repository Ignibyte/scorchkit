use std::collections::BTreeSet;

use scorchkit_core::{Result, ScorchError};
use scorchkit_policy::EffectClass;
use serde_yaml::{Mapping, Value};

const ALLOWED_ROOT_KEYS: &[&str] = &["http", "id", "info", "stop-at-first-match"];
const DENIED_PROTOCOL_KEYS: &[&str] = &[
    "code",
    "dns",
    "file",
    "flow",
    "headless",
    "javascript",
    "network",
    "requests",
    "self-contained",
    "ssl",
    "tcp",
    "websocket",
    "whois",
    "workflows",
];
const ALLOWED_HTTP_KEYS: &[&str] = &[
    "body",
    "extractors",
    "headers",
    "matchers",
    "matchers-condition",
    "method",
    "name",
    "path",
    "stop-at-first-match",
];
const DENIED_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
const ALLOWED_METHODS: &[&str] = &["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];
const MATCHER_COMMON_KEYS: &[&str] = &["condition", "name", "negative", "part", "type"];
const EXTRACTOR_COMMON_KEYS: &[&str] = &["name", "part", "type"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NucleiTemplateClassification {
    pub effect_floor: EffectClass,
    pub methods: Vec<String>,
}

pub fn classify_template(bytes: &[u8], expected_id: &str) -> Result<NucleiTemplateClassification> {
    let root: Value = serde_yaml::from_slice(bytes).map_err(|error| {
        config_error(format!("template '{expected_id}' is invalid YAML: {error}"))
    })?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| config_error(format!("template '{expected_id}' root is not a mapping")))?;

    reject_unknown_root_keys(mapping, expected_id)?;
    let id = mapping_string(mapping, "id").ok_or_else(|| {
        config_error(format!("template '{expected_id}' has no scalar top-level id"))
    })?;
    if id != expected_id {
        return Err(config_error(format!(
            "template id '{id}' does not match approved id '{expected_id}'"
        )));
    }
    let http = mapping_get(mapping, "http")
        .and_then(Value::as_sequence)
        .filter(|requests| !requests.is_empty())
        .ok_or_else(|| {
            config_error(format!(
                "template '{expected_id}' must contain a nonempty structured http sequence"
            ))
        })?;

    let mut effect_floor = EffectClass::ActiveSafe;
    let mut methods = BTreeSet::new();
    for (index, request) in http.iter().enumerate() {
        let request = request.as_mapping().ok_or_else(|| {
            config_error(format!(
                "template '{expected_id}' http request {} is not a mapping",
                index + 1
            ))
        })?;
        reject_unknown_http_keys(request, expected_id, index)?;
        let method = mapping_string(request, "method").ok_or_else(|| {
            config_error(format!(
                "template '{expected_id}' http request {} has no scalar method",
                index + 1
            ))
        })?;
        let method = method.to_ascii_uppercase();
        if !ALLOWED_METHODS.contains(&method.as_str()) {
            return Err(config_error(format!(
                "template '{expected_id}' http request {} uses unsupported method '{method}'",
                index + 1
            )));
        }
        if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            effect_floor = EffectClass::Intrusive;
        }
        methods.insert(method);
        validate_paths(request, expected_id, index)?;
        validate_headers(request, expected_id, index)?;
        validate_response_operators(request, expected_id, index)?;
        if let Some(body) = mapping_get(request, "body") {
            let body = body.as_str().ok_or_else(|| {
                config_error(format!(
                    "template '{expected_id}' http request {} body is not a scalar string",
                    index + 1
                ))
            })?;
            if !body.is_empty() {
                effect_floor = EffectClass::Intrusive;
                reject_external_request_value(body, expected_id, "body")?;
            }
        }
    }

    Ok(NucleiTemplateClassification { effect_floor, methods: methods.into_iter().collect() })
}

fn reject_unknown_root_keys(mapping: &Mapping, template_id: &str) -> Result<()> {
    for key in mapping.keys() {
        let Some(key) = key.as_str() else {
            return Err(config_error(format!(
                "template '{template_id}' has a non-string top-level key"
            )));
        };
        if DENIED_PROTOCOL_KEYS.contains(&key) {
            return Err(config_error(format!(
                "template '{template_id}' uses denied protocol or execution key '{key}'"
            )));
        }
        if !ALLOWED_ROOT_KEYS.contains(&key) {
            return Err(config_error(format!(
                "template '{template_id}' uses unsupported top-level key '{key}'"
            )));
        }
    }
    Ok(())
}

fn reject_unknown_http_keys(
    mapping: &Mapping,
    template_id: &str,
    request_index: usize,
) -> Result<()> {
    for key in mapping.keys() {
        let Some(key) = key.as_str() else {
            return Err(config_error(format!(
                "template '{template_id}' http request {} has a non-string key",
                request_index + 1
            )));
        };
        if !ALLOWED_HTTP_KEYS.contains(&key) {
            return Err(config_error(format!(
                "template '{template_id}' http request {} uses unsupported key '{key}'",
                request_index + 1
            )));
        }
    }
    Ok(())
}

fn validate_paths(mapping: &Mapping, template_id: &str, request_index: usize) -> Result<()> {
    let paths = mapping_get(mapping, "path")
        .and_then(Value::as_sequence)
        .filter(|paths| !paths.is_empty())
        .ok_or_else(|| {
            config_error(format!(
                "template '{template_id}' http request {} has no nonempty path list",
                request_index + 1
            ))
        })?;
    for path in paths {
        let path = path.as_str().ok_or_else(|| {
            config_error(format!(
                "template '{template_id}' http request {} contains a non-string path",
                request_index + 1
            ))
        })?;
        if !path.starts_with("{{BaseURL}}") && !path.starts_with("{{RootURL}}") {
            return Err(config_error(format!(
                "template '{template_id}' path must begin with {{{{BaseURL}}}} or {{{{RootURL}}}}"
            )));
        }
        let suffix = path
            .strip_prefix("{{BaseURL}}")
            .or_else(|| path.strip_prefix("{{RootURL}}"))
            .unwrap_or_default();
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(config_error(format!(
                "template '{template_id}' path must remain under the approved base URL"
            )));
        }
        if suffix.contains("://") || suffix.starts_with('@') || suffix.starts_with("//") {
            return Err(config_error(format!(
                "template '{template_id}' path can replace the approved request authority"
            )));
        }
        if suffix.contains("{{") || suffix.contains("}}") {
            return Err(config_error(format!(
                "template '{template_id}' path contains an unreviewed runtime expression"
            )));
        }
        if contains_oast_token(path) {
            return Err(config_error(format!(
                "template '{template_id}' path requests an out-of-band interaction"
            )));
        }
        if path.bytes().any(|byte| byte.is_ascii_control()) || path.contains('\\') {
            return Err(config_error(format!(
                "template '{template_id}' path contains ambiguous framing characters"
            )));
        }
    }
    Ok(())
}

fn validate_headers(mapping: &Mapping, template_id: &str, request_index: usize) -> Result<()> {
    let Some(headers) = mapping_get(mapping, "headers") else {
        return Ok(());
    };
    let headers = headers.as_mapping().ok_or_else(|| {
        config_error(format!(
            "template '{template_id}' http request {} headers are not a mapping",
            request_index + 1
        ))
    })?;
    for (name, value) in headers {
        let name = name.as_str().ok_or_else(|| {
            config_error(format!("template '{template_id}' contains a non-string header name"))
        })?;
        if name.is_empty() || !name.bytes().all(is_header_name_byte) {
            return Err(config_error(format!(
                "template '{template_id}' contains invalid header name '{name}'"
            )));
        }
        if DENIED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(config_error(format!(
                "template '{template_id}' contains denied header '{name}'"
            )));
        }
        let value = value.as_str().ok_or_else(|| {
            config_error(format!("template '{template_id}' header '{name}' is not a scalar string"))
        })?;
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | b'\0')) {
            return Err(config_error(format!(
                "template '{template_id}' header '{name}' contains framing characters"
            )));
        }
        reject_external_request_value(value, template_id, "header")?;
    }
    Ok(())
}

fn validate_response_operators(
    mapping: &Mapping,
    template_id: &str,
    request_index: usize,
) -> Result<()> {
    if let Some(matchers) = mapping_get(mapping, "matchers") {
        validate_operator_list(matchers, template_id, request_index, "matcher", true)?;
    }
    if let Some(extractors) = mapping_get(mapping, "extractors") {
        validate_operator_list(extractors, template_id, request_index, "extractor", false)?;
    }
    Ok(())
}

fn validate_operator_list(
    value: &Value,
    template_id: &str,
    request_index: usize,
    operator: &str,
    matcher: bool,
) -> Result<()> {
    let operators = value.as_sequence().filter(|items| !items.is_empty()).ok_or_else(|| {
        config_error(format!(
            "template '{template_id}' http request {} {operator}s are not a nonempty sequence",
            request_index + 1
        ))
    })?;
    for (operator_index, value) in operators.iter().enumerate() {
        let mapping = value.as_mapping().ok_or_else(|| {
            config_error(format!(
                "template '{template_id}' {operator} {} is not a mapping",
                operator_index + 1
            ))
        })?;
        let kind = mapping_string(mapping, "type").ok_or_else(|| {
            config_error(format!(
                "template '{template_id}' {operator} {} has no scalar type",
                operator_index + 1
            ))
        })?;
        let kind_keys: &[&str] = if matcher {
            match kind {
                "binary" => &["binary"],
                "regex" => &["regex"],
                "size" => &["size"],
                "status" => &["status"],
                "word" => &["case-insensitive", "encoding", "words"],
                _ => {
                    return Err(config_error(format!(
                        "template '{template_id}' uses unsupported matcher type '{kind}'"
                    )))
                }
            }
        } else {
            match kind {
                "json" => &["json"],
                "kval" => &["kval"],
                "regex" => &["group", "regex"],
                _ => {
                    return Err(config_error(format!(
                        "template '{template_id}' uses unsupported extractor type '{kind}'"
                    )))
                }
            }
        };
        let common = if matcher { MATCHER_COMMON_KEYS } else { EXTRACTOR_COMMON_KEYS };
        for key in mapping.keys() {
            let Some(key) = key.as_str() else {
                return Err(config_error(format!(
                    "template '{template_id}' {operator} {} has a non-string key",
                    operator_index + 1
                )));
            };
            if !common.contains(&key) && !kind_keys.contains(&key) {
                return Err(config_error(format!(
                    "template '{template_id}' {operator} {} uses unsupported key '{key}'",
                    operator_index + 1
                )));
            }
        }
        reject_operator_expressions(value, template_id, operator)?;
    }
    Ok(())
}

fn reject_operator_expressions(value: &Value, template_id: &str, operator: &str) -> Result<()> {
    match value {
        Value::String(value)
            if value.contains("{{") || value.contains("}}") || contains_oast_token(value) =>
        {
            Err(config_error(format!(
                "template '{template_id}' {operator} contains a runtime expression"
            )))
        }
        Value::Sequence(values) => {
            for value in values {
                reject_operator_expressions(value, template_id, operator)?;
            }
            Ok(())
        }
        Value::Mapping(values) => {
            for value in values.values() {
                reject_operator_expressions(value, template_id, operator)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_external_request_value(value: &str, template_id: &str, carrier: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("dns://")
        || contains_oast_token(&lower)
        || value.contains("{{")
        || value.contains("}}")
    {
        return Err(config_error(format!(
            "template '{template_id}' {carrier} contains an external or out-of-band target"
        )));
    }
    Ok(())
}

fn contains_oast_token(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("interactsh") || lower.contains("oast.") || lower.contains("oast-")
}

const fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn mapping_string<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a str> {
    mapping_get(mapping, key).and_then(Value::as_str)
}

const fn config_error(message: String) -> ScorchError {
    ScorchError::Config(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(request: &str) -> Vec<u8> {
        format!(
            "id: fixture\ninfo:\n  name: Fixture\n  author: test\n  severity: info\nhttp:\n  - {request}\n# digest: aa:fragment\n"
        )
        .into_bytes()
    }

    #[test]
    fn structured_get_is_active_safe_and_mutating_methods_or_bodies_are_intrusive() {
        let get = classify_template(
            &template("method: GET\n    path:\n      - '{{BaseURL}}/health'"),
            "fixture",
        )
        .expect("GET template");
        assert_eq!(get.effect_floor, EffectClass::ActiveSafe);

        for request in [
            "method: POST\n    path:\n      - '{{BaseURL}}/check'",
            "method: GET\n    path:\n      - '{{RootURL}}/check'\n    body: probe",
        ] {
            let classified =
                classify_template(&template(request), "fixture").expect("intrusive template");
            assert_eq!(classified.effect_floor, EffectClass::Intrusive);
        }
    }

    #[test]
    fn every_non_http_protocol_and_unknown_execution_key_fails_closed() {
        for key in DENIED_PROTOCOL_KEYS {
            let bytes = format!(
                "id: fixture\ninfo: {{name: Fixture, author: test, severity: info}}\n{key}: []\nhttp:\n  - method: GET\n    path: ['{{{{BaseURL}}}}/']\n"
            );
            assert!(classify_template(bytes.as_bytes(), "fixture").is_err(), "accepted {key}");
        }
        let unknown = b"id: fixture\ninfo: {}\nhttp: []\nvariables: {}\n";
        assert!(classify_template(unknown, "fixture").is_err());
    }

    #[test]
    fn authority_credentials_external_targets_and_unsafe_options_are_rejected() {
        for request in [
            "method: GET\n    path: ['https://outside.test/']",
            "method: GET\n    path: ['{{BaseURL}}//outside.test/']",
            "method: GET\n    path: ['{{BaseURL}}/']\n    headers: {Host: outside.test}",
            "method: GET\n    path: ['{{BaseURL}}/']\n    headers: {Authorization: fixture}",
            "method: POST\n    path: ['{{BaseURL}}/']\n    body: 'url=https://outside.test/'",
            "method: GET\n    path: ['{{BaseURL}}/']\n    unsafe: true",
            "method: GET\n    path: ['{{BaseURL}}/{{interactsh-url}}']",
            "method: GET\n    path: ['{{BaseURL}}/{{randstr}}']",
            "method: CONNECT\n    path: ['{{BaseURL}}/']",
            "method: GET\n    path: ['{{BaseURL}}\\\\outside.test']",
            "method: GET\n    path: ['{{BaseURL}}?next=/outside']",
            "method: GET\n    path: ['{{BaseURL}}/']\n    headers: {X-Probe: '{{randstr}}'}",
            "method: GET\n    path: ['{{BaseURL}}/']\n    headers: {'Bad Header': value}",
            "method: POST\n    path: ['{{BaseURL}}/']\n    body: '{{file(\"/etc/passwd\")}}'",
        ] {
            assert!(
                classify_template(&template(request), "fixture").is_err(),
                "accepted request: {request}"
            );
        }
    }

    #[test]
    fn response_operators_deny_dsl_dns_oast_and_unknown_shapes() {
        for request in [
            "method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: dsl\n        dsl: [\"resolve('outside.test', 'a') == '127.0.0.1'\"]",
            "method: GET\n    path: ['{{BaseURL}}/']\n    extractors:\n      - type: dsl\n        dsl: [\"wait_for(60)\"]",
            "method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: word\n        words: ['{{interactsh-url}}']",
            "method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: word\n        words: [safe]\n        dsl: [\"resolve('outside.test', 'a')\"]",
        ] {
            assert!(
                classify_template(&template(request), "fixture").is_err(),
                "accepted response operator: {request}"
            );
        }

        let safe = template(
            "method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: word\n        part: body\n        words: [safe]\n    extractors:\n      - type: regex\n        part: body\n        regex: ['version=[0-9]+']",
        );
        assert!(classify_template(&safe, "fixture").is_ok());
    }

    #[test]
    fn approved_id_and_exact_http_shape_are_required() {
        let bytes = template("method: GET\n    path:\n      - '{{BaseURL}}/'");
        assert!(classify_template(&bytes, "other").is_err());
        assert!(classify_template(b"[]", "fixture").is_err());
        assert!(classify_template(b"id: fixture\ninfo: {}\nhttp: []\n", "fixture").is_err());
        let duplicate_http = b"id: fixture\ninfo: {}\nhttp: []\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n";
        assert!(
            classify_template(duplicate_http, "fixture").is_err(),
            "duplicate YAML keys must not cross parser boundaries"
        );
    }
}
