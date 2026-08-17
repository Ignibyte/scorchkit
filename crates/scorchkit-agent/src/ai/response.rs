//! JSON extraction used by the versioned AI contract decoder.

use serde::de::DeserializeOwned;

/// Extract one typed JSON value from direct, fenced, or prefixed provider text.
///
/// Contract validation still occurs in `ai::contracts`; successful extraction
/// alone does not make a provider response valid.
#[must_use]
pub fn try_extract<T: DeserializeOwned>(raw: &str) -> Option<T> {
    let trimmed = raw.trim();

    if let Ok(value) = serde_json::from_str(trimmed) {
        return Some(value);
    }

    if let Some(fenced) = extract_code_fence(trimmed) {
        if let Ok(value) = serde_json::from_str(fenced) {
            return Some(value);
        }
    }

    let start = trimmed.find('{')?;
    serde_json::Deserializer::from_str(&trimmed[start..])
        .into_iter::<T>()
        .next()
        .and_then(std::result::Result::ok)
}

fn extract_code_fence(text: &str) -> Option<&str> {
    let start_markers = ["```json\n", "```json\r\n", "```JSON\n"];
    for marker in &start_markers {
        if let Some(start) = text.find(marker) {
            let content_start = start + marker.len();
            if let Some(end) = text[content_start..].find("```") {
                return Some(text[content_start..content_start + end].trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_direct_fenced_and_prefixed_json() {
        for input in [
            r#"{"key":"direct"}"#,
            "```json\n{\"key\":\"fenced\"}\n```",
            "Provider preamble {\"key\":\"prefixed\"} trailing text",
        ] {
            let value: serde_json::Value = try_extract(input).expect("JSON value");
            assert!(value["key"].is_string());
        }
    }

    #[test]
    fn serde_owns_escaped_and_nested_object_boundaries() {
        let input = r#"Preamble {"key":"quote: \" slash: \\ brace: }","nested":{"inner":1}} after"#;
        let value: serde_json::Value = try_extract(input).expect("first object");
        assert_eq!(value["key"], "quote: \" slash: \\ brace: }");
        assert_eq!(value["nested"]["inner"], 1);
    }

    #[test]
    fn rejects_text_without_a_typed_json_value() {
        assert!(try_extract::<serde_json::Value>("plain text").is_none());
        assert!(try_extract::<serde_json::Value>("```not-json```").is_none());
    }
}
