use crate::ai::prompts::AnalysisFocus;

/// Structured result from AI analysis.
#[derive(Debug)]
pub struct AiAnalysis {
    /// Which analysis mode was used.
    pub focus: &'static str,
    /// The raw analysis text from Claude.
    pub content: String,
    /// Cost of the analysis (USD), if reported.
    pub cost_usd: Option<f64>,
    /// Model used.
    pub model: Option<String>,
}

/// Parse the Claude CLI JSON output into an `AiAnalysis`.
pub fn parse_claude_response(output: &str, focus: AnalysisFocus) -> AiAnalysis {
    // Claude CLI --output-format json returns:
    // {"type":"result","subtype":"success","cost_usd":0.05,"is_error":false,
    //  "duration_ms":3000,"duration_api_ms":2800,"num_turns":1,
    //  "result":"the analysis text...","session_id":"..."}

    let (content, cost_usd, model) =
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
            let text = json["result"]
                .as_str()
                .unwrap_or_else(|| {
                    // Fallback: check for "content" or plain text
                    json["content"].as_str().unwrap_or(output)
                })
                .to_string();

            let cost = json["cost_usd"].as_f64();
            let model = json["model"].as_str().map(String::from);

            (text, cost, model)
        } else {
            // Not JSON — treat entire output as the analysis text
            (output.to_string(), None, None)
        };

    AiAnalysis { focus: focus.label(), content, cost_usd, model }
}
