//! Attack-chain report formatter — text + Mermaid diagram (WORK-139).
//!
//! Renders [`AttackChain`]s as human-readable text summaries and
//! Mermaid flowchart diagrams for HTML reports.

use std::fmt::Write;

use crate::engine::correlation::AttackChain;

/// Format attack chains as a human-readable text report.
#[must_use]
pub fn format_attack_chains(chains: &[AttackChain]) -> String {
    let mut out = String::new();

    if chains.is_empty() {
        out.push_str("No attack chains identified.\n");
        return out;
    }

    let _ = writeln!(out, "=== Attack Chains ({} identified) ===\n", chains.len());

    for (i, chain) in chains.iter().enumerate() {
        let _ = writeln!(
            out,
            "{}. [{}] {} (priority: {})",
            i + 1,
            chain.severity,
            chain.name,
            chain.remediation_priority
        );
        let _ = writeln!(out, "   {}", chain.description);
        let _ = writeln!(out, "   Steps:");
        for step in &chain.steps {
            let _ = writeln!(out, "     → [{}] {} ({})", step.module_id, step.title, step.role);
        }
        out.push('\n');
    }

    out
}

/// Generate a Mermaid flowchart diagram from attack chains.
///
/// Produces a `graph TD` Mermaid diagram where each chain is a
/// subgraph and steps flow top-down with role annotations.
#[must_use]
pub fn render_mermaid(chains: &[AttackChain]) -> String {
    let mut out = String::from("graph TD\n");

    for (ci, chain) in chains.iter().enumerate() {
        let chain_id = format!("chain{ci}");
        let _ = writeln!(out, "  subgraph {chain_id}[\"{} ({})\"]", chain.name, chain.severity);

        for (si, step) in chain.steps.iter().enumerate() {
            let node_id = format!("{chain_id}_s{si}");
            let label = format!("{}: {}", step.module_id, step.title);
            let _ = writeln!(out, "    {node_id}[\"{label}\"]");

            if si > 0 {
                let prev = format!("{chain_id}_s{}", si - 1);
                let _ = writeln!(out, "    {prev} -->|{}| {node_id}", step.role);
            }
        }

        let _ = writeln!(out, "  end");
    }

    out
}

/// Wrap a Mermaid diagram in an HTML page with the Mermaid JS renderer.
#[must_use]
pub fn render_mermaid_html(chains: &[AttackChain]) -> String {
    let mermaid = render_mermaid(chains);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ScorchKit Attack Chain Report</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 1200px; margin: 2em auto; }}
    h1 {{ color: #1a1a2e; }}
    .mermaid {{ background: #f8f9fa; padding: 1em; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>Attack Chain Analysis</h1>
  <p>{count} attack chain{s} identified across {step_count} findings.</p>
  <div class="mermaid">
{mermaid}
  </div>
  <script>mermaid.initialize({{ startOnLoad: true, theme: 'default' }});</script>
</body>
</html>"#,
        count = chains.len(),
        s = if chains.len() == 1 { "" } else { "s" },
        step_count = chains.iter().map(|c| c.steps.len()).sum::<usize>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::correlation::ChainStep;
    use crate::engine::severity::Severity;

    fn sample_chain() -> AttackChain {
        AttackChain {
            name: "Test Chain".into(),
            severity: Severity::High,
            description: "A test chain".into(),
            steps: vec![
                ChainStep {
                    module_id: "xss".into(),
                    title: "XSS Found".into(),
                    role: "entry".into(),
                },
                ChainStep {
                    module_id: "headers".into(),
                    title: "Missing CSP".into(),
                    role: "enabler".into(),
                },
            ],
            remediation_priority: "high".into(),
        }
    }

    /// Text format includes chain name and steps.
    #[test]
    fn test_format_attack_chains_text() {
        let chains = vec![sample_chain()];
        let text = format_attack_chains(&chains);
        assert!(text.contains("Test Chain"));
        assert!(text.contains("XSS Found"));
        assert!(text.contains("Missing CSP"));
    }

    /// Empty chains → "No attack chains" message.
    #[test]
    fn test_format_attack_chains_empty() {
        let text = format_attack_chains(&[]);
        assert!(text.contains("No attack chains"));
    }

    /// Mermaid output is valid graph syntax.
    #[test]
    fn test_render_mermaid() {
        let chains = vec![sample_chain()];
        let mermaid = render_mermaid(&chains);
        assert!(mermaid.starts_with("graph TD"));
        assert!(mermaid.contains("subgraph"));
        assert!(mermaid.contains("XSS Found"));
        assert!(mermaid.contains("-->"));
    }

    /// HTML wrapper includes Mermaid JS.
    #[test]
    fn test_render_mermaid_html() {
        let chains = vec![sample_chain()];
        let html = render_mermaid_html(&chains);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("mermaid"));
        assert!(html.contains("Attack Chain"));
    }
}
