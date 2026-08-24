use scorchkit_extension::{
    export_extension, ExtensionFindingV1, ExtensionOutputV1, ExtensionTurnInputV1,
    ExtensionTurnOutputV1, GuestExtension,
};

#[derive(Default)]
struct HeaderExtension;

impl GuestExtension for HeaderExtension {
    fn turn(&mut self, input: ExtensionTurnInputV1) -> ExtensionTurnOutputV1 {
        match input {
            ExtensionTurnInputV1::Start(invocation) => {
                ExtensionTurnOutputV1::Complete(ExtensionOutputV1 {
                    findings: vec![ExtensionFindingV1 {
                        title: "Example isolated extension".to_string(),
                        description: "The no-import guest returned one typed proposal".to_string(),
                        affected_target: invocation.target,
                        severity: "info".to_string(),
                        confidence: 1.0,
                        remediation: None,
                        owasp_category: None,
                        cwe_id: None,
                        observations: Vec::new(),
                        evidence: Vec::new(),
                        source_artifacts: Vec::new(),
                    }],
                    diagnostics: Vec::new(),
                })
            }
            ExtensionTurnInputV1::EffectResult(_) => {
                ExtensionTurnOutputV1::Complete(ExtensionOutputV1 {
                    findings: Vec::new(),
                    diagnostics: vec!["unexpected effect result".to_string()],
                })
            }
        }
    }
}

export_extension!(HeaderExtension);
