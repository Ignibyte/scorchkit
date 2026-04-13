use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

/// Create a spinner for a running module.
#[must_use]
pub fn module_spinner(module_name: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    pb.set_style(style);
    pb.set_message(format!("Running {module_name}..."));
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Finish a spinner with a success message.
pub fn finish_success(pb: &ProgressBar, module_name: &str, finding_count: usize) {
    if finding_count == 0 {
        pb.finish_with_message(format!("{module_name} - no issues found"));
    } else {
        pb.finish_with_message(format!(
            "{module_name} - {finding_count} finding{}",
            if finding_count == 1 { "" } else { "s" }
        ));
    }
}

/// Finish a spinner with an error message.
pub fn finish_error(pb: &ProgressBar, module_name: &str, error: &str) {
    pb.finish_with_message(format!("{module_name} - ERROR: {error}"));
}
