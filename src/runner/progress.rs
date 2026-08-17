use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

use crate::report::terminal::escape_terminal_text;

/// Return whether human progress should be rendered for this invocation.
#[must_use]
pub(crate) const fn is_visible(quiet: bool) -> bool {
    !quiet
}

/// Return whether a count-backed status has visible items to render.
#[must_use]
pub(crate) const fn has_visible_items(item_count: usize, quiet: bool) -> bool {
    item_count > 0 && is_visible(quiet)
}

/// Return whether an empty-state message should be rendered.
#[must_use]
pub(crate) const fn has_no_visible_items(item_count: usize, quiet: bool) -> bool {
    item_count == 0 && is_visible(quiet)
}

/// Create a spinner for a running module.
#[must_use]
pub fn module_spinner(module_name: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    pb.set_style(style);
    pb.set_message(format!("Running {}...", escape_terminal_text(module_name)));
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Finish a spinner with a success message.
pub fn finish_success(pb: &ProgressBar, module_name: &str, finding_count: usize) {
    let module_name = escape_terminal_text(module_name);
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
    pb.finish_with_message(format!(
        "{} - ERROR: {}",
        escape_terminal_text(module_name),
        escape_terminal_text(error)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_visibility_is_the_inverse_of_quiet_mode() {
        assert!(is_visible(false));
        assert!(!is_visible(true));
    }

    #[test]
    fn count_backed_status_requires_visibility_and_the_expected_cardinality() {
        assert!(!has_visible_items(0, false));
        assert!(has_visible_items(1, false));
        assert!(has_visible_items(2, false));
        assert!(!has_visible_items(0, true));
        assert!(!has_visible_items(1, true));

        assert!(has_no_visible_items(0, false));
        assert!(!has_no_visible_items(1, false));
        assert!(!has_no_visible_items(0, true));
        assert!(!has_no_visible_items(1, true));
    }

    #[test]
    fn completed_spinner_messages_preserve_counts_and_escape_controls() {
        let none = ProgressBar::hidden();
        finish_success(&none, "headers", 0);
        assert_eq!(none.message(), "headers - no issues found");

        let one = ProgressBar::hidden();
        finish_success(&one, "scanner\u{1b}", 1);
        assert_eq!(one.message(), "scanner\\u{1b} - 1 finding");

        let many = ProgressBar::hidden();
        finish_success(&many, "scanner", 2);
        assert_eq!(many.message(), "scanner - 2 findings");

        let failed = ProgressBar::hidden();
        finish_error(&failed, "tool\u{1b}", "bad\u{7}");
        assert_eq!(failed.message(), "tool\\u{1b} - ERROR: bad\\u{7}");
    }
}
