use std::fmt::Write;

use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Result, ScorchError};

/// Target specification parsed from user input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// The original input string from the user.
    pub raw: String,
    /// Parsed URL.
    pub url: Url,
    /// Domain name extracted from the URL.
    pub domain: Option<String>,
    /// Port (from URL or default 443/80).
    pub port: u16,
    /// Whether the target uses HTTPS.
    pub is_https: bool,
}

impl Target {
    /// Parse a target string into a structured `Target`.
    ///
    /// Accepts full URLs (`https://example.com`) or bare domains (`example.com`).
    /// Bare domains default to HTTPS on port 443.
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be parsed as a valid URL or has no host.
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.to_string();

        // If no scheme, prepend https://
        let url_str = if input.starts_with("http://") || input.starts_with("https://") {
            input.to_string()
        } else {
            format!("https://{input}")
        };

        let url = Url::parse(&url_str).map_err(|e| ScorchError::InvalidTarget {
            target: raw.clone(),
            reason: e.to_string(),
        })?;

        let domain = url.host_str().map(String::from);
        let is_https = url.scheme() == "https";
        let port = url.port().unwrap_or(if is_https { 443 } else { 80 });

        if domain.is_none() {
            return Err(ScorchError::InvalidTarget {
                target: raw,
                reason: "no host found in URL".to_string(),
            });
        }

        Ok(Self { raw, url, domain, port, is_https })
    }

    /// Return the base URL (scheme + host + port if non-default).
    #[must_use]
    pub fn base_url(&self) -> String {
        let mut base = format!("{}://{}", self.url.scheme(), self.domain.as_deref().unwrap_or(""));
        let default_port = if self.is_https { 443 } else { 80 };
        if self.port != default_port {
            let _ = write!(base, ":{}", self.port);
        }
        base
    }
}

/// Parse a targets file into a list of target strings.
///
/// Each non-empty, non-comment line is treated as a target URL or domain.
/// Lines starting with `#` are comments. Leading/trailing whitespace is trimmed.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn parse_targets_file(path: &std::path::Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ScorchError::Config(format!("failed to read targets file {}: {e}", path.display()))
    })?;
    let targets: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();
    if targets.is_empty() {
        return Err(ScorchError::Config(format!(
            "targets file {} contains no valid targets",
            path.display()
        )));
    }
    Ok(targets)
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_https_url() {
        let t = Target::parse("https://example.com").unwrap();
        assert_eq!(t.domain.as_deref(), Some("example.com"));
        assert_eq!(t.port, 443);
        assert!(t.is_https);
    }

    #[test]
    fn parse_http_url() {
        let t = Target::parse("http://example.com").unwrap();
        assert_eq!(t.port, 80);
        assert!(!t.is_https);
    }

    #[test]
    fn parse_bare_domain_defaults_https() {
        let t = Target::parse("example.com").unwrap();
        assert!(t.is_https);
        assert_eq!(t.port, 443);
        assert_eq!(t.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_custom_port() {
        let t = Target::parse("https://example.com:8443").unwrap();
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn parse_with_path() {
        let t = Target::parse("https://example.com/app/login").unwrap();
        assert_eq!(t.domain.as_deref(), Some("example.com"));
        assert!(t.url.as_str().contains("/app/login"));
    }

    #[test]
    fn base_url_omits_default_port() {
        let t = Target::parse("https://example.com").unwrap();
        assert_eq!(t.base_url(), "https://example.com");
    }

    #[test]
    fn base_url_includes_custom_port() {
        let t = Target::parse("https://example.com:8443").unwrap();
        assert_eq!(t.base_url(), "https://example.com:8443");
    }

    /// Verify targets file parsing skips comments and blank lines.
    #[test]
    fn parse_targets_file_skips_comments() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("targets.txt");
        std::fs::write(
            &path,
            "# Production targets\nhttps://example.com\n\n  http://test.local  \n# staging\napi.example.com\n",
        )
        .expect("write test file");
        let targets = parse_targets_file(&path).expect("parse targets");
        assert_eq!(targets, vec!["https://example.com", "http://test.local", "api.example.com"]);
    }

    /// Verify empty targets file returns an error.
    #[test]
    fn parse_targets_file_empty_errors() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "# only comments\n\n").expect("write test file");
        let result = parse_targets_file(&path);
        assert!(result.is_err());
    }

    /// Verify missing targets file returns an error.
    #[test]
    fn parse_targets_file_missing_errors() {
        let result = parse_targets_file(std::path::Path::new("/nonexistent/targets.txt"));
        assert!(result.is_err());
    }
}
