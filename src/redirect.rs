//! Redirect URI validation for OAuth2.

/// Exact-match a redirect URI against a registered allowlist.
pub fn redirect_uri_allowed(requested: &str, registered: &[String]) -> bool {
    registered.iter().any(|r| r == requested)
}

/// Build a provider callback redirect URI from a base URL and provider name.
///
/// Returns `"{base_url}/auth/callback/{provider}"`.
pub fn build_redirect_uri(base_url: &str, provider: &str) -> String {
    format!("{}/auth/callback/{}", base_url.trim_end_matches('/'), provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_allowed_exact() {
        assert!(redirect_uri_allowed("https://app.com/callback", &["https://app.com/callback".into()]));
    }

    #[test]
    fn redirect_uri_allowed_mismatch() {
        assert!(!redirect_uri_allowed("https://evil.com/callback", &["https://app.com/callback".into()]));
    }

    #[test]
    fn redirect_uri_allowed_empty() {
        assert!(!redirect_uri_allowed("https://app.com", &[]));
    }

    #[test]
    fn build_redirect_uri_works() {
        assert_eq!(build_redirect_uri("https://app.com", "github"), "https://app.com/auth/callback/github");
    }

    #[test]
    fn build_redirect_uri_trailing_slash() {
        assert_eq!(build_redirect_uri("https://app.com/", "google"), "https://app.com/auth/callback/google");
    }
}
