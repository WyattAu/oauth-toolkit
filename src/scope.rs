//! OAuth2 scope parsing and validation.

/// Parse a space- or comma-separated scope string into a sorted, deduplicated vec.
pub fn parse_scopes(input: &str) -> Vec<String> {
    let mut scopes: Vec<String> = input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_lowercase())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Validate that every requested scope is in the allowed set.
///
/// Returns the normalized scope list on success, or the first unknown scope as an error.
pub fn validate_scopes(requested: &[String], allowed: &[&str]) -> Result<Vec<String>, ScopeError> {
    for scope in requested {
        if !allowed.contains(&scope.as_str()) {
            return Err(ScopeError::UnknownScope(scope.clone()));
        }
    }
    Ok(requested.to_vec())
}

/// Check that `requested` scopes are a subset of `allowed` scopes.
pub fn scopes_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|r| allowed.contains(r))
}

/// Errors for scope operations.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// An unknown scope was requested.
    #[error("unknown scope: {0}")]
    UnknownScope(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scopes_whitespace() {
        assert_eq!(
            parse_scopes("read write admin"),
            vec!["admin", "read", "write"]
        );
    }

    #[test]
    fn parse_scopes_comma() {
        assert_eq!(
            parse_scopes("read,write,admin"),
            vec!["admin", "read", "write"]
        );
    }

    #[test]
    fn parse_scopes_dedup() {
        assert_eq!(parse_scopes("read read"), vec!["read"]);
    }

    #[test]
    fn validate_scopes_ok() {
        let requested = vec!["read".into(), "write".into()];
        let allowed = &["read", "write", "admin"];
        assert!(validate_scopes(&requested, allowed).is_ok());
    }

    #[test]
    fn validate_scopes_unknown() {
        let requested = vec!["read".into(), "dangerous".into()];
        let allowed = &["read", "write"];
        assert!(validate_scopes(&requested, allowed).is_err());
    }

    #[test]
    fn scopes_subset_true() {
        assert!(scopes_subset(&["a".into()], &["a".into(), "b".into()]));
    }

    #[test]
    fn scopes_subset_false() {
        assert!(!scopes_subset(
            &["a".into(), "c".into()],
            &["a".into(), "b".into()]
        ));
    }
}
