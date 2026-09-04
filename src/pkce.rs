//! RFC 7636 PKCE (Proof Key for Code Exchange) support.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::Digest;

/// PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// SHA-256 hash of the verifier (recommended).
    S256,
    /// Plain text (not recommended for production).
    Plain,
}

/// Generate a PKCE code verifier and its S256 challenge.
///
/// Returns `(verifier, challenge)` where:
/// - `verifier` is a 43-128 character random string (URL-safe base64)
/// - `challenge` is `base64url(SHA256(verifier))`
pub fn generate_pkce_pair() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill(&mut verifier_bytes[..]);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let challenge = sha256_base64url(&verifier);
    (verifier, challenge)
}

/// Verify a PKCE code challenge against the verifier.
///
/// Supports S256 (base64url(SHA256(verifier)) == challenge) and plain (verifier == challenge).
pub fn verify_pkce(code_verifier: &str, stored_challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let computed = sha256_base64url(code_verifier);
            constant_time_eq(computed.as_bytes(), stored_challenge.as_bytes())
        }
        "plain" => constant_time_eq(code_verifier.as_bytes(), stored_challenge.as_bytes()),
        _ => false,
    }
}

fn sha256_base64url(input: &str) -> String {
    let hash = sha2::Sha256::digest(input.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_pkce_pair_deterministic_challenge() {
        let (v, c) = generate_pkce_pair();
        let expected = sha256_base64url(&v);
        assert_eq!(c, expected);
    }

    #[test]
    fn verify_pkce_s256_correct() {
        let (verifier, challenge) = generate_pkce_pair();
        assert!(verify_pkce(&verifier, &challenge, "S256"));
    }

    #[test]
    fn verify_pkce_s256_wrong_verifier() {
        let (_, challenge) = generate_pkce_pair();
        assert!(!verify_pkce("wrong-verifier", &challenge, "S256"));
    }

    #[test]
    fn verify_pkce_plain_correct() {
        assert!(verify_pkce("test", "test", "plain"));
    }

    #[test]
    fn verify_pkce_plain_wrong() {
        assert!(!verify_pkce("test", "wrong", "plain"));
    }

    #[test]
    fn verify_pkce_unknown_method() {
        assert!(!verify_pkce("a", "b", "unknown"));
    }
}
