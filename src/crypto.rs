//! Cryptographic helpers for OAuth2 tokens and secrets.

use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 hex digest of a raw value (unkeyed).
///
/// Used for hashing bearer tokens and authorization codes at rest.
pub fn sha256_hex(value: &str) -> String {
    let hash = Sha256::digest(value.as_bytes());
    hex::encode(hash)
}

/// HMAC-SHA256 keyed hash of a value.
///
/// Used for hashing client secrets at registration time.
pub fn hmac_sha256_hex(key: &str, value: &str) -> String {
    // HMAC-SHA256 accepts keys of any length, so `new_from_slice` cannot
    // fail here; the panic branch is unreachable by construction.
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature (constant-time comparison).
pub fn hmac_sha256_verify(key: &str, value: &str, signature_hex: &str) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    mac.update(value.as_bytes());
    let expected =
        hex::decode(signature_hex).map_err(|e| CryptoError::InvalidHex(e.to_string()))?;
    mac.verify_slice(&expected)
        .map_err(|_| CryptoError::SignatureMismatch)
}

/// Generate a cryptographically secure random token with a configurable prefix.
///
/// Returns "{prefix}{random_hex}" where random_hex has `2 * byte_length` hex characters.
pub fn generate_opaque_token(prefix: &str, byte_length: usize) -> String {
    let mut bytes = vec![0u8; byte_length];
    rand::rng().fill(&mut bytes[..]);
    format!("{}{}", prefix, hex::encode(bytes))
}

/// Generate a hex-encoded random state nonce for CSRF / PKCE state.
pub fn generate_state_nonce(byte_length: usize) -> String {
    generate_opaque_token("", byte_length)
}

/// Errors for cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Invalid key for HMAC operation.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid hex encoding.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Signature does not match (constant-time comparison).
    #[error("signature mismatch")]
    SignatureMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn sha256_hex_different_inputs() {
        assert_ne!(sha256_hex("hello"), sha256_hex("world"));
    }

    #[test]
    fn hmac_roundtrip() {
        let sig = hmac_sha256_hex("secret-key", "test-message");
        assert!(hmac_sha256_verify("secret-key", "test-message", &sig).is_ok());
    }

    #[test]
    fn hmac_wrong_key_fails() {
        let sig = hmac_sha256_hex("key1", "message");
        assert!(hmac_sha256_verify("key2", "message", &sig).is_err());
    }

    #[test]
    fn hmac_wrong_message_fails() {
        let sig = hmac_sha256_hex("key", "msg1");
        assert!(hmac_sha256_verify("key", "msg2", &sig).is_err());
    }

    #[test]
    fn generate_opaque_token_prefix() {
        let token = generate_opaque_token("tok_", 16);
        assert!(token.starts_with("tok_"));
        assert_eq!(token.len(), 4 + 32);
    }

    #[test]
    fn generate_state_nonce_length() {
        let nonce = generate_state_nonce(16);
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn hmac_invalid_hex_fails() {
        assert!(hmac_sha256_verify("key", "msg", "not-hex").is_err());
    }
}
