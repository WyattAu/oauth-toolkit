//! Lightweight JWT helpers for HS256 operations.

use serde::{Deserialize, Serialize};

/// Errors for JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Token has expired.
    #[error("token expired")]
    Expired,

    /// Token is invalid.
    #[error("invalid token: {0}")]
    Invalid(String),

    /// A required claim is missing.
    #[error("missing claim: {0}")]
    MissingClaim(String),
}

/// Encode a claims struct as an HS256 JWT.
pub fn encode_hs256(claims: &impl Serialize, secret: &str) -> Result<String, JwtError> {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| JwtError::Invalid(e.to_string()))
}

/// Decode and validate an HS256 JWT, returning typed claims.
pub fn decode_hs256<T: for<'de> Deserialize<'de>>(
    token: &str,
    secret: &str,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> Result<T, JwtError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);

    if let Some(iss) = issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = audience {
        validation.set_audience(&[aud]);
    }

    jsonwebtoken::decode::<T>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match *e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
        _ => JwtError::Invalid(e.to_string()),
    })
}

/// Extract a Bearer token from an Authorization header value.
pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ").map(|t| t.trim())
}

/// Build a Set-Cookie header value for an auth token.
pub fn build_auth_cookie(cookie_name: &str, token: &str, max_age_secs: i64) -> String {
    format!("{cookie_name}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}")
}

#[cfg(test)]
// Test code: unwrap/expect are the idiomatic way to assert setup success.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: usize,
        iat: usize,
    }

    #[test]
    fn encode_decode_roundtrip() {
        let claims = TestClaims {
            sub: "user123".into(),
            exp: 9999999999,
            iat: 1000000000,
        };
        let token = encode_hs256(&claims, "secret-key-1234567890123456").unwrap();
        let decoded: TestClaims =
            decode_hs256(&token, "secret-key-1234567890123456", None, None).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn decode_wrong_secret_fails() {
        let claims = TestClaims {
            sub: "user123".into(),
            exp: 9999999999,
            iat: 1000000000,
        };
        let token = encode_hs256(&claims, "secret1").unwrap();
        assert!(decode_hs256::<TestClaims>(&token, "secret2", None, None).is_err());
    }

    #[test]
    fn extract_bearer_token_valid() {
        assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123"));
    }

    #[test]
    fn extract_bearer_token_missing() {
        assert!(extract_bearer_token("Basic abc123").is_none());
    }

    #[test]
    fn build_auth_cookie_format() {
        let cookie = build_auth_cookie("session", "tok123", 3600);
        assert!(cookie.contains("session=tok123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Max-Age=3600"));
    }
}
