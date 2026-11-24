//! JWT helpers: HS256 (shared-secret) and ES256/RS256 (PEM-key,
//! asymmetric) — the asymmetric pair is what any estate OIDC issuer
//! needs (research loop wave 3b prerequisite).

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

/// A signature-validated HS256 token without typed claims: raw header
/// and payload bytes.
///
/// The hot-path variant of [`decode_hs256`]: signature is verified
/// (constant-time compare) and `alg` is pinned to HS256 (alg-confusion
/// defense), but NO claim validation runs — no serde deserialization, no
/// exp/iss/aud checks. For servers with a fixed, tiny payload shape that
/// parse claims themselves, or callers that need the payload bytes before
/// choosing a claims type. The caller owns claim validation, including
/// expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHs256 {
    /// Decoded header JSON (alg/kid/typ as the issuer wrote it).
    pub header: Vec<u8>,
    /// Decoded payload JSON, signature verified.
    pub payload: Vec<u8>,
}

/// Verify an HS256 token and return its raw parts. See [`RawHs256`].
///
/// # Errors
/// - [`JwtError::Invalid`] on malformed structure, a non-HS256 `alg`
///   header, or a signature mismatch.
pub fn decode_hs256_raw(token: &str, secret: &str) -> Result<RawHs256, JwtError> {
    let mut parts = token.split('.');
    let (Some(h_b64), Some(p_b64), Some(s_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Invalid("malformed token: want 3 segments".into()));
    };
    if h_b64.is_empty() || p_b64.is_empty() || s_b64.is_empty() {
        return Err(JwtError::Invalid("empty segment".into()));
    }
    let header = b64url_decode_segment(h_b64)?;
    let payload = b64url_decode_segment(p_b64)?;
    let sig = b64url_decode_segment(s_b64)?;
    // alg confusion defense: the header must declare HS256. Parse the
    // header as JSON (robust) rather than substring-scanning.
    let hdr: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|e| JwtError::Invalid(format!("header json: {e}")))?;
    if hdr.get("alg").and_then(serde_json::Value::as_str) != Some("HS256") {
        return Err(JwtError::Invalid("alg is not HS256".into()));
    }
    // HMAC-SHA256 over "<header>.<payload>" (the original b64 segments)
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| JwtError::Invalid(format!("hmac key: {e}")))?;
    mac.update(h_b64.as_bytes());
    mac.update(b".");
    mac.update(p_b64.as_bytes());
    let expected = mac.finalize().into_bytes();
    if !crate::crypto::constant_time_eq(&expected, &sig) {
        return Err(JwtError::Invalid("signature mismatch".into()));
    }
    Ok(RawHs256 { header, payload })
}

/// base64url decode tolerating padded or unpadded input (JWTs omit
/// padding; some issuers keep it).
fn b64url_decode_segment(seg: &str) -> Result<Vec<u8>, JwtError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let trimmed = seg.strip_suffix('=').map_or(seg, |s| s);
    let trimmed = trimmed.strip_suffix('=').map_or(trimmed, |s| s);
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| JwtError::Invalid(format!("base64url: {e}")))
}

/// Encode a claims struct as an ES256 JWT (P-256 ECDSA, PKCS#8 PEM key).
///
/// # Errors
/// Returns [`JwtError::Invalid`] for PEM parse or signing failures.
pub fn encode_es256(claims: &impl Serialize, private_key_pem: &str) -> Result<String, JwtError> {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let key = jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .map_err(|e| JwtError::Invalid(format!("bad ES256 private PEM: {e}")))?;
    jsonwebtoken::encode(&header, claims, &key).map_err(|e| JwtError::Invalid(e.to_string()))
}

/// Decode and validate an ES256 JWT, returning typed claims.
///
/// # Errors
/// Returns [`JwtError::Expired`] for expired tokens and
/// [`JwtError::Invalid`] for any signature/claim failure.
pub fn decode_es256<T: for<'de> Deserialize<'de>>(
    token: &str,
    public_key_pem: &str,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> Result<T, JwtError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    if let Some(iss) = issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = audience {
        validation.set_audience(&[aud]);
    }
    let key = jsonwebtoken::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
        .map_err(|e| JwtError::Invalid(format!("bad ES256 public PEM: {e}")))?;
    jsonwebtoken::decode::<T>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match *e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid(e.to_string()),
        })
}

/// Encode a claims struct as an RS256 JWT (RSA, PKCS#8 PEM key).
///
/// # Errors
/// Returns [`JwtError::Invalid`] for PEM parse or signing failures.
pub fn encode_rs256(claims: &impl Serialize, private_key_pem: &str) -> Result<String, JwtError> {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| JwtError::Invalid(format!("bad RS256 private PEM: {e}")))?;
    jsonwebtoken::encode(&header, claims, &key).map_err(|e| JwtError::Invalid(e.to_string()))
}

/// Decode and validate an RS256 JWT, returning typed claims.
///
/// # Errors
/// Returns [`JwtError::Expired`] for expired tokens and
/// [`JwtError::Invalid`] for any signature/claim failure.
pub fn decode_rs256<T: for<'de> Deserialize<'de>>(
    token: &str,
    public_key_pem: &str,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> Result<T, JwtError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    if let Some(iss) = issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = audience {
        validation.set_audience(&[aud]);
    }
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
        .map_err(|e| JwtError::Invalid(format!("bad RS256 public PEM: {e}")))?;
    jsonwebtoken::decode::<T>(token, &key, &validation)
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

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct EsClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: usize,
    }

    const TEST_ES256_PRIV: &str = r##"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxvCgr98XLeY5qBtV
EUAHmzqfBkJclip1tDcOaOnZRnWhRANCAARciewarZqgQwFGY5sTdhAs6Bl8KIjz
KJiV2d3HJBDLGgb/HCrFnhPOFPR2wzgrDrIQvBTQ+dvaEp9KA7EONjR3
-----END PRIVATE KEY-----"##;
    const TEST_ES256_PUB: &str = r##"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXInsGq2aoEMBRmObE3YQLOgZfCiI
8yiYldndxyQQyxoG/xwqxZ4TzhT0dsM4Kw6yELwU0Pnb2hKfSgOxDjY0dw==
-----END PUBLIC KEY-----
"##;

    fn es_claims() -> EsClaims {
        EsClaims {
            sub: "wyatt".to_string(),
            iss: "https://authbox.wyattau.com".to_string(),
            aud: "hosting-api".to_string(),
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize)
                + 600,
        }
    }

    #[test]
    fn es256_roundtrip_and_rejection() {
        let token = encode_es256(&es_claims(), TEST_ES256_PRIV).unwrap();
        let decoded: EsClaims = decode_es256(
            &token,
            TEST_ES256_PUB,
            Some("https://authbox.wyattau.com"),
            Some("hosting-api"),
        )
        .unwrap();
        assert_eq!(decoded, es_claims());

        // Tampered payload must fail.
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "eyJzdWIiOiJldmlsIn0";
        let tampered = parts.join(".");
        assert!(decode_es256::<EsClaims>(&tampered, TEST_ES256_PUB, None, None).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod hs256_raw_tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        username: String,
        exp: i64,
    }

    fn test_claims() -> Claims {
        Claims {
            sub: "42".into(),
            username: "golden_ember".into(),
            // comfortably in the future; typed decode validates exp
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64)
                + 3600,
        }
    }

    #[test]
    fn round_trip_raw_matches_typed() {
        let token = encode_hs256(&test_claims(), "secret").unwrap();
        let raw = decode_hs256_raw(&token, "secret").unwrap();
        let typed: Claims = serde_json::from_slice(&raw.payload).unwrap();
        assert_eq!(typed, test_claims());
        // typed path agrees the token is valid
        let typed2: Claims = decode_hs256(&token, "secret", None, None).unwrap();
        assert_eq!(typed2, test_claims());
    }

    #[test]
    fn tampered_payload_rejected() {
        use base64::Engine as _;
        let token = encode_hs256(&test_claims(), "secret").unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        // flip payload bytes
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let mut evil = payload.clone();
        evil[0] ^= 0x01;
        let evil_seg = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(evil);
        parts[1] = &evil_seg;
        let evil_token = parts.join(".");
        assert!(decode_hs256_raw(&evil_token, "secret").is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = encode_hs256(&test_claims(), "secret").unwrap();
        assert!(decode_hs256_raw(&token, "other-secret").is_err());
    }

    #[test]
    fn alg_confusion_rejected() {
        use base64::Engine as _;
        // header says HS512 but signed as HS256: structurally valid JWT,
        // signature verifies — must STILL be rejected by the alg pin
        let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS512","typ":"JWT"}"#);
        let pl = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"1"}"#);
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(hdr.as_bytes());
        mac.update(b".");
        mac.update(pl.as_bytes());
        let sig =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{hdr}.{pl}.{sig}");
        assert!(decode_hs256_raw(&token, "secret").is_err());
    }

    #[test]
    fn segment_abuse_rejected() {
        assert!(decode_hs256_raw("", "secret").is_err());
        assert!(decode_hs256_raw("a.b", "secret").is_err());
        assert!(decode_hs256_raw("a.b.c.d", "secret").is_err());
        assert!(decode_hs256_raw(".b.c", "secret").is_err());
        assert!(decode_hs256_raw("a..c", "secret").is_err());
        assert!(decode_hs256_raw("!!!.!!!.!!!", "secret").is_err());
    }

    #[test]
    fn exp_is_not_checked_here() {
        // raw = crypto only: an expired token still decodes (caller owns
        // claim validation). typed decode_hs256 must reject the same token.
        let expired = Claims {
            exp: 1,
            ..test_claims()
        };
        let token = encode_hs256(&expired, "secret").unwrap();
        assert!(decode_hs256_raw(&token, "secret").is_ok());
        assert!(matches!(
            decode_hs256::<Claims>(&token, "secret", None, None),
            Err(JwtError::Expired)
        ));
    }
}
