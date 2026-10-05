//! RFC 7636 PKCE (Proof Key for Code Exchange), as narrowed by OAuth 2.1.
//!
//! # Why `plain` is refused by default
//!
//! RFC 7636 §4.2 defines two challenge methods, `plain` and `S256`. OAuth 2.1
//! (`draft-ietf-oauth-v2-1-16` §7.5.2) then **forbids `plain` outright**, on the
//! grounds that its only historical justification was clients incapable of
//! SHA-256 — and that OAuth 2.1 requires TLS 1.2+, which mandates SHA-256, so
//! *"any device capable of implementing OAuth 2.1 necessarily supports SHA-256."*
//!
//! [`PkcePolicy::default`] therefore refuses `plain`. A deployment that really
//! does face a client without SHA-256 can say so with
//! [`PkcePolicy::allow_plain`], which exists as an explicit, greppable decision
//! rather than as an accident of a `&str` comparison.
//!
//! # Why the method is a type, not a string
//!
//! This module used to take `method: &str` and return `bool`. A client that sent
//! `"s256"`, `"S-256"` or `"S256 "` got a quiet `false` — indistinguishable from
//! a wrong verifier. Those are different failures: a typo is a client bug to be
//! reported, a mismatch is a possible attack to be refused silently. [`PkceMethod`]
//! parses once and fails loudly; [`verify`] returns a [`PkceOutcome`] that says
//! which it was.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::Digest;

/// Minimum length of a `code_verifier`, from RFC 7636 §4.1.
pub const MIN_VERIFIER_LEN: usize = 43;
/// Maximum length of a `code_verifier`, from RFC 7636 §4.1.
pub const MAX_VERIFIER_LEN: usize = 128;

/// PKCE code challenge method.
///
/// Deliberately not `#[non_exhaustive]`: a new method from a future spec is a
/// semver event we want to make deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// `S256` — `base64url(SHA256(code_verifier))`. The only method OAuth 2.1
    /// permits.
    S256,
    /// `plain` — the verifier is sent as the challenge. Forbidden by OAuth 2.1
    /// §7.5.2; see the module docs.
    Plain,
}

impl PkceMethod {
    /// The method's `code_challenge_method` wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S256 => "S256",
            Self::Plain => "plain",
        }
    }

    /// Parse a `code_challenge_method` value.
    ///
    /// The comparison is exact: RFC 7636 registers `plain` and `S256`, and
    /// these values are compared byte-for-byte, so a near-miss is an error
    /// rather than a mismatch.
    pub fn parse(value: &str) -> Result<Self, PkceError> {
        match value {
            "S256" => Ok(Self::S256),
            "plain" => Ok(Self::Plain),
            other => Err(PkceError::UnknownMethod(other.to_string())),
        }
    }
}

/// Why a PKCE verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkceError {
    /// The `code_challenge_method` is not one this server knows. A client bug:
    /// report it back as `invalid_request`.
    UnknownMethod(String),
    /// The method is known but refused by policy. A server decision, not a
    /// client error.
    MethodNotPermitted {
        /// The method the client asked for.
        method: PkceMethod,
    },
    /// The verifier does not satisfy RFC 7636 §4.1's syntax.
    MalformedVerifier(String),
    /// The verifier and challenge do not correspond.
    Mismatch,
}

impl std::fmt::Display for PkceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownMethod(m) => {
                write!(
                    f,
                    "unknown code_challenge_method {m:?}; RFC 7636 defines plain and S256"
                )
            }
            Self::MethodNotPermitted { method } => write!(
                f,
                "code_challenge_method {:?} is refused; OAuth 2.1 section 7.5.2 forbids it",
                method.as_str()
            ),
            Self::MalformedVerifier(why) => {
                write!(f, "code_verifier rejected: {why}")
            }
            Self::Mismatch => write!(f, "code_verifier does not match the stored challenge"),
        }
    }
}

impl std::error::Error for PkceError {}

/// Which challenge methods this server accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkcePolicy {
    /// Whether RFC 7636's `plain` is accepted.
    pub plain: bool,
}

impl Default for PkcePolicy {
    /// `S256` only, per OAuth 2.1 `draft-ietf-oauth-v2-1-16` §7.5.2.
    fn default() -> Self {
        Self { plain: false }
    }
}

impl PkcePolicy {
    /// A policy that also accepts `plain`.
    ///
    /// Only for a deployment with a client demonstrably unable to do SHA-256.
    /// The name is the point: the decision is visible in a code review.
    pub fn allow_plain() -> Self {
        Self { plain: true }
    }

    /// Whether this policy permits `method`.
    pub fn permits(&self, method: PkceMethod) -> bool {
        match method {
            PkceMethod::S256 => true,
            PkceMethod::Plain => self.plain,
        }
    }
}

/// Generate a PKCE code verifier and its S256 challenge.
///
/// Returns `(verifier, challenge)` where:
/// - `verifier` is 43 characters of URL-safe base64, from 32 bytes of CSPRNG
///   output (RFC 7636 §4.1 allows 43-128)
/// - `challenge` is `base64url(SHA256(verifier))`
pub fn generate_pkce_pair() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut verifier_bytes[..]);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let challenge = sha256_base64url(&verifier);
    (verifier, challenge)
}

/// Validate a `code_verifier` against RFC 7636 §4.1's syntax.
///
/// `43 <= len <= 128`, and every character in the unreserved set
/// `[A-Za-z0-9-._~]`. Enforced on the way in: a verifier that cannot have been
/// produced by a conforming client is not worth hashing.
pub fn validate_verifier(code_verifier: &str) -> Result<(), PkceError> {
    let len = code_verifier.chars().count();
    if !(MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&len) {
        return Err(PkceError::MalformedVerifier(format!(
            "{len} characters, RFC 7636 section 4.1 requires {MIN_VERIFIER_LEN}-{MAX_VERIFIER_LEN}"
        )));
    }
    if let Some(bad) = code_verifier
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')))
    {
        return Err(PkceError::MalformedVerifier(format!(
            "{bad:?} is not in the unreserved set [A-Za-z0-9-._~]"
        )));
    }
    Ok(())
}

/// Verify a PKCE code challenge against the verifier, under `policy`.
///
/// The error distinguishes a client bug (unknown method, malformed verifier)
/// from a possible attack (mismatch), because the two deserve different
/// responses: the first is a `400 invalid_request` the client should see, the
/// second is a `400 invalid_grant` that reveals nothing.
pub fn verify(
    code_verifier: &str,
    stored_challenge: &str,
    method: PkceMethod,
    policy: &PkcePolicy,
) -> Result<(), PkceError> {
    if !policy.permits(method) {
        return Err(PkceError::MethodNotPermitted { method });
    }
    validate_verifier(code_verifier)?;
    match method {
        PkceMethod::S256 => {
            let computed = sha256_base64url(code_verifier);
            if constant_time_eq(computed.as_bytes(), stored_challenge.as_bytes()) {
                Ok(())
            } else {
                Err(PkceError::Mismatch)
            }
        }
        PkceMethod::Plain => {
            if constant_time_eq(code_verifier.as_bytes(), stored_challenge.as_bytes()) {
                Ok(())
            } else {
                Err(PkceError::Mismatch)
            }
        }
    }
}

/// Verify using the default policy (`S256` only).
pub fn verify_with_default_policy(
    code_verifier: &str,
    stored_challenge: &str,
    method: PkceMethod,
) -> Result<(), PkceError> {
    verify(
        code_verifier,
        stored_challenge,
        method,
        &PkcePolicy::default(),
    )
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
// Test code: unwrap/expect are the idiomatic way to assert setup success.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B, verbatim. Published test data, not a value this
    /// crate produced — the one kind of vector that cannot drift.
    const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc7636_appendix_b_vector() {
        assert!(
            verify_with_default_policy(RFC7636_VERIFIER, RFC7636_CHALLENGE, PkceMethod::S256)
                .is_ok()
        );
    }

    #[test]
    fn generate_pkce_pair_deterministic_challenge() {
        let (v, c) = generate_pkce_pair();
        let expected = sha256_base64url(&v);
        assert_eq!(c, expected);
        // A generated verifier must satisfy the syntax we now enforce.
        validate_verifier(&v).expect("generated verifier is well formed");
        assert_eq!(v.chars().count(), MIN_VERIFIER_LEN);
    }

    #[test]
    fn s256_correct() {
        let (verifier, challenge) = generate_pkce_pair();
        assert!(verify_with_default_policy(&verifier, &challenge, PkceMethod::S256).is_ok());
    }

    #[test]
    fn s256_wrong_verifier_is_a_mismatch_not_a_client_bug() {
        let (verifier, challenge) = generate_pkce_pair();
        let other = format!("{verifier}X");
        assert_eq!(
            verify_with_default_policy(&other, &challenge, PkceMethod::S256),
            Err(PkceError::Mismatch)
        );
    }

    /// OAuth 2.1 `-16` §7.5.2. The default policy refuses `plain` even when
    /// the verifier and challenge are identical — the old `verify_pkce("test",
    /// "test", "plain")` shape, which returned `true`.
    #[test]
    fn plain_is_refused_by_default_even_when_it_would_match() {
        assert_eq!(
            verify_with_default_policy(RFC7636_VERIFIER, RFC7636_VERIFIER, PkceMethod::Plain),
            Err(PkceError::MethodNotPermitted {
                method: PkceMethod::Plain
            })
        );
    }

    #[test]
    fn plain_is_available_only_through_an_explicit_policy() {
        let policy = PkcePolicy::allow_plain();
        assert!(
            verify(
                RFC7636_VERIFIER,
                RFC7636_VERIFIER,
                PkceMethod::Plain,
                &policy
            )
            .is_ok(),
            "a deployment that knowingly accepts plain can still do so"
        );
    }

    /// The finding that motivated this module: a near-miss method used to be a
    /// silent `false`, indistinguishable from a wrong verifier.
    #[test]
    fn a_misspelled_method_is_an_error_not_a_mismatch() {
        for typo in ["s256", "S-256", "S256 ", "sha256", ""] {
            assert_eq!(
                PkceMethod::parse(typo),
                Err(PkceError::UnknownMethod(typo.to_string())),
                "{typo:?} must not parse as a method"
            );
        }
        assert_eq!(PkceMethod::parse("S256"), Ok(PkceMethod::S256));
        assert_eq!(PkceMethod::parse("plain"), Ok(PkceMethod::Plain));
    }

    #[test]
    fn verifier_syntax_is_enforced_per_rfc7636_4_1() {
        assert!(validate_verifier(RFC7636_VERIFIER).is_ok());
        assert!(matches!(
            validate_verifier("too-short"),
            Err(PkceError::MalformedVerifier(_))
        ));
        assert!(matches!(
            validate_verifier(&"a".repeat(MAX_VERIFIER_LEN + 1)),
            Err(PkceError::MalformedVerifier(_))
        ));
        assert!(matches!(
            validate_verifier(&"a".repeat(MAX_VERIFIER_LEN)),
            Ok(())
        ));
        // `+` and `/` are base64 but not unreserved.
        assert!(matches!(
            validate_verifier(&"a".repeat(42).replace('a', "+")),
            Err(PkceError::MalformedVerifier(_))
        ));
        // A malformed verifier is reported before any hashing happens.
        assert!(matches!(
            verify_with_default_policy("short", RFC7636_CHALLENGE, PkceMethod::S256),
            Err(PkceError::MalformedVerifier(_))
        ));
    }
}
