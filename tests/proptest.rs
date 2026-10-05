use oauth_toolkit::pkce::{
    PkceError, PkceMethod, PkcePolicy, generate_pkce_pair, validate_verifier, verify,
    verify_with_default_policy,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn pkce_roundtrip_s256(_dummy in 0..1u32) {
        let (verifier, challenge) = generate_pkce_pair();
        prop_assert!(!verifier.is_empty(), "verifier must not be empty");
        prop_assert!(!challenge.is_empty(), "challenge must not be empty");
        prop_assert!(verify_with_default_policy(&verifier, &challenge, PkceMethod::S256).is_ok(),
            "S256 verification must succeed for a generated pair");
    }

    #[test]
    fn pkce_verifier_length_range(_dummy in 0..1u32) {
        let (verifier, _) = generate_pkce_pair();
        // Base64url-encoded 32 bytes = 43 characters
        prop_assert!(verifier.len() >= 40 && verifier.len() <= 50,
            "verifier length {} should be ~43", verifier.len());
    }

    #[test]
    fn pkce_wrong_verifier_is_a_mismatch(
        // Exactly the length generate_pkce_pair produces, and only characters
        // RFC 7636 section 4.1 allows, so the failure is the comparison and not
        // the syntax check.
        wrong in "[a-zA-Z0-9._~-]{43}",
    ) {
        let (_, challenge) = generate_pkce_pair();
        prop_assume!(validate_verifier(&wrong).is_ok());
        prop_assume!(wrong != *challenge);
        prop_assert_eq!(
            verify_with_default_policy(&wrong, &challenge, PkceMethod::S256),
            Err(PkceError::Mismatch)
        );
    }

    /// The property this suite used to assert, in the opposite direction: `plain`
    /// matching identical strings. OAuth 2.1 -16 section 7.5.2 forbids the method,
    /// so the default policy must refuse it even when the strings agree — and a
    /// deployment that opts in via PkcePolicy::allow_plain gets the old behaviour.
    #[test]
    fn pkce_plain_is_refused_by_default_and_available_on_request(
        plaintext in "[a-zA-Z0-9_-]{43,128}"
    ) {
        prop_assume!(validate_verifier(&plaintext).is_ok());
        prop_assert_eq!(
            verify_with_default_policy(&plaintext, &plaintext, PkceMethod::Plain),
            Err(PkceError::MethodNotPermitted { method: PkceMethod::Plain })
        );
        let permissive = PkcePolicy::allow_plain();
        prop_assert!(verify(&plaintext, &plaintext, PkceMethod::Plain, &permissive).is_ok());
    }

    #[test]
    fn pkce_unknown_method_never_parses(verifier in "[a-zA-Z0-9_-]{43,50}", challenge in "[a-zA-Z0-9_-]{40,50}") {
        prop_assert!(PkceMethod::parse("unknown").is_err());
        prop_assert!(PkceMethod::parse("s256").is_err(), "a lowercased method is not S256");
        prop_assert!(verify_with_default_policy(&verifier, &challenge, PkceMethod::S256).is_err());
    }

    /// RFC 7636 section 4.1's syntax, as a property rather than three examples.
    #[test]
    fn verifier_syntax_bounds_hold(verifier in ".{0,200}") {
        match validate_verifier(&verifier) {
            Ok(()) => prop_assert!((43..=128).contains(&verifier.chars().count())),
            Err(PkceError::MalformedVerifier(_)) => prop_assert!(true),
            Err(other) => prop_assert!(false, "unexpected error: {other}"),
        }
    }
}
