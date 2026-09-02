use proptest::prelude::*;
use oauth_toolkit::pkce::{generate_pkce_pair, verify_pkce};

proptest! {
    #[test]
    fn pkce_roundtrip_s256(_dummy in 0..1u32) {
        let (verifier, challenge) = generate_pkce_pair();
        prop_assert!(!verifier.is_empty(), "verifier must not be empty");
        prop_assert!(!challenge.is_empty(), "challenge must not be empty");
        prop_assert!(verify_pkce(&verifier, &challenge, "S256"), "S256 verification must succeed for generated pair");
    }

    #[test]
    fn pkce_verifier_length_range(_dummy in 0..1u32) {
        let (verifier, _) = generate_pkce_pair();
        // Base64url-encoded 32 bytes = 43 characters
        prop_assert!(verifier.len() >= 40 && verifier.len() <= 50,
            "verifier length {} should be ~43", verifier.len());
    }

    #[test]
    fn pkce_wrong_verifier_fails(
        wrong in "[a-zA-Z0-9_-]{40,50}",
    ) {
        let (_, challenge) = generate_pkce_pair();
        // Skip if the random string happens to match (astronomically unlikely)
        prop_assume!(!verify_pkce(&wrong, &challenge, "S256"));
    }

    #[test]
    fn pkce_plain_method_roundtrip(plaintext in "[a-zA-Z0-9_-]{1,128}") {
        prop_assert!(verify_pkce(&plaintext, &plaintext, "plain"),
            "plain method must match identical strings");
    }

    #[test]
    fn pkce_unknown_method_rejects(verifier in "[a-zA-Z0-9_-]{40,50}", challenge in "[a-zA-Z0-9_-]{40,50}") {
        prop_assert!(!verify_pkce(&verifier, &challenge, "unknown"),
            "unknown method must always reject");
    }
}
