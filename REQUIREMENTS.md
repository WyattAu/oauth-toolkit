# Requirements — oauth-toolkit

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement.

Scope note: `oauth-toolkit` provides the shared OAuth2/OIDC primitives —
PKCE, CSRF state, HMAC/crypto helpers, HS256 JWT, token exchange/refresh,
OIDC discovery/validation, redirect-URI policy, scope handling, social
provider presets, and the local loopback listener.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-OT-001 | `pkce::generate_pkce_pair` produces a verifier/challenge pair; S256 challenge is the SHA-256 of the verifier; `verify_pkce` accepts the matching verifier and rejects others | MUST |
| REQ-OT-002 | `csrf::MemoryCsrfStore` stores a nonce under a key, returns it once per lookup window, enforces a TTL, and reports missing/expired keys as absent | MUST |
| REQ-OT-003 | `crypto` exposes SHA-256 hex digests, HMAC-SHA256 sign/verify over strings, opaque token generation with prefix, and random state nonces of configurable byte length | MUST |
| REQ-OT-004 | `jwt::encode_hs256`/`decode_hs256` round-trip any `Serialize`/`Deserialize` claims value under a shared secret | MUST |
| REQ-OT-005 | `jwt::extract_bearer_token` parses `"Bearer <token>"` and `build_auth_cookie` emits a cookie string with name, value, and `Max-Age` | MUST |
| REQ-OT-006 | `token` module exchanges an authorization code (with PKCE form fields) for a `TokenResponse` and refreshes access tokens, sending the documented form encoding | MUST |
| REQ-OT-007 | `redirect::redirect_uri_allowed` admits exactly the registered URIs and `build_redirect_uri` joins base URL + provider consistently (no duplicate slashes) | MUST |
| REQ-OT-008 | `scope::parse_scopes` splits/dedups whitespace- and comma-separated scope strings; `validate_scopes` rejects unregistered scopes; `scopes_subset` is a strict subset test | MUST |
| REQ-OT-009 | `social::build_authorize_url` constructs provider authorize URLs with client ID, redirect URI, scopes, and state for each supported provider preset | SHOULD |
| REQ-OT-010 | `social::sanitize_username` maps arbitrary provider display names to a short, single-token, safe username | SHOULD |
| REQ-OT-011 | `loopback::LoopbackFlow` binds an ephemeral local port, builds the redirect URI, captures the authorization response, and shuts down after a single use or timeout | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-OT-100 | A JWT signed with a different secret is rejected by `decode_hs256` — never accepted | MUST |
| REQ-OT-101 | HMAC verification fails on wrong key, wrong message, or non-hex signature input | MUST |
| REQ-OT-102 | PKCE verification fails on a wrong verifier, and an unknown method string is rejected rather than coerced | MUST |
| REQ-OT-103 | The loopback capture rejects a redirect whose `state` does not match the issued nonce, and a state value is single-use | MUST |
| REQ-OT-104 | Redirect-URI checking is exact-match: a URI that merely extends a registered URI is refused | MUST |
| REQ-OT-105 | Scope validation rejects any requested scope not present in the allow-list | MUST |
| REQ-OT-106 | Provider/userinfo network failures surface as typed errors; no panic path exists on hostile responses | MUST |
| REQ-OT-107 | Outbound provider HTTP uses TLS (rustls) with default certificate verification — invalid-certificate bypass is not exposed | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-OT-200 | Malformed percent-encoded redirect queries decode without panicking | MUST |
| REQ-OT-201 | Scope parsing normalizes repeated separators and deduplicates values | SHOULD |
| REQ-OT-202 | `TokenResponse` deserializes both minimal (missing optional fields) and full provider payloads | SHOULD |
| REQ-OT-203 | Loopback capture surfaces a provider `error` response as a typed error instead of hanging until timeout | SHOULD |

## Constant-Time Audit

- AUDIT: MAC verification is delegated to the `hmac`/`sha2` crates
  (`HmacSha256::verify_slice`), which perform constant-time tag
  comparison. ✓ No `==` on secret material, MACs, or digests exists in
  this crate's code.
- AUDIT: `hmac_sha256_verify` rejects non-hex input before any
  comparison work (fail-fast, no oracle from comparison timing).
- FLAG (accepted, invariant): `crypto.rs` contains one `expect` on
  `HmacSha256::new_from_slice` — HMAC accepts any key length by RFC
  2104 definition, so the error arm is unreachable; the expectation is
  documented at the call site.
- AUDIT: opaque tokens/state nonces use the OS CSPRNG via `rand`;
  no deterministic fallback path exists.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-OT-001 | `pkce_roundtrip_s256`, `verify_pkce_s256_correct`, `verify_pkce_s256_wrong_verifier`, `verify_pkce_plain_correct`, `pkce_verifier_length_range` (`src/pkce.rs`); proptests of the same names (`tests/proptest.rs`) | unit/property |
| REQ-OT-002 | `memory_store_roundtrip`, `memory_store_missing_key`, `memory_store_cleanup`, `csrf_store_type_delegates` (`src/csrf.rs`) | unit |
| REQ-OT-003 | `sha256_hex_deterministic`, `sha256_hex_different_inputs`, `hmac_roundtrip`, `generate_opaque_token_prefix`, `generate_state_nonce_length` (`src/crypto.rs`) | unit |
| REQ-OT-004 | `encode_decode_roundtrip` (`src/jwt.rs`) | unit |
| REQ-OT-005 | `extract_bearer_token_valid`, `extract_bearer_token_missing`, `build_auth_cookie_format` (`src/jwt.rs`) | unit |
| REQ-OT-006 | `exchange_code_sends_pkce_form`, `refresh_access_token_sends_correct_form`, `refresh_access_token_url_construction`, `refresh_access_token_handles_rotation` (`src/token.rs`) | unit |
| REQ-OT-007 | `redirect_uri_allowed_exact`, `redirect_uri_allowed_mismatch`, `redirect_uri_allowed_empty`, `build_redirect_uri_works`, `build_redirect_uri_trailing_slash` (`src/redirect.rs`) | unit |
| REQ-OT-008 | `parse_scopes_whitespace`, `parse_scopes_comma`, `parse_scopes_dedup`, `validate_scopes_ok`, `validate_scopes_unknown`, `scopes_subset_true`, `scopes_subset_false` (`src/scope.rs`) | unit |
| REQ-OT-009 | `build_authorize_url_google`, `build_authorize_url_github`, `authorization_url_contains_required_params`, `authorization_scopes_order_preserved` (`src/social.rs`) | unit |
| REQ-OT-010 | `sanitize_username_normal`, `sanitize_username_special_chars`, `sanitize_username_long`, `sanitize_username_too_short` (`src/social.rs`) | unit |
| REQ-OT-011 | `binds_ephemeral_loopback_port`, `loopback_redirect_uri_shape`, `capture_accepts_valid_redirect`, `capture_times_out_when_no_redirect`, `state_is_single_use_and_listener_shuts_down` (`src/loopback.rs`) | unit/integration |
| REQ-OT-100 | `decode_wrong_secret_fails` (`src/jwt.rs`) | unit |
| REQ-OT-101 | `hmac_wrong_key_fails`, `hmac_wrong_message_fails`, `hmac_invalid_hex_fails` (`src/crypto.rs`) | unit |
| REQ-OT-102 | `pkce_wrong_verifier_fails`, `pkce_unknown_method_rejects`, `verify_pkce_unknown_method` (`src/pkce.rs`; proptest in `tests/proptest.rs`) | unit/property |
| REQ-OT-103 | `capture_rejects_state_mismatch`, `state_is_single_use_and_listener_shuts_down`, `memory_store_missing_key` (`src/loopback.rs`, `src/csrf.rs`) | unit/integration |
| REQ-OT-104 | `redirect_uri_allowed_mismatch`, `redirect_uri_allowed_empty` (`src/redirect.rs`) | unit |
| REQ-OT-105 | `validate_scopes_unknown`, `scopes_subset_false` (`src/scope.rs`) | unit |
| REQ-OT-106 | `refresh_access_token_network_error`, `refresh_access_token_rejects_invalid_token`, `capture_surfaces_provider_error` (`src/token.rs`, `src/loopback.rs`) | unit |
| REQ-OT-107 | `Cargo.toml` pins `reqwest` with `rustls-tls` and `default-features = false` (no `native-tls` bypass surface); design review of outbound client construction | design |
| REQ-OT-200 | `percent_decoded_query_values` (`src/loopback.rs`) | unit |
| REQ-OT-201 | `parse_scopes_whitespace`, `parse_scopes_comma`, `parse_scopes_dedup` (`src/scope.rs`) | unit |
| REQ-OT-202 | `token_response_deserialize_full`, `token_response_deserialize_minimal` (`src/token.rs`) | unit |
| REQ-OT-203 | `capture_surfaces_provider_error`, `capture_rejects_missing_code` (`src/loopback.rs`) | unit |

## Test Count

- Unit tests: 69 (`cargo test`); integration proptests: 5 (`tests/proptest.rs`).
- All-features suite passes with 0 failures; no-default-features suite passes.
