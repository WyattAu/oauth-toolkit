# Threat Model — oauth-toolkit

Status: **v1.0** · Method: STRIDE over the public API surface
(`pkce`, `csrf`, `crypto`, `jwt`, `token`, `oidc`, `oidc_validator`,
`redirect`, `scope`, `social`, `providers`, `loopback`).

Trust boundaries: (1) the OAuth2 redirect arriving at the loopback
listener / redirect endpoint (hostile — attacker-controlled query
string), (2) network responses from provider token/userinfo/discovery
endpoints, (3) the local process state (CSRF store, loopback listener
lifetime), (4) the `hmac`/`sha2`/`jsonwebtoken`/`reqwest` dependency
tree.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | Authorization-code binding | Attacker substitutes their own `code`/`state` into a victim's redirect |
| A2 | Client secrets & signing keys | Provider client secret or HS256 secret leaked via logs/`Debug` |
| A3 | CSRF `state` integrity | Replay or fixation of the anti-CSRF nonce |
| A4 | PKCE verifier/challenge binding | Downgrade to `plain`, or cross-request verifier reuse |
| A5 | Redirect-URI allow-list | Open-redirect via permissive prefix matching |
| A6 | Availability | Hostile input (oversized state, unknown method, bad hex) causes panic |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|---|--------|----------|---------|------------|----------------|
| T1 | CSRF `state` forged or replayed | Spoofing/Replay | `csrf::MemoryCsrfStore`, `loopback` | Nonces are random (`generate_state_nonce`), single-use, TTL-bounded; listener rejects mismatched state | `memory_store_roundtrip`, `memory_store_missing_key`, `memory_store_cleanup`, `capture_rejects_state_mismatch`, `state_is_single_use_and_listener_shuts_down`, `generate_state_nonce_length` |
| T2 | PKCE downgrade / verifier substitution | Tampering | `pkce` | `PkceMethod::S256` default; `plain` only when explicitly requested; verification compares SHA-256 of verifier against stored challenge | `pkce_roundtrip_s256`, `pkce_wrong_verifier_fails`, `pkce_unknown_method_rejects`, proptests `pkce_roundtrip_s256`/`pkce_wrong_verifier_fails`/`pkce_unknown_method_rejects` |
| T3 | Forged JWT accepted | Spoofing | `jwt::decode_hs256` | HMAC verification with configured secret only; algorithm is pinned to HS256 by construction (no header-driven algorithm choice) | `decode_wrong_secret_fails`, `encode_decode_roundtrip` |
| T4 | HMAC tag / signature tampering | Tampering | `crypto::hmac_sha256_verify` | Constant-time MAC comparison via `hmac` crate; non-hex input rejected before comparison | `hmac_wrong_key_fails`, `hmac_wrong_message_fails`, `hmac_invalid_hex_fails`, `hmac_roundtrip` |
| T5 | Open redirect via crafted redirect target | Elevation | `redirect::redirect_uri_allowed` | Exact-match against registered URIs; no prefix/substring matching | `redirect_uri_allowed_exact`, `redirect_uri_allowed_mismatch`, `redirect_uri_allowed_empty` |
| T6 | Scope escalation beyond consent | Elevation | `scope` | Requested scopes validated against allow-list and subset-checked before use | `validate_scopes_ok`, `validate_scopes_unknown`, `scopes_subset_true`, `scopes_subset_false` |
| T7 | Hostile redirect query crashes listener | DoS | `loopback` | All capture paths return `Result`/typed errors; provider errors surfaced not propagated; bounded timeout | `capture_rejects_missing_code`, `capture_surfaces_provider_error`, `capture_times_out_when_no_redirect`, `percent_decoded_query_values` |
| T8 | Malicious provider response poisons userinfo | Tampering | `token`, `oidc`, `social` | Deserialization is typed (`TokenResponse`, `SocialUserInfo`); network errors mapped to `SocialError`/`TokenError`; TLS enforced via `reqwest` `rustls-tls` (no `danger_accept_invalid_certs`) | `token_response_deserialize_full`, `token_response_deserialize_minimal`, `refresh_access_token_network_error` |
| T9 | Username injection from provider profile | Tampering | `social::sanitize_username` | Hostile display names are length-clamped and character-filtered to a safe local-part | `sanitize_username_normal`, `sanitize_username_special_chars`, `sanitize_username_long`, `sanitize_username_too_short` |
| T10 | Client secret exposure via diagnostics | Information Disclosure | config types | Secrets are passed as `&str` parameters, not stored in `Debug`-derived structs; no secret material is `Display`/`Debug`-formatted | Design review: `social::SocialProviderConfig`, `build_authorize_url` take secrets by reference; no `derive(Debug)` on secret-bearing payloads (`token` request forms are built, not printed) |
| T11 | Opaque token predictability | Spoofing | `crypto::generate_opaque_token` | Tokens drawn from the OS RNG (`rand::OsRng`-backed) with configurable byte length | `generate_opaque_token_prefix`, `generate_state_nonce_length` |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — `MemoryCsrfStore` is per-process.** Multi-instance
  deployments cannot share CSRF state; a request landing on a different
  instance fails state validation (fail-closed, but operational). Callers
  needing horizontal scale must supply their own store via
  `CsrfStoreType` delegation.
- **OPEN-2 — `jwt` module is HS256-only.** No RS256/JWKS-signing path in
  `jwt` itself; `oidc_validator` covers the JWKS-validation direction.
  Callers needing asymmetric signing must use a dedicated JWT crate.
- **OPEN-3 — token exchange responses are not audited for `scope`
  narrowing.** The provider may return a narrower scope set than
  requested; `TokenResponse.scope` is surfaced but not re-validated
  against the allow-list automatically.
- **OPEN-4 — `loopback` binds a local port per flow.** A local process
  could race to bind the fixed port first (denial of the flow, not
  interception); the bind is ephemeral by default
  (`binds_ephemeral_loopback_port`).

## Out of Scope

- Browser/OS security of the device running the loopback listener.
- Provider-side security (account takeover at the IdP, consent phishing).
- Transport beyond enforcing TLS on outbound HTTP (no certificate
  pinning per provider).
- Storage encryption of tokens after exchange (callers persisting
  `TokenSet` own at-rest protection).

## Residual Risks

- `plain` PKCE remains selectable for legacy providers; misuse is a
  caller decision (type-visible via `PkceMethod`).
- `sanitize_username` is a best-effort local-part filter, not a
  complete normalization (Unicode confusables are not mapped).
