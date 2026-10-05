# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [0.3.0] - 2026-10-05

### Changed (breaking)

- **PKCE `plain` is refused by default.** `draft-ietf-oauth-v2-1-16` §7.5.2
  forbids the method outright: its only historical justification was clients
  incapable of SHA-256, and OAuth 2.1 requires TLS 1.2+, which mandates
  SHA-256 — *"any device capable of implementing OAuth 2.1 necessarily supports
  SHA-256."* `PkcePolicy::default()` is `S256`-only. RFC 7636 still permits
  `plain`, and FAPI 2.0 forbade it earlier still, so the sources disagree; the
  newest and strictest governs the default.
  `PkcePolicy::allow_plain()` restores the old behaviour as an explicit,
  greppable decision for a deployment that genuinely faces such a client.
- **`verify_pkce(&str, &str, &str) -> bool` is replaced by
  `verify(&str, &str, PkceMethod, &PkcePolicy) -> Result<(), PkceError>`.** The
  old signature took the method as a `&str` and returned a bare `bool`, so
  `"s256"`, `"S-256"` and `"S256 "` were quietly *false* — indistinguishable
  from a wrong verifier. Those are different failures and want different
  responses: a typo is a client bug to report as `invalid_request`, a mismatch
  is a possible attack to refuse as `invalid_grant` revealing nothing. The
  method is now a type, parsed once by `PkceMethod::parse`.

### Added

- `PkceError` distinguishing `UnknownMethod`, `MethodNotPermitted`,
  `MalformedVerifier` and `Mismatch`.
- `validate_verifier`, enforcing RFC 7636 §4.1: 43-128 characters from the
  unreserved set `[A-Za-z0-9-._~]`. Checked before any hashing, so a verifier
  that cannot have come from a conforming client is not worth hashing.
- The RFC 7636 Appendix B vector verbatim (`dBjftJeZ4CVP…` →
  `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`). Published test data, not a
  value this crate produced — the kind of vector that cannot drift.

### Changed (tests)

- `pkce_plain_method_roundtrip` asserted `plain` must match identical strings,
  i.e. it encoded the method OAuth 2.1 forbids as the contract. Replaced with a
  property asserting the default policy refuses `plain` even when the strings
  agree, and that `allow_plain` restores it.

## [0.2.2] - 2026-09-12

### Added

- `tests/config_matrix.rs` (10 tests): behavior-observable coverage for the
  public config knobs — `MemoryCsrfStore::with_ttl` (expiry gates replay;
  cleanup consumes), `SocialProviderConfig` fields (authorize URL changes),
  `OidcConfig` credentials + PKCE verifier (token-exchange POST body over a
  loopback server), and `OidcValidatorConfig` issuer/audience/jwks_uri
  (accept vs reject on the same signed token; JWKS fetch routed to the
  configured URI).

### Changed

- Dogfood: `MemoryCsrfStore` now delegates expiry handling to
  `shared-state`'s `TtlCache` (`take_fresh` single-use consume) instead of
  hand-rolling a TTL map over `dashmap`; a stale state can never be
  replayed, and the `dashmap` dependency is gone.

## [0.2.1] - 2026-09-09

### Docs
- README and crate docs now lead with the differentiators (RFC 8252
  loopback flow, mail-provider presets, PKCE) and add a feature matrix vs
  `oauth2` (protocol primitives — no turnkey loopback listener) and
  `openidconnect` (deeper ID-token validation), with honest notes on where
  oauth-toolkit lags.

## [0.2.0] - 2026-09-01

### Added
- OAuth2/OIDC primitives — PKCE, crypto, scopes, CSRF, loopback flow, mail presets.
- Published to crates.io (2026-09-01).
