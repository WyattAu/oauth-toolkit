# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

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
