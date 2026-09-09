# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

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
