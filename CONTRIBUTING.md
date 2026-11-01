# Contributing to oauth-toolkit

Part of the [WyattAu estate](https://github.com/WyattAu). This crate is
the estate's OIDC/JWT validation layer — changes here affect every
service that validates tokens.

## The short version

1. Branch from `main`, keep commits atomic.
2. `cargo fmt`, `cargo clippy --all-targets --all-features`, and
   `cargo test` must all pass — CI enforces them via the shared
   [engineering-standards](https://github.com/WyattAu/engineering-standards)
   gate matrix, plus `cargo deny` and `cargo vet`.
3. New dependencies need `cargo vet` coverage (audits or exemptions in
   `supply-chain/`) — CI tells you exactly what's missing.
4. Public-API changes must respect semver: `cargo semver-checks` runs in
   CI; breaking changes require a major version bump.
5. JWT/validation behavior changes need a test that fails without the
   change (the estate rule: prove it live, not on paper).

## Reporting issues

Open a GitHub issue with the token/issuer shape involved (redact
secrets — never paste real tokens, keys, or JWKS contents).

## License

By contributing you agree your contributions are licensed under the
repository's license (MIT OR Apache-2.0, at your option).
