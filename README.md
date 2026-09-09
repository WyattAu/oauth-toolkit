# oauth-toolkit

> Turnkey OAuth2/OIDC for Rust — **desktop loopback flows (RFC 8252)**, **mail-provider presets**, PKCE, crypto, scopes, CSRF, social login, JWKS validation.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/WyattAu/oauth-toolkit/ci.yaml?branch=main)](https://github.com/WyattAu/oauth-toolkit/actions)

## Why oauth-toolkit

- **RFC 8252 loopback flow, done for you.** `LoopbackFlow` binds
  `127.0.0.1:<ephemeral>`, builds the authorization URL with PKCE (S256) and
  a single-use `state`, captures **exactly one** redirect, then shuts down.
  The [`oauth2`] crate gives you the protocol primitives — but no turnkey
  loopback listener; you'd write the socket handling, state check, and
  shutdown logic yourself. Here it's one call: `start` → open URL →
  `wait_for_code`.
- **Mail-provider presets.** Gmail, Outlook, Yahoo, AOL, and Fastmail
  endpoints plus the correct IMAP/SMTP **XOAUTH2** scope sets, so desktop
  mail clients don't hand-maintain provider quirks (Outlook tenant support
  included).
- **PKCE both sides.** Generate client-side pairs *and* verify incoming
  `code_verifier`/`code_challenge` pairs server-side (RFC 7636).
- Plus the shared primitives: token exchange/refresh, OIDC discovery,
  JWKS-backed validation, CSRF store, social login (GitHub/Google),
  scope parsing, HMAC/opaque-token crypto.

## Feature matrix

oauth-toolkit is a **turnkey toolkit for common flows**. Compare scope, not
quality — [`oauth2`] is the protocol foundation and [`openidconnect`] is the
deep OIDC implementation:

|                                        | oauth-toolkit | oauth2            | openidconnect     |
|----------------------------------------|---------------|-------------------|-------------------|
| Scope                                  | turnkey flows + presets | OAuth2 protocol primitives | OIDC: discovery + ID-token validation |
| RFC 8252 loopback listener (bind → capture one redirect → shutdown) | **yes, one call** | no — build URLs only, bring your own listener | no |
| PKCE S256 (generate + server-side verify) | yes        | generate + exchange | via oauth2        |
| Mail presets with XOAUTH2 scopes (Gmail/Outlook/Yahoo/AOL/Fastmail) | **yes** | no | no |
| Social login helpers (GitHub, Google)  | yes           | no                | no                |
| OIDC discovery                         | yes           | no                | yes               |
| JWKS token validation                  | yes (RS256, 24 h cache) | no      | yes (RS256/ES256, nonce, `at_hash`, per-`kid` keys) |
| Token exchange + refresh               | yes           | yes (all grant types) | yes          |
| CSRF store abstraction                 | yes (trait: memory/Redis) | no    | no                |
| Grant-type coverage                    | authorization code (+ PKCE), refresh | client credentials, device code, extensions | via oauth2 |

### Where oauth-toolkit lags (honestly)

- **Not a protocol framework.** `oauth2` covers the full grant surface
  (client credentials, device authorization, extension grants) with total
  control over every request. oauth-toolkit implements the flows apps
  actually ship — authorization code with PKCE and refresh — and trades
  configurability for turnkey ergonomics.
- **ID-token validation is the shallower variant.** [`openidconnect`]
  validates `nonce`, `at_hash`, `azp`, per-`kid` key selection, and
  multiple algorithms. oauth-toolkit's validator is RS256 + issuer/audience
  with a cached JWKS — right for many apps; if you need certified
  relying-party rigor, use `openidconnect`.
- **Smaller ecosystem / track record.** `oauth2` and `openidconnect` are
  years-deep and widely audited. oauth-toolkit is young; treat the
  primitives as building blocks under your own review.

[`oauth2`]: https://crates.io/crates/oauth2
[`openidconnect`]: https://crates.io/crates/openidconnect

## Quick Start

### Desktop loopback flow with a mail preset (RFC 8252)

```rust
use oauth_toolkit::{loopback, providers, token};

// Gmail/Outlook/Yahoo/AOL/Fastmail presets carry endpoints + XOAUTH2 scopes.
let provider = providers::MailProvider::gmail("my-client-id");

// Binds 127.0.0.1:<ephemeral>, PKCE S256 + single-use state.
let flow = loopback::LoopbackFlow::start_for_provider(
    &provider, None, std::time::Duration::from_secs(300))?;
println!("Open in browser: {}", flow.authorization_url());

let captured = flow.wait_for_code()?; // one redirect, then shutdown
let tokens = token::exchange_code(
    &reqwest::Client::new(),
    &provider.token_url,
    &provider.client_id,
    None,
    &captured.code,
    &loopback::loopback_redirect_uri(captured.port),
    &captured.verifier,
).await?;
```

### Other modules

```rust
use oauth_toolkit::{crypto, pkce, social};

// Hash a token for storage
let hash = crypto::sha256_hex("my-bearer-token");

// Generate a PKCE pair (client side)…
let (verifier, challenge) = pkce::generate_pkce_pair();
// …or verify a verifier/challenge pair (server side, RFC 7636)
assert!(pkce::verify_pkce(&verifier, &challenge, "S256"));

// Build GitHub authorization URL
let config = social::SocialProviderConfig {
    client_id: "my-client-id".into(),
    client_secret: "my-secret".into(),
    redirect_uri: "https://app.com/callback".into(),
};
let url = social::build_authorize_url(social::SocialProvider::GitHub, &config, "csrf-state");
```

## Modules

| Module | Purpose |
|--------|---------|
| `loopback` | **Desktop loopback redirect capture (RFC 8252 §7.3): ephemeral `127.0.0.1` bind, PKCE + single-use state, one redirect then shutdown** |
| `providers` | **Mail presets (Gmail, Outlook, Yahoo, AOL, Fastmail) with IMAP/SMTP XOAUTH2 scopes + canonical endpoint constants** |
| `pkce` | RFC 7636 S256 pair generation and verification |
| `crypto` | SHA-256 hex, HMAC-SHA256, opaque token generation |
| `scope` | Parse/validate OAuth scopes |
| `redirect` | URI exact-match validation |
| `csrf` | CsrfStore trait (memory + Redis backends) |
| `social` | GitHub + Google OAuth2 flows |
| `token` | Authorization-code exchange (PKCE) and refresh via the token endpoint |
| `oidc` | Discovery, token exchange, user info, refresh |
| `oidc_validator` | JWKS-backed token validation |
| `jwt` | HS256 encode/decode helpers |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under MIT OR Apache-2.0.
