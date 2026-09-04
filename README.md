# oauth-toolkit

> Shared OAuth2/OIDC primitives — crypto, PKCE, scopes, CSRF, social login, OIDC, JWKS validation.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/WyattAu/oauth-toolkit/ci.yaml?branch=main)](https://github.com/WyattAu/oauth-toolkit/actions)

## Modules

| Module | Purpose |
|--------|---------|
| `crypto` | SHA-256 hex, HMAC-SHA256, opaque token generation |
| `pkce` | RFC 7636 S256 verification |
| `scope` | Parse/validate OAuth scopes |
| `redirect` | URI exact-match validation |
| `csrf` | CsrfStore trait (memory + Redis backends) |
| `social` | GitHub + Google OAuth2 flows |
| `providers` | Canonical endpoint constants + mail presets (Gmail, Outlook, Yahoo, AOL, Fastmail) with IMAP/SMTP XOAUTH2 scopes |
| `loopback` | Desktop loopback redirect capture (RFC 8252): ephemeral `127.0.0.1` bind, PKCE + single-use state, one redirect then shutdown |
| `token` | Authorization-code exchange (PKCE) and refresh via the token endpoint |
| `oidc` | Discovery, token exchange, user info, refresh |
| `oidc_validator` | JWKS-backed token validation |
| `jwt` | HS256 encode/decode helpers |

## Quick Start

```rust
use oauth_toolkit::{crypto, pkce, social};

// Hash a token for storage
let hash = crypto::sha256_hex("my-bearer-token");

// Generate PKCE pair
let (verifier, challenge) = pkce::generate_pkce_pair();

// Build GitHub authorization URL
let config = social::SocialProviderConfig {
    client_id: "my-client-id".into(),
    client_secret: "my-secret".into(),
    redirect_uri: "https://app.com/callback".into(),
};
let url = social::build_authorize_url(social::SocialProvider::GitHub, &config, "csrf-state");

// Desktop loopback OAuth2 with a mail provider preset
let provider = providers::MailProvider::gmail("my-client-id");
let flow = loopback::LoopbackFlow::start_for_provider(&provider, None, std::time::Duration::from_secs(300))?;
println!("Open in browser: {}", flow.authorization_url());
let captured = flow.wait_for_code()?; // single-use state, shuts down after one redirect
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under MIT OR Apache-2.0.
