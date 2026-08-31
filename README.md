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
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under MIT OR Apache-2.0.
