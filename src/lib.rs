#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared OAuth2/OIDC primitives — crypto, PKCE, scopes, CSRF, social login, OIDC, JWKS validation.
//!
//! Provides reusable building blocks for OAuth2 authorization code flows,
//! OIDC SSO, social login (GitHub, Google), desktop loopback redirect
//! capture with PKCE, token exchange/refresh, and mail provider presets
//! (Gmail, Outlook, Yahoo, AOL, Fastmail).

pub mod crypto;
pub mod csrf;
pub mod jwt;
pub mod loopback;
pub mod oidc;
pub mod oidc_validator;
pub mod pkce;
pub mod providers;
pub mod redirect;
pub mod scope;
pub mod social;
pub mod token;
