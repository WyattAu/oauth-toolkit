#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Turnkey OAuth2/OIDC primitives for Rust.
//!
//! Two capabilities lead the crate:
//!
//! - **RFC 8252 desktop loopback flow** ([`loopback`]) — binds an ephemeral
//!   `127.0.0.1` port, builds the authorization URL with PKCE (S256) and a
//!   single-use `state`, captures exactly one redirect, then shuts down.
//!   The [`oauth2`](https://crates.io/crates/oauth2) crate ships protocol
//!   primitives but no turnkey loopback listener; this is one call:
//!   [`loopback::LoopbackFlow::start`] → open URL →
//!   [`loopback::LoopbackFlow::wait_for_code`].
//! - **Mail-provider presets** ([`providers`]) — Gmail, Outlook, Yahoo,
//!   AOL, and Fastmail endpoints plus the IMAP/SMTP XOAUTH2 scope sets for
//!   desktop mail clients.
//!
//! Around those: PKCE generation *and* server-side verification
//! ([`pkce`]), token exchange/refresh ([`token`]), OIDC discovery and
//! JWKS-backed validation ([`oidc`], [`oidc_validator`]), social login
//! (GitHub/Google, [`social`]), CSRF state ([`csrf`]), scope handling
//! ([`scope`]), and HMAC/opaque-token crypto ([`crypto`]).
//!
//! Scope note: [`oauth2`](https://crates.io/crates/oauth2) covers the full
//! grant surface (client credentials, device code, extensions) and
//! [`openidconnect`](https://crates.io/crates/openidconnect) validates ID
//! tokens more deeply (nonce, `at_hash`, ES256, per-`kid` keys) — this
//! crate trades that breadth for turnkey flows.

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
