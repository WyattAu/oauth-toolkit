#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared OAuth2/OIDC primitives — crypto, PKCE, scopes, CSRF, social login, OIDC, JWKS validation.
//!
//! Provides reusable building blocks for OAuth2 authorization code flows,
//! OIDC SSO, and social login (GitHub, Google).

pub mod crypto;
pub mod pkce;
pub mod scope;
pub mod redirect;
pub mod csrf;
pub mod social;
pub mod oidc;
pub mod oidc_validator;
pub mod jwt;
