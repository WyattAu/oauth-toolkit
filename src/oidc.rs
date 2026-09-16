//! OIDC discovery, token exchange, and user info.

use serde::{Deserialize, Serialize};

/// OIDC provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g., <https://accounts.google.com>).
    pub issuer: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: String,
    /// Redirect URI after authorization.
    pub redirect_uri: String,
    /// Scopes to request.
    pub scope: Vec<String>,
}

/// OIDC discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// Issuer URL.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// Userinfo endpoint URL.
    pub userinfo_endpoint: String,
    /// JWKS URI for key discovery.
    pub jwks_uri: String,
}

/// OIDC token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    /// Access token.
    pub access_token: String,
    /// Token type (usually "Bearer").
    pub token_type: String,
    /// Expires in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Refresh token (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID token (optional, for OIDC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// OIDC user info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// Subject (user ID).
    pub sub: String,
    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Profile picture URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// Errors for OIDC operations.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// OIDC discovery document fetch failed.
    #[error("discovery failed: {0}")]
    DiscoveryFailed(String),

    /// Token exchange with the provider failed.
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// User info fetch failed.
    #[error("userinfo fetch failed: {0}")]
    UserInfoFailed(String),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    HttpError(String),
}

/// Fetch and parse the OIDC discovery document from an issuer URL.
pub async fn fetch_discovery(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<OidcDiscovery, OidcError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

    let discovery: OidcDiscovery = resp
        .json()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

    Ok(discovery)
}

/// Exchange an authorization code for tokens.
///
/// If `code_verifier` is `Some`, includes it for PKCE.
pub async fn exchange_code(
    client: &reqwest::Client,
    token_endpoint: &str,
    config: &OidcConfig,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<OidcTokenResponse, OidcError> {
    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", config.redirect_uri.clone()),
        ("client_id", config.client_id.clone()),
        ("client_secret", config.client_secret.clone()),
    ];

    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier.to_string()));
    }

    let resp = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| OidcError::HttpError(e.to_string()))?;

    let token_resp: OidcTokenResponse = resp
        .json()
        .await
        .map_err(|e| OidcError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_resp)
}

/// Fetch user info from the userinfo endpoint.
pub async fn fetch_user_info(
    client: &reqwest::Client,
    userinfo_endpoint: &str,
    access_token: &str,
) -> Result<OidcUserInfo, OidcError> {
    let resp = client
        .get(userinfo_endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OidcError::HttpError(e.to_string()))?;

    let user_info: OidcUserInfo = resp
        .json()
        .await
        .map_err(|e| OidcError::UserInfoFailed(e.to_string()))?;

    Ok(user_info)
}

/// Refresh an access token using a refresh token.
pub async fn refresh_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<OidcTokenResponse, OidcError> {
    let resp = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .map_err(|e| OidcError::HttpError(e.to_string()))?;

    let token_resp: OidcTokenResponse = resp
        .json()
        .await
        .map_err(|e| OidcError::TokenExchangeFailed(e.to_string()))?;

    Ok(token_resp)
}

/// Build an OIDC end-session URL for front-channel logout.
pub fn end_session_url(issuer: &str, client_id: &str, post_logout_redirect: &str) -> String {
    format!(
        "{}/logout?client_id={}&post_logout_redirect_uri={}",
        issuer.trim_end_matches('/'),
        urlencoding::encode(client_id),
        urlencoding::encode(post_logout_redirect),
    )
}
