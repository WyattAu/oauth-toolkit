//! Social login providers (GitHub, Google).
//!
//! Endpoint URLs come from [`crate::providers::endpoints`] — the single
//! source of truth shared with the mail provider presets.

use serde::{Deserialize, Serialize};

use crate::providers::endpoints;

/// Supported social login providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocialProvider {
    /// GitHub OAuth2.
    GitHub,
    /// Google OAuth2.
    Google,
}

impl SocialProvider {
    /// Authorization URL for the provider.
    pub fn authorize_url(&self) -> &'static str {
        match self {
            Self::GitHub => endpoints::GITHUB_AUTHORIZE_URL,
            Self::Google => endpoints::GOOGLE_AUTHORIZE_URL,
        }
    }

    /// Token exchange URL for the provider.
    pub fn token_url(&self) -> &'static str {
        match self {
            Self::GitHub => endpoints::GITHUB_TOKEN_URL,
            Self::Google => endpoints::GOOGLE_TOKEN_URL,
        }
    }

    /// Default scopes for the provider.
    pub fn default_scopes(&self) -> &'static [&'static str] {
        match self {
            Self::GitHub => &["read:user", "user:email"],
            Self::Google => &["openid", "email", "profile"],
        }
    }

    /// User info URL for the provider.
    pub fn user_info_url(&self) -> &'static str {
        match self {
            Self::GitHub => endpoints::GITHUB_USER_INFO_URL,
            Self::Google => endpoints::GOOGLE_USER_INFO_URL,
        }
    }
}

/// Configuration for a social login provider.
#[derive(Debug, Clone)]
pub struct SocialProviderConfig {
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: String,
    /// Redirect URI after authorization.
    pub redirect_uri: String,
}

/// User information returned by a social login provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserInfo {
    /// Provider name (e.g., "github", "google").
    pub provider: String,
    /// Provider-specific user ID.
    pub provider_user_id: String,
    /// User email address.
    pub email: String,
    /// User display name.
    pub name: String,
    /// User avatar URL (optional).
    pub avatar_url: Option<String>,
}

/// Errors for social login operations.
#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    /// Token exchange with the provider failed.
    #[error("token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// User info fetch from the provider failed.
    #[error("user info fetch failed: {0}")]
    UserInfoFailed(String),

    /// A required field is missing from the provider response.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    HttpError(String),
}

/// Build the authorization redirect URL with CSRF state.
pub fn build_authorize_url(
    provider: SocialProvider,
    config: &SocialProviderConfig,
    state: &str,
) -> String {
    let scopes = provider.default_scopes().join(" ");
    let redirect = urlencoding::encode(&config.redirect_uri);
    let state = urlencoding::encode(state);
    format!(
        "{}?client_id={}&redirect_uri={}&scope={}&state={}&response_type=code",
        provider.authorize_url(),
        config.client_id,
        redirect,
        scopes,
        state,
    )
}

/// Exchange an authorization code for an access token.
pub async fn exchange_code(
    client: &reqwest::Client,
    provider: SocialProvider,
    config: &SocialProviderConfig,
    code: &str,
) -> Result<String, SocialError> {
    match provider {
        SocialProvider::GitHub => {
            let resp = client
                .post(provider.token_url())
                .header("Accept", "application/json")
                .header("User-Agent", "oauth-toolkit")
                .form(&[
                    ("client_id", config.client_id.as_str()),
                    ("client_secret", config.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", config.redirect_uri.as_str()),
                ])
                .send()
                .await
                .map_err(|e| SocialError::HttpError(e.to_string()))?;

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| SocialError::TokenExchangeFailed(e.to_string()))?;

            body["access_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    SocialError::TokenExchangeFailed("no access_token in response".into())
                })
        }
        SocialProvider::Google => {
            let resp = client
                .post(provider.token_url())
                .form(&[
                    ("client_id", config.client_id.as_str()),
                    ("client_secret", config.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", config.redirect_uri.as_str()),
                    ("grant_type", "authorization_code"),
                ])
                .send()
                .await
                .map_err(|e| SocialError::HttpError(e.to_string()))?;

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| SocialError::TokenExchangeFailed(e.to_string()))?;

            body["access_token"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    SocialError::TokenExchangeFailed("no access_token in response".into())
                })
        }
    }
}

/// Fetch user profile info from the provider.
pub async fn fetch_user_info(
    client: &reqwest::Client,
    provider: SocialProvider,
    access_token: &str,
) -> Result<SocialUserInfo, SocialError> {
    let resp = client
        .get(provider.user_info_url())
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| SocialError::HttpError(e.to_string()))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| SocialError::UserInfoFailed(e.to_string()))?;

    match provider {
        SocialProvider::GitHub => {
            let user_id = body["id"]
                .as_str()
                .or_else(|| body["id"].as_i64().map(|_| ""))
                .ok_or(SocialError::MissingField("id".into()))?;
            let email = body["email"].as_str().unwrap_or("").to_string();
            let name = body["name"].as_str().unwrap_or("").to_string();
            let avatar = body["avatar_url"].as_str().map(String::from);

            Ok(SocialUserInfo {
                provider: "github".into(),
                provider_user_id: user_id.to_string(),
                email,
                name,
                avatar_url: avatar,
            })
        }
        SocialProvider::Google => {
            let user_id = body["id"]
                .as_str()
                .ok_or(SocialError::MissingField("id".into()))?;
            let email = body["email"]
                .as_str()
                .ok_or(SocialError::MissingField("email".into()))?;
            let name = body["name"].as_str().unwrap_or("").to_string();
            let avatar = body["picture"].as_str().map(String::from);

            Ok(SocialUserInfo {
                provider: "google".into(),
                provider_user_id: user_id.to_string(),
                email: email.to_string(),
                name,
                avatar_url: avatar,
            })
        }
    }
}

/// Sanitize a username from a provider: alphanumeric + underscore, 3-30 chars.
/// Falls back to `user_{random}` if too short after sanitization.
pub fn sanitize_username(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(30)
        .collect();

    if sanitized.len() >= 3 {
        sanitized
    } else {
        let nonce = crate::crypto::generate_opaque_token("", 4);
        format!("user_{}", nonce)
    }
}

#[cfg(test)]
// Test code: unwrap/expect are the idiomatic way to assert setup success.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn build_authorize_url_github() {
        let config = SocialProviderConfig {
            client_id: "id123".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app.com/callback".into(),
        };
        let url = build_authorize_url(SocialProvider::GitHub, &config, "state123");
        assert!(url.contains("client_id=id123"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("github.com/login/oauth/authorize"));
    }

    #[test]
    fn build_authorize_url_google() {
        let config = SocialProviderConfig {
            client_id: "id456".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app.com/callback".into(),
        };
        let url = build_authorize_url(SocialProvider::Google, &config, "state456");
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn sanitize_username_normal() {
        assert_eq!(sanitize_username("john_doe"), "john_doe");
    }

    #[test]
    fn sanitize_username_special_chars() {
        let result = sanitize_username("!@#");
        assert!(result.starts_with("user_"));
        assert!(result.len() > 5);
    }

    #[test]
    fn sanitize_username_too_short() {
        let result = sanitize_username("ab");
        assert!(result.starts_with("user_"));
    }

    #[test]
    fn sanitize_username_long() {
        let long = "a".repeat(50);
        let result = sanitize_username(&long);
        assert!(result.len() <= 30);
    }

    #[test]
    fn provider_urls_match_endpoint_constants() {
        // Dedupe regression: social URLs must come from providers::endpoints.
        assert_eq!(
            SocialProvider::GitHub.authorize_url(),
            endpoints::GITHUB_AUTHORIZE_URL
        );
        assert_eq!(
            SocialProvider::GitHub.token_url(),
            endpoints::GITHUB_TOKEN_URL
        );
        assert_eq!(
            SocialProvider::GitHub.user_info_url(),
            endpoints::GITHUB_USER_INFO_URL
        );
        assert_eq!(
            SocialProvider::Google.authorize_url(),
            endpoints::GOOGLE_AUTHORIZE_URL
        );
        assert_eq!(
            SocialProvider::Google.token_url(),
            endpoints::GOOGLE_TOKEN_URL
        );
        assert_eq!(
            SocialProvider::Google.user_info_url(),
            endpoints::GOOGLE_USER_INFO_URL
        );
    }
}
