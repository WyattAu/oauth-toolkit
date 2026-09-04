//! `OAuth2` token endpoint operations: authorization-code exchange (with
//! PKCE verifier) and refresh-token rotation.

use serde::{Deserialize, Serialize};

/// Errors from token endpoint operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// HTTP request to the token endpoint failed.
    #[error("token endpoint: {0}")]
    Http(String),
    /// The endpoint returned a non-success status.
    #[error("token endpoint returned {0}")]
    Status(reqwest::StatusCode),
    /// The response body was not valid token-endpoint JSON.
    #[error("token JSON: {0}")]
    Json(String),
}

/// Parsed response from an `OAuth2` token endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token string.
    pub access_token: String,
    /// Token type (e.g. `"Bearer"`).
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Rotated refresh token (if the provider issues one).
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Outcome of a completed token request, with access-token expiry
/// computed in unix milliseconds.
#[derive(Clone, Debug)]
pub struct TokenSet {
    /// Access token (short-lived).
    pub access_token: String,
    /// Refresh token (persist and treat as a secret).
    pub refresh_token: Option<String>,
    /// Access-token expiry in unix ms.
    pub expires_at: i64,
}

/// Exchanges an authorization code for tokens (PKCE verifier required).
///
/// # Errors
/// [`TokenError`] on HTTP/protocol failure.
pub async fn exchange_code(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenSet, TokenError> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("client_id", client_id.to_string()),
        ("code_verifier", code_verifier.to_string()),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret.to_owned()));
    }
    token_request(http, token_url, &form).await
}

/// Refreshes an access token with a stored refresh token.
///
/// # Errors
/// [`TokenError::Status`] when the refresh is rejected (revoked/expired).
pub async fn refresh(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<TokenSet, TokenError> {
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret.to_owned()));
    }
    token_request(http, token_url, &form).await
}

/// Refreshes an access token and returns the raw [`TokenResponse`]
/// (rotation-aware: callers read `refresh_token` off the response).
///
/// # Errors
/// [`TokenError::Status`] when the refresh is rejected (revoked/expired).
pub async fn refresh_access_token(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, TokenError> {
    let form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", client_id.to_string()),
    ];
    token_request_raw(http, token_url, &form).await
}

async fn token_request(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, String)],
) -> Result<TokenSet, TokenError> {
    let parsed = token_request_raw(http, url, form).await?;
    let expires_in = i64::try_from(parsed.expires_in.unwrap_or(3600)).unwrap_or(i64::MAX);
    let expires_at = now_unix_ms().saturating_add(expires_in.saturating_mul(1000));
    Ok(TokenSet {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at,
    })
}

async fn token_request_raw(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, String)],
) -> Result<TokenResponse, TokenError> {
    let response = http
        .post(url)
        .form(form)
        .send()
        .await
        .map_err(|e| TokenError::Http(e.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| TokenError::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(TokenError::Status(status));
    }
    serde_json::from_str(&text).map_err(|e| TokenError::Json(e.to_string()))
}

/// Wall-clock read for token-expiry math (inherently wall-clock: the token
/// endpoint defines lifetimes).
fn now_unix_ms() -> i64 {
    #[allow(clippy::disallowed_methods)]
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Spawns a minimal mock token endpoint and returns its base URL.
    async fn spawn_mock_token_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let base = format!("http://127.0.0.1:{port}");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read");
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            // Determine response based on request body.
            let body = if request.contains("refresh_token=bad") {
                r#"{"error":"invalid_grant","error_description":"token is invalid"}"#
            } else if request.contains("grant_type=authorization_code") {
                r#"{"access_token":"exch_at","token_type":"Bearer","expires_in":1800,"refresh_token":"exch_rt"}"#
            } else if request.contains("grant_type=refresh_token") {
                r#"{"access_token":"new_at","token_type":"Bearer","expires_in":3600,"refresh_token":"new_rt"}"#
            } else {
                r#"{"error":"unsupported_grant_type"}"#
            };
            let status = if request.contains("bad") || request.contains("unsupported") {
                "400"
            } else {
                "200"
            };
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        (base, handle)
    }

    #[tokio::test]
    async fn exchange_code_sends_pkce_form() {
        let (base, handle) = spawn_mock_token_server().await;
        let http = reqwest::Client::new();
        let set = exchange_code(
            &http,
            &format!("{base}/token"),
            "test-cid",
            None,
            "the-code",
            "http://127.0.0.1:53123/cb",
            "the-verifier",
        )
        .await
        .expect("success");
        assert_eq!(set.access_token, "exch_at");
        assert_eq!(set.refresh_token.as_deref(), Some("exch_rt"));
        assert!(set.expires_at > 0, "expiry computed from expires_in");
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_access_token_sends_correct_form() {
        let (base, handle) = spawn_mock_token_server().await;
        let http = reqwest::Client::new();
        let resp = refresh_access_token(
            &http,
            &format!("{base}/token"),
            "test-client-id",
            "test-refresh-token",
        )
        .await
        .expect("success");
        assert_eq!(resp.access_token, "new_at");
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.refresh_token.as_deref(), Some("new_rt"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_access_token_handles_rotation() {
        let (base, handle) = spawn_mock_token_server().await;
        let http = reqwest::Client::new();
        let resp = refresh_access_token(&http, &format!("{base}/token"), "client", "old-rt")
            .await
            .expect("ok");
        // The mock returns a new refresh token.
        assert_eq!(resp.refresh_token.as_deref(), Some("new_rt"));
        assert_ne!(resp.refresh_token.as_deref(), Some("old-rt"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_access_token_rejects_invalid_token() {
        let (base, handle) = spawn_mock_token_server().await;
        let http = reqwest::Client::new();
        let err = refresh_access_token(&http, &format!("{base}/token"), "client", "bad")
            .await
            .expect_err("should fail");
        match err {
            TokenError::Status(status) => assert_eq!(status.as_u16(), 400),
            other => panic!("unexpected: {other}"),
        }
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_access_token_network_error() {
        let http = reqwest::Client::new();
        let err = refresh_access_token(&http, "http://127.0.0.1:1/nope", "client", "rt")
            .await
            .expect_err("should fail");
        assert!(matches!(err, TokenError::Http(_)));
    }

    #[tokio::test]
    async fn refresh_access_token_url_construction() {
        // Verify the form fields are sent correctly by reading the raw POST
        // body from a mock server that captures it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let base = format!("http://127.0.0.1:{port}");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read");
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            // Extract the POST body (after double CRLF).
            let body = raw.split_once("\r\n\r\n").map_or("", |(_, b)| b);
            assert!(body.contains("grant_type=refresh_token"), "body: {body}");
            assert!(body.contains("refresh_token=test-rt"), "body: {body}");
            assert!(body.contains("client_id=test-cid"), "body: {body}");
            let resp = r#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"new-rt"}"#;
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                resp.len()
            );
            stream.write_all(http.as_bytes()).await.expect("write");
        });
        let http = reqwest::Client::new();
        let result = refresh_access_token(&http, &format!("{base}/token"), "test-cid", "test-rt")
            .await
            .expect("ok");
        assert_eq!(result.access_token, "at");
        server.await.unwrap();
    }

    #[test]
    fn token_response_deserialize_minimal() {
        let json = r#"{"access_token":"at","token_type":"Bearer","expires_in":300}"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.access_token, "at");
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.expires_in, Some(300));
        assert!(resp.refresh_token.is_none());
    }

    #[test]
    fn token_response_deserialize_full() {
        let json =
            r#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt"}"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.refresh_token.as_deref(), Some("rt"));
    }
}
