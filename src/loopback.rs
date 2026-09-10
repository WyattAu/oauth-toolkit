//! Desktop loopback redirect capture (RFC 8252 §7.3).
//!
//! Binds `127.0.0.1:<ephemeral>`, builds the authorization URL with PKCE
//! (S256) and a single-use `state`, then captures exactly one redirect:
//! the listener serves one response and shuts down.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::pkce::generate_pkce_pair;

/// Loopback host the capture server binds (never a routable interface).
pub const LOOPBACK_HOST: &str = "127.0.0.1";
/// Fixed callback path for the redirect URI.
pub const CALLBACK_PATH: &str = "/cb";

/// The redirect URI for a loopback port: `http://127.0.0.1:<port>/cb`.
#[must_use]
pub fn loopback_redirect_uri(port: u16) -> String {
    format!("http://{LOOPBACK_HOST}:{port}{CALLBACK_PATH}")
}

/// Build the browser authorization URL (RFC 8252 style; the user opens it
/// externally) with PKCE S256, state, scopes, and an optional login hint.
#[must_use]
pub fn build_authorization_url(
    authorize_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    scopes: &[String],
    code_challenge: &str,
    login_hint: Option<&str>,
) -> String {
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}&code_challenge={}&code_challenge_method=S256",
        authorize_url,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
        urlencoding::encode(&scopes.join(" ")),
        urlencoding::encode(code_challenge),
    );
    if let Some(hint) = login_hint {
        let _ = write!(url, "&login_hint={}", urlencoding::encode(hint));
    }
    url
}

/// Errors from the loopback capture flow.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackError {
    /// Binding the loopback listener failed.
    #[error("loopback bind: {0}")]
    Bind(String),
    /// The user did not complete the redirect within the timeout.
    #[error("loopback capture timed out")]
    Timeout,
    /// The redirect's `state` did not match (possible CSRF).
    #[error("state mismatch (possible CSRF)")]
    StateMismatch,
    /// The provider redirected with an `error` parameter.
    #[error("provider error: {0}")]
    Provider(String),
    /// The redirect carried no authorization `code`.
    #[error("redirect missing code")]
    MissingCode,
    /// Socket I/O failure during capture.
    #[error("loopback io: {0}")]
    Io(String),
}

/// A started loopback flow: the authorization URL to open plus the capture
/// server waiting on an ephemeral loopback port.
pub struct LoopbackFlow {
    listener: TcpListener,
    auth_url: String,
    state: String,
    verifier: String,
    port: u16,
    timeout: Duration,
}

/// Result of a captured redirect.
#[derive(Clone, Debug)]
pub struct CapturedCode {
    /// Authorization code from the provider.
    pub code: String,
    /// PKCE verifier matching the challenge sent in the auth URL.
    pub verifier: String,
    /// The ephemeral loopback port (needed to reconstruct `redirect_uri`).
    pub port: u16,
}

impl LoopbackFlow {
    /// Binds an ephemeral loopback port and builds the authorization URL.
    ///
    /// # Errors
    /// [`LoopbackError::Bind`] if the loopback listener cannot bind.
    pub fn start(
        authorize_url: &str,
        client_id: &str,
        scopes: &[String],
        login_hint: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|e| LoopbackError::Bind(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| LoopbackError::Bind(e.to_string()))?
            .port();
        let (verifier, challenge) = generate_pkce_pair();
        let state = crate::crypto::generate_state_nonce(16);
        let auth_url = build_authorization_url(
            authorize_url,
            client_id,
            &loopback_redirect_uri(port),
            &state,
            scopes,
            &challenge,
            login_hint,
        );
        Ok(Self {
            listener,
            auth_url,
            state,
            verifier,
            port,
            timeout,
        })
    }

    /// Convenience wrapper binding a flow for a
    /// [`MailProvider`](crate::providers::MailProvider) preset.
    ///
    /// # Errors
    /// [`LoopbackError::Bind`] if the loopback listener cannot bind.
    pub fn start_for_provider(
        provider: &crate::providers::MailProvider,
        login_hint: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, LoopbackError> {
        Self::start(
            &provider.auth_url,
            &provider.client_id,
            &provider.authorization_scopes(),
            login_hint,
            timeout,
        )
    }

    /// The ephemeral port the capture server is listening on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The full authorization URL for the user's browser.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.auth_url
    }

    /// The single-use state token (exposed for tests and diagnostics).
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Waits for exactly one redirect, validates the single-use `state`,
    /// serves a confirmation page, and shuts the listener down.
    ///
    /// Consumes `self`: after this returns (ok or err) the port is closed
    /// and a second redirect is refused.
    ///
    /// # Errors
    /// [`LoopbackError`] variants for timeout, provider error, state
    /// mismatch, missing code, or I/O failure.
    pub fn wait_for_code(self) -> Result<CapturedCode, LoopbackError> {
        let Self {
            listener,
            state,
            verifier,
            port,
            timeout,
            ..
        } = self;
        let deadline = Instant::now() + timeout;

        listener
            .set_nonblocking(true)
            .map_err(|e| LoopbackError::Io(e.to_string()))?;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LoopbackError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(LoopbackError::Io(e.to_string())),
            }
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        stream
            .set_read_timeout(Some(remaining.max(Duration::from_millis(50))))
            .map_err(|e| LoopbackError::Io(e.to_string()))?;

        let request = read_request(&mut stream)?;
        let query = request_line_query(&request);
        let (code, got_state, oauth_error) = parse_query(&query);

        let body = "<html><body><h3>Signed in</h3>You may close this tab and return to the application.</body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        drop(stream);
        drop(listener);

        if !oauth_error.is_empty() {
            return Err(LoopbackError::Provider(oauth_error));
        }
        if got_state != state {
            return Err(LoopbackError::StateMismatch);
        }
        code.map(|code| CapturedCode {
            code,
            verifier,
            port,
        })
        .ok_or(LoopbackError::MissingCode)
    }
}

fn read_request(stream: &mut TcpStream) -> Result<String, LoopbackError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(LoopbackError::Timeout);
            }
            Err(e) => return Err(LoopbackError::Io(e.to_string())),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn request_line_query(request: &str) -> String {
    let request_line = request.lines().next().unwrap_or_default();
    let path = request_line.split_whitespace().nth(1).unwrap_or_default();
    path.split_once('?')
        .map_or(String::new(), |(_, q)| q.to_owned())
}

fn parse_query(query: &str) -> (Option<String>, String, String) {
    let mut code = None;
    let mut state = String::new();
    let mut error = String::new();
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let decoded = urlencoding::decode(v)
            .map(|c| c.into_owned())
            .unwrap_or_default();
        match k {
            "code" => code = Some(decoded),
            "state" => state = decoded,
            "error" => error = decoded,
            _ => {}
        }
    }
    (code, state, error)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const FIVE_SECS: Duration = Duration::from_secs(5);

    fn start_test_flow(timeout: Duration) -> LoopbackFlow {
        LoopbackFlow::start(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "cid-123",
            &["https://mail.google.com/".to_string()],
            Some("a@b.c"),
            timeout,
        )
        .unwrap()
    }

    /// Sends a forged redirect request and returns the raw HTTP response.
    fn send_redirect(port: u16, query: &str) -> String {
        let mut sock = TcpStream::connect((LOOPBACK_HOST, port)).expect("connect");
        let request =
            format!("GET /cb?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        sock.write_all(request.as_bytes()).expect("write");
        let mut buf = String::new();
        let _ = sock.read_to_string(&mut buf);
        buf
    }

    #[test]
    fn binds_ephemeral_loopback_port() {
        let flow = start_test_flow(FIVE_SECS);
        assert!(flow.port() > 0, "must bind an ephemeral port, not :0");
        assert!(
            flow.authorization_url()
                .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A")
        );
    }

    #[test]
    fn authorization_url_contains_required_params() {
        let flow = start_test_flow(FIVE_SECS);
        let url = flow.authorization_url();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("client_id=cid-123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains(&format!("state={}", flow.state())));
        assert!(url.contains("scope=https%3A%2F%2Fmail.google.com%2F"));
        assert!(url.contains("login_hint=a%40b.c"));
    }

    #[test]
    fn loopback_redirect_uri_shape() {
        assert_eq!(loopback_redirect_uri(53123), "http://127.0.0.1:53123/cb");
    }

    #[test]
    fn capture_accepts_valid_redirect() {
        let flow = start_test_flow(FIVE_SECS);
        let port = flow.port();
        let state = flow.state().to_owned();
        let handle = std::thread::spawn(move || flow.wait_for_code());
        let response = send_redirect(port, &format!("code=AC123&state={state}"));
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("Signed in"), "{response}");
        let captured = handle.join().unwrap().unwrap();
        assert_eq!(captured.code, "AC123");
        assert_eq!(captured.port, port);
        assert!(!captured.verifier.is_empty(), "PKCE verifier returned");
    }

    #[test]
    fn capture_rejects_state_mismatch() {
        let flow = start_test_flow(FIVE_SECS);
        let port = flow.port();
        let handle = std::thread::spawn(move || flow.wait_for_code());
        send_redirect(port, "code=X&state=evil");
        match handle.join().unwrap() {
            Err(LoopbackError::StateMismatch) => {}
            other => panic!("expected StateMismatch, got {other:?}"),
        }
    }

    #[test]
    fn state_is_single_use_and_listener_shuts_down() {
        let flow = start_test_flow(FIVE_SECS);
        let port = flow.port();
        // First (mismatched) redirect consumes the single capture.
        let handle = std::thread::spawn(move || flow.wait_for_code());
        let _ = send_redirect(port, "code=X&state=evil");
        assert!(handle.join().unwrap().is_err());
        // The listener is gone: a second redirect is refused.
        assert!(
            TcpStream::connect((LOOPBACK_HOST, port)).is_err(),
            "port {port} must be shut down after the first redirect"
        );
    }

    #[test]
    fn capture_times_out_when_no_redirect() {
        let flow = LoopbackFlow::start(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "cid",
            &[],
            None,
            Duration::from_millis(150),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        match flow.wait_for_code() {
            Err(LoopbackError::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn capture_surfaces_provider_error() {
        let flow = start_test_flow(FIVE_SECS);
        let port = flow.port();
        let state = flow.state().to_owned();
        let handle = std::thread::spawn(move || flow.wait_for_code());
        send_redirect(port, &format!("error=access_denied&state={state}"));
        match handle.join().unwrap() {
            Err(LoopbackError::Provider(e)) => assert_eq!(e, "access_denied"),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[test]
    fn capture_rejects_missing_code() {
        let flow = start_test_flow(FIVE_SECS);
        let port = flow.port();
        let state = flow.state().to_owned();
        let handle = std::thread::spawn(move || flow.wait_for_code());
        send_redirect(port, &format!("state={state}"));
        match handle.join().unwrap() {
            Err(LoopbackError::MissingCode) => {}
            other => panic!("expected MissingCode, got {other:?}"),
        }
    }

    #[test]
    fn percent_decoded_query_values() {
        assert_eq!(
            parse_query("code=a%20b%2Fc&state=s%2Bt").0.as_deref(),
            Some("a b/c")
        );
        assert_eq!(parse_query("state=s%2Bt").1, "s+t");
        assert_eq!(parse_query("").0, None);
    }

    #[test]
    fn start_for_provider_bakes_gmail_urls() {
        let provider = crate::providers::MailProvider::fastmail("fm-cid");
        let flow = LoopbackFlow::start_for_provider(&provider, None, FIVE_SECS).unwrap();
        let url = flow.authorization_url();
        assert!(url.starts_with("https://app.fastmail.com/oauth/authorize?"));
        assert!(url.contains("client_id=fm-cid"));
        assert!(url.contains("protocolIMAP"));
        assert!(url.contains("protocolSMTP"));
    }
}
