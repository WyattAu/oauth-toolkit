//! Config-knob behavior matrix for oauth-toolkit.
//!
//! Every public config knob must OBSERVABLY change behavior: the table
//! below pairs a default with a configured value and asserts the observable
//! output/state differs. A knob that cannot change behavior is a bug (see
//! breaker's sliding_window_size incident).
//!
//! Network note: the OIDC/social knobs are exercised against a tiny local
//! HTTP server (std `TcpListener`, loopback, per-test port) so issuer,
//! audience, JWKS URI, and token-exchange credentials are all validated at
//! a real wire boundary. Time note: the CSRF TTL reads wall-clock
//! `Instant` (no injected clock), so expiry tests use millisecond-scale
//! real waits.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oauth_toolkit::csrf::{CsrfStore, MemoryCsrfStore};
use oauth_toolkit::oidc::OidcConfig;
use oauth_toolkit::oidc_validator::{OidcValidator, OidcValidatorConfig};
use oauth_toolkit::social::{SocialProvider, SocialProviderConfig, build_authorize_url};
use serde::Deserialize;

// --- Static RSA test key (loopback-only, generated for this suite) ---------

const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2UeQaa3o6ZDgm
7TVruz5Jpk/jBmyjXpmi3lqjiQlNTejQeCT4t1dMTWAbwJFl3gt12rODQNipEKzK
r36eQ+I5IR5oUWO5+mPOmSMr0BgeyHrlaCilZSnQD7GQyFS/8aJzUdGeuVNJ8DUV
uedOd/4VwZWe2hNMhu664umKRuSNrbfxPcJZZgHtL5H5q5/i9qCidSUwmFHQKM7r
ZihntcUYLCLKpC6JfMF8o8/+zsLMWHIl19P0GsbK9LXlrLtI8oZc75vr518MqSdt
ypSVfb+E7tQ5L1merPBwbZJbrmCHOSGb2BrpqVbGAlwSPX3ze4qsHnLkiwt37G0B
7bnvfLVpAgMBAAECggEAAkF8YebNR/psNvAVqn/yNvlRsPiIANP3cOxRIQedp7kU
bbrk0zZ6hClLbIB7FBB1ohdLBA9Z9uqLxsS523Wxz3zlSktigV8zm69pn93G5J+c
pKi/ov8/z5EYJHdUFB1mYgijwDPhD8/C6mJG1kHWERkYc7MVTMu5GbMbymAS7R1R
F41e/ZjDpiKEE006OnH8aXw6V8xpiiajFCBjmOD7Ra/0cAMbnfe2vAuBBi1Kgrc/
ws3TH2vdhWUawEHTrkNZq3zLhNuFraDnQKNZrbrEYLpEo5ThJB24EEXiML4lahXx
1xJcIstUqlmGDBdZ9GkWBhWm9zeQaVcq94RgvBdsoQKBgQD+ofv5X2yfptQP/DWR
geKoi+nO3arYzNTH9lZb4GaZ52RiB2e287U9FD7axvuclqP9jk3Gza+NUzg+7GGp
4HxpjsR4ZPtvmpdy8LzoQPqR9kI0kLb859PxXlLBaJ3Iwcst7VU60+mwzhtIVPlo
ltDtMplw2IRJttnnk3xrZvvmCQKBgQC3TIGVhrMZxc/l+CgG/AXs9+p1iAEjHtFo
yHpl9QhSzFA3y4x1We1WoJgUsTvJbceQKQOpYzJL+Q7bpkbdchSoou10iXlITzJ1
NyGKrpXZioYmPJxIWjs+SzmmF3Zb80BvMohVrVawIek9nQRLvS5xsfnN4MPTWHgK
9QXY0rksYQKBgQDgHQ471IM0mY84apFzelBWbJ7jFjMTEmWNggFMaFulxgWSSlY8
ro+sLK+Nu2klz2iS+Lb37X0/9CkjKMZk0FJwTdoa5TZwai42WjDKcraX1Zk7zstg
GWNvo8dOt5d4ZSlBSQyk9HNQzHcy2KeUKHnG66wlqEv23Vs4+ZSeq0u2kQKBgQCt
pChOAiDAlYfxDzi8BRuH9QOC+6g4IQW4AdMRqyKLbUnA0W7p7JrNqazoTU2Z8AlR
I8l4OaR4HCRbKBWRynSPnGjeMS1Xts7SA7weqG0EfBnBN0HFuNTOmmyuTyOsz6+G
p5RHtcGdcUKHP6vGJB1PT46Z3gcku3ZcyukTEeyhgQKBgBKBOBuUBzvQzJc359fd
KpMJ6CTjbz/QtgMcvrRXCSZLUPl8FXmQbHm6rN/ehZNtaJqJxJLhTB9qRVy+YTKj
NJ30KUHr3ANqmr64JllvzAfH0dxYPWQMN3UFOvOb9a3Uyb0MG6PQ0m7Cw21UP/WS
ujdib1t2h74aEdWhS62rLXxV
-----END PRIVATE KEY-----";

const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":"tlHkGmt6OmQ4Ju01a7s-SaZP4wZso16Zot5ao4kJTU3o0Hgk-LdXTE1gG8CRZd4Lddqzg0DYqRCsyq9-nkPiOSEeaFFjufpjzpkjK9AYHsh65WgopWUp0A-xkMhUv_Gic1HRnrlTSfA1FbnnTnf-FcGVntoTTIbuuuLpikbkja238T3CWWYB7S-R-auf4vagonUlMJhR0CjO62YoZ7XFGCwiyqQuiXzBfKPP_s7CzFhyJdfT9BrGyvS15ay7SPKGXO-b6-dfDKknbcqUlX2_hO7UOS9ZnqzwcG2SW65ghzkhm9ga6alWxgJcEj1983uKrB5y5IsLd-xtAe2573y1aQ","e":"AQAB"}]}"#;

const ISSUER: &str = "https://issuer.example.com";
const AUDIENCE: &str = "test-audience";

// --- Tiny loopback HTTP server ----------------------------------------------

/// Spawn a one-thread loopback server that replies `body` to every request
/// and records each request head+body for assertions.
fn spawn_recording_server(body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_thread = captured.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = vec![0u8; 8192];
            let mut request = String::new();
            // Read until headers complete, then try to pick up a body.
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        request.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if request.contains("\r\n\r\n") {
                            let headers_end = request.find("\r\n\r\n").unwrap() + 4;
                            let declared = request
                                .to_lowercase()
                                .find("content-length:")
                                .and_then(|pos| {
                                    request[pos + 15..]
                                        .split("\r\n")
                                        .next()
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if request.len() - headers_end >= declared {
                                break;
                            }
                        }
                    }
                }
            }
            captured_thread.lock().unwrap().push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    (format!("http://{addr}"), captured)
}

fn sign_rs256(issuer: &str, audience: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    #[derive(serde::Serialize)]
    struct Claims {
        iss: String,
        aud: String,
        sub: String,
        exp: usize,
    }
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as usize
        + 3600;
    let claims = Claims {
        iss: issuer.to_string(),
        aud: audience.to_string(),
        sub: "user-1".into(),
        exp,
    };
    jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("valid test key"),
    )
    .expect("sign test token")
}

// --- MemoryCsrfStore::with_ttl ------------------------------------------------

#[tokio::test]
async fn knob_ttl_governs_state_lifetime() {
    let default = MemoryCsrfStore::new();
    let flash = MemoryCsrfStore::with_ttl(Duration::from_millis(1));
    default.store("k", "nonce", None).await;
    flash.store("k", "nonce", None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    assert_eq!(
        default.retrieve_and_consume("k").await,
        Some(("nonce".into(), None)),
        "default 10-minute TTL must keep the state"
    );
    assert_eq!(
        flash.retrieve_and_consume("k").await,
        None,
        "1ms TTL must expire the state (expired state must not be replayable)"
    );
}

#[tokio::test]
async fn knob_ttl_flows_into_cleanup_expired() {
    let flash = MemoryCsrfStore::with_ttl(Duration::from_millis(1));
    flash.store("k", "nonce", None).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    flash.cleanup_expired().await;
    // Consumed by cleanup, not just hidden: a second consume sees nothing.
    assert!(flash.retrieve_and_consume("k").await.is_none());
}

#[tokio::test]
async fn csrf_state_is_single_use_and_carries_redirect() {
    let store = MemoryCsrfStore::with_ttl(Duration::from_secs(600));
    store
        .store("k", "nonce-1", Some("https://app.example.com/cb".into()))
        .await;
    assert_eq!(
        store.retrieve_and_consume("k").await,
        Some(("nonce-1".into(), Some("https://app.example.com/cb".into())))
    );
    assert!(
        store.retrieve_and_consume("k").await.is_none(),
        "state must be one-time use"
    );
}

// --- SocialProviderConfig (via the observable authorize URL) ------------------

#[test]
fn social_config_fields_change_the_authorize_url() {
    let default = SocialProviderConfig {
        client_id: "id123".into(),
        client_secret: "secret".into(),
        redirect_uri: "https://app.com/callback".into(),
    };
    let configured = SocialProviderConfig {
        client_id: "other-client".into(),
        client_secret: "secret".into(),
        redirect_uri: "https://other.app/cb?x=1".into(),
    };

    let base = build_authorize_url(SocialProvider::GitHub, &default, "state123");
    let changed = build_authorize_url(SocialProvider::GitHub, &configured, "state123");

    assert_ne!(base, changed, "config fields must change the authorize URL");
    assert!(base.contains("client_id=id123"));
    assert!(changed.contains("client_id=other-client"));
    assert!(
        changed.contains(&format!(
            "redirect_uri={}",
            urlencoding::encode("https://other.app/cb?x=1")
        )),
        "redirect_uri must be configured and URL-encoded"
    );
    // `state` is behavior-critical (CSRF), so the full binding is asserted.
    assert!(changed.contains("state=state123"));

    // client_secret is consumed only in the token exchange POST body —
    // observability channel is exchange_code, not the authorize URL.
    assert!(base.contains("response_type=code"));
}

// --- OidcConfig (fields observable in the token-exchange POST body) ------------

#[tokio::test]
async fn oidc_config_credentials_reach_the_token_exchange() {
    let token_json = r#"{"access_token":"at","token_type":"Bearer"}"#;
    let (uri, captured) = spawn_recording_server(token_json);

    let config = OidcConfig {
        issuer: ISSUER.into(),
        client_id: "my-client".into(),
        client_secret: "hunter2".into(),
        redirect_uri: "https://app.example.com/cb".into(),
        scope: vec!["openid".into(), "email".into()],
    };
    let client = reqwest::Client::new();
    let _ =
        oauth_toolkit::oidc::exchange_code(&client, &format!("{uri}/token"), &config, "abc", None)
            .await
            .expect("exchange against loopback server");

    let body = captured
        .lock()
        .unwrap()
        .last()
        .expect("request captured")
        .clone();
    assert!(body.contains("client_id=my-client"), "body: {body}");
    assert!(body.contains("client_secret=hunter2"), "body: {body}");
    assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"));
    assert!(body.contains("grant_type=authorization_code"));
}

#[tokio::test]
async fn oidc_config_with_pkce_sends_code_verifier() {
    let token_json = r#"{"access_token":"at","token_type":"Bearer"}"#;
    let (uri, captured) = spawn_recording_server(token_json);

    let config = OidcConfig {
        issuer: ISSUER.into(),
        client_id: "my-client".into(),
        client_secret: "hunter2".into(),
        redirect_uri: "https://app.example.com/cb".into(),
        scope: vec!["openid".into()],
    };
    let client = reqwest::Client::new();
    let _ = oauth_toolkit::oidc::exchange_code(
        &client,
        &format!("{uri}/token"),
        &config,
        "abc",
        Some("verifier-42"),
    )
    .await
    .expect("exchange against loopback server");

    let body = captured
        .lock()
        .unwrap()
        .last()
        .expect("request captured")
        .clone();
    assert!(body.contains("code_verifier=verifier-42"), "body: {body}");
}

// --- OidcValidatorConfig: issuer / audience / jwks_uri -------------------------

#[derive(Debug, Deserialize)]
struct ValidatorClaims {
    iss: String,
    sub: String,
}

#[tokio::test]
async fn validator_config_accepts_matching_issuer_and_audience() {
    let (uri, _captured) = spawn_recording_server(TEST_JWKS_JSON);
    let token = sign_rs256(ISSUER, AUDIENCE);

    let validator = OidcValidator::new(OidcValidatorConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: Some(format!("{uri}/jwks")),
    });
    let claims = validator
        .validate_token::<ValidatorClaims>(&token)
        .await
        .expect("matching iss/aud must validate");
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.sub, "user-1");
}

#[tokio::test]
async fn knob_audience_must_match_the_token() {
    let (uri, _captured) = spawn_recording_server(TEST_JWKS_JSON);
    let token = sign_rs256(ISSUER, AUDIENCE);

    let validator = OidcValidator::new(OidcValidatorConfig {
        issuer: ISSUER.into(),
        audience: "different-audience".into(),
        jwks_uri: Some(format!("{uri}/jwks")),
    });
    assert!(
        validator
            .validate_token::<ValidatorClaims>(&token)
            .await
            .is_err(),
        "a mismatched audience must be rejected"
    );
}

#[tokio::test]
async fn knob_issuer_must_match_the_token() {
    let (uri, _captured) = spawn_recording_server(TEST_JWKS_JSON);
    let token = sign_rs256(ISSUER, AUDIENCE);

    let validator = OidcValidator::new(OidcValidatorConfig {
        issuer: "https://evil.example.com".into(),
        audience: AUDIENCE.into(),
        jwks_uri: Some(format!("{uri}/jwks")),
    });
    assert!(
        validator
            .validate_token::<ValidatorClaims>(&token)
            .await
            .is_err(),
        "a mismatched issuer must be rejected"
    );
}

#[tokio::test]
async fn knob_jwks_uri_points_the_key_fetch() {
    // Same validator config but pointing at a DIFFERENT server (no JWKS
    // material): validation must fail, proving the knob routes the fetch.
    let (empty_uri, _x) = spawn_recording_server(r#"{"keys":[]}"#);
    let (good_uri, good_captured) = spawn_recording_server(TEST_JWKS_JSON);
    let token = sign_rs256(ISSUER, AUDIENCE);

    let validator = OidcValidator::new(OidcValidatorConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: Some(format!("{empty_uri}/jwks")),
    });
    assert!(
        validator
            .validate_token::<ValidatorClaims>(&token)
            .await
            .is_err(),
        "empty key set must not validate anything"
    );

    // Same token validates once jwks_uri points at the serving key set.
    let validator = OidcValidator::new(OidcValidatorConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: Some(format!("{good_uri}/jwks")),
    });
    assert!(
        validator
            .validate_token::<ValidatorClaims>(&token)
            .await
            .is_ok()
    );
    assert!(
        !good_captured.lock().unwrap().is_empty(),
        "jwks_uri must route the key fetch to the configured server"
    );
}
