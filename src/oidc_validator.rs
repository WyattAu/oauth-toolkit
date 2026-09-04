//! JWKS-backed OIDC token validation.

use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;

use crate::oidc::OidcError;

/// Configuration for OIDC token validation.
#[derive(Debug, Clone)]
pub struct OidcValidatorConfig {
    /// Expected issuer URL.
    pub issuer: String,
    /// Expected audience.
    pub audience: String,
    /// JWKS URI. If None, auto-discovered from `.well-known/openid-configuration`.
    pub jwks_uri: Option<String>,
}

struct JwksCache {
    keys: HashMap<String, jsonwebtoken::DecodingKey>,
    fetched_at: std::time::Instant,
}

/// JWKS-backed OIDC token validator.
///
/// Caches JWKS keys with a 24-hour TTL. Rejects HMAC algorithms
/// (only accepts asymmetric: RS256, ES256, etc.).
pub struct OidcValidator {
    config: Arc<OidcValidatorConfig>,
    jwks: Arc<RwLock<JwksCache>>,
    http_client: reqwest::Client,
}

impl OidcValidator {
    /// Create a new validator. Call `refresh_jwks()` after construction.
    pub fn new(config: OidcValidatorConfig) -> Self {
        Self {
            config: Arc::new(config),
            jwks: Arc::new(RwLock::new(JwksCache {
                keys: HashMap::new(),
                fetched_at: std::time::Instant::now() - std::time::Duration::from_secs(86400),
            })),
            http_client: reqwest::Client::new(),
        }
    }

    /// Get the validator configuration.
    pub fn config(&self) -> &OidcValidatorConfig {
        &self.config
    }

    /// Validate a JWT and extract typed claims.
    pub async fn validate_token<T: DeserializeOwned>(&self, token: &str) -> Result<T, OidcError> {
        self.maybe_refresh_jwks().await?;

        let cache = self.jwks.read();
        for (_kid, key) in cache.keys.iter() {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.set_audience(&[&self.config.audience]);
            validation.set_issuer(&[&self.config.issuer]);

            if let Ok(data) = jsonwebtoken::decode::<T>(token, key, &validation) {
                return Ok(data.claims);
            }
        }

        Err(OidcError::TokenExchangeFailed(
            "no matching key found".into(),
        ))
    }

    /// Force-refresh the JWKS cache.
    pub async fn refresh_jwks(&self) -> Result<(), OidcError> {
        let jwks_uri = match &self.config.jwks_uri {
            Some(uri) => uri.clone(),
            None => {
                let discovery =
                    crate::oidc::fetch_discovery(&self.http_client, &self.config.issuer).await?;
                discovery.jwks_uri
            }
        };

        let resp = self
            .http_client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

        let jwks_value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

        let mut keys = HashMap::new();
        if let Some(key_array) = jwks_value["keys"].as_array() {
            for key_obj in key_array {
                if let (Some(kty), Some(kid)) = (key_obj["kty"].as_str(), key_obj["kid"].as_str()) {
                    if kty == "RSA" {
                        if let (Some(n), Some(e)) = (key_obj["n"].as_str(), key_obj["e"].as_str()) {
                            let decoding_key =
                                jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok();
                            if let Some(key) = decoding_key {
                                keys.insert(kid.to_string(), key);
                            }
                        }
                    }
                }
            }
        }

        let mut cache = self.jwks.write();
        cache.keys = keys;
        cache.fetched_at = std::time::Instant::now();

        Ok(())
    }

    async fn maybe_refresh_jwks(&self) -> Result<(), OidcError> {
        let needs_refresh = {
            let cache = self.jwks.read();
            cache.fetched_at.elapsed() > std::time::Duration::from_secs(86400)
        };
        if needs_refresh {
            self.refresh_jwks().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_config_creation() {
        let config = OidcValidatorConfig {
            issuer: "https://accounts.google.com".into(),
            audience: "my-app".into(),
            jwks_uri: None,
        };
        let _validator = OidcValidator::new(config);
    }
}
