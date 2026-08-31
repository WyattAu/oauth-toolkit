//! CSRF state management with pluggable backends.

use std::time::{Duration, Instant};
use dashmap::DashMap;

/// CSRF state store trait.
#[async_trait::async_trait]
pub trait CsrfStore: Send + Sync {
    /// Store a state nonce with optional redirect URL.
    /// Returns true if stored successfully.
    async fn store(&self, key: &str, nonce: &str, redirect_url: Option<String>) -> bool;

    /// Retrieve and consume a state nonce (one-time use).
    /// Returns (nonce, redirect_url) if found and not expired.
    async fn retrieve_and_consume(&self, key: &str) -> Option<(String, Option<String>)>;

    /// Remove expired entries.
    async fn cleanup_expired(&self);
}

/// In-memory CSRF store using DashMap with TTL.
pub struct MemoryCsrfStore {
    entries: DashMap<String, CsrfEntry>,
    ttl: Duration,
}

struct CsrfEntry {
    nonce: String,
    redirect_url: Option<String>,
    created_at: Instant,
}

impl Default for MemoryCsrfStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCsrfStore {
    /// Create a new in-memory store with 10-minute TTL.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            ttl: Duration::from_secs(600),
        }
    }

    /// Create with custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }
}

#[async_trait::async_trait]
impl CsrfStore for MemoryCsrfStore {
    async fn store(&self, key: &str, nonce: &str, redirect_url: Option<String>) -> bool {
        self.entries.insert(
            key.to_string(),
            CsrfEntry {
                nonce: nonce.to_string(),
                redirect_url,
                created_at: Instant::now(),
            },
        );
        true
    }

    async fn retrieve_and_consume(&self, key: &str) -> Option<(String, Option<String>)> {
        let entry = self.entries.remove(key)?;
        if entry.1.created_at.elapsed() > self.ttl {
            return None;
        }
        Some((entry.1.nonce, entry.1.redirect_url))
    }

    async fn cleanup_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| now.duration_since(entry.created_at) <= self.ttl);
    }
}

/// Multi-backend CSRF store.
pub enum CsrfStoreType {
    /// In-memory backend (single-instance only).
    Memory(MemoryCsrfStore),
}

impl Default for CsrfStoreType {
    fn default() -> Self {
        Self::Memory(MemoryCsrfStore::new())
    }
}

impl CsrfStoreType {
    /// Create a new store. Currently only in-memory is supported.
    pub fn new() -> Self {
        Self::Memory(MemoryCsrfStore::new())
    }
}

#[async_trait::async_trait]
impl CsrfStore for CsrfStoreType {
    async fn store(&self, key: &str, nonce: &str, redirect_url: Option<String>) -> bool {
        match self {
            Self::Memory(s) => s.store(key, nonce, redirect_url).await,
        }
    }

    async fn retrieve_and_consume(&self, key: &str) -> Option<(String, Option<String>)> {
        match self {
            Self::Memory(s) => s.retrieve_and_consume(key).await,
        }
    }

    async fn cleanup_expired(&self) {
        match self {
            Self::Memory(s) => s.cleanup_expired().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_roundtrip() {
        let store = MemoryCsrfStore::new();
        store.store("key1", "nonce1", Some("https://app.com".into())).await;
        let result = store.retrieve_and_consume("key1").await;
        assert_eq!(result, Some(("nonce1".into(), Some("https://app.com".into()))));
        assert!(store.retrieve_and_consume("key1").await.is_none());
    }

    #[tokio::test]
    async fn memory_store_missing_key() {
        let store = MemoryCsrfStore::new();
        assert!(store.retrieve_and_consume("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn memory_store_cleanup() {
        let store = MemoryCsrfStore::with_ttl(Duration::from_millis(1));
        store.store("key1", "nonce1", None).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        store.cleanup_expired().await;
        assert!(store.retrieve_and_consume("key1").await.is_none());
    }

    #[tokio::test]
    async fn csrf_store_type_delegates() {
        let store = CsrfStoreType::new();
        store.store("key1", "nonce1", None).await;
        assert!(store.retrieve_and_consume("key1").await.is_some());
    }
}
