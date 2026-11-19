//! E2E instance + nonce discovery and caching.
//!
//! Manages the pool of TEE instances and their one-shot nonces from
//! `api.chutes.ai/e2e/instances/{chute_id}`.

use crate::e2ee::crypto::{self, CryptoError, MLKEM_EK_SIZE};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// One TEE instance with its public key and pool of one-shot nonces.
#[derive(Clone, Debug)]
pub struct Instance {
    pub instance_id: String,
    pub e2e_pubkey: Vec<u8>,
    pub nonces: Vec<String>,
    /// Optional TDX quote (raw bytes) if the API returned one.
    pub quote: Option<Vec<u8>>,
}

/// The parsed response from `GET /e2e/instances/{chute_id}`.
#[derive(Debug, Deserialize)]
pub struct InstancesResponse {
    pub instances: Vec<InstanceRaw>,
    pub nonce_expires_in: u64,
}

/// Raw instance from the API (nonces as strings, pubkey as base64).
#[derive(Clone, Debug, Deserialize)]
pub struct InstanceRaw {
    pub instance_id: String,
    pub e2e_pubkey: String,
    pub nonces: Vec<String>,
    /// Optional TDX quote (base64-encoded raw quote bytes). The current Chutes
    /// API does not return this field, but it is parsed when present so the
    /// attestation verification path can be exercised.
    #[serde(default)]
    pub quote: Option<String>,
}

/// Cached instance pool with TTL.
pub struct InstanceCache {
    chute_id: String,
    instances: Vec<Instance>,
    nonce_expires_in: u64,
    fetched_at: Instant,
}

impl InstanceCache {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > Duration::from_secs(self.nonce_expires_in)
    }
}

/// The discovery manager holds the cached instance pool per chute.
pub struct Discovery {
    cache: Arc<RwLock<Option<InstanceCache>>>,
    client: reqwest::Client,
    api_base: String,
}

impl Discovery {
    pub fn new(client: reqwest::Client, api_base: String) -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            client,
            api_base,
        }
    }

    /// Take one (instance_id, e2e_pubkey, nonce, quote) tuple from the pool.
    /// If the cache is empty or expired, returns None (caller should refresh).
    pub async fn take_nonce(&self) -> Option<(String, Vec<u8>, String, Option<Vec<u8>>)> {
        let mut cache = self.cache.write().await;
        let cache = cache.as_mut()?;
        if cache.is_expired() {
            return None;
        }
        // Round-robin: pick the first instance with remaining nonces.
        for inst in cache.instances.iter_mut() {
            if let Some(nonce) = inst.nonces.pop() {
                return Some((
                    inst.instance_id.clone(),
                    inst.e2e_pubkey.clone(),
                    nonce,
                    inst.quote.clone(),
                ));
            }
        }
        None
    }

    /// Invalidate the cache (e.g. on 403 nonce error).
    pub async fn invalidate(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }

    /// Fetch fresh instances + nonces from the control plane.
    pub async fn refresh(
        &self,
        chute_id: &str,
        api_key: &str,
    ) -> Result<(), DiscoveryError> {
        let url = format!("{}/e2e/instances/{}", self.api_base.trim_end_matches('/'), chute_id);
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Cache-Control", "no-cache, no-store")
            .send()
            .await
            .map_err(DiscoveryError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DiscoveryError::Status(status.as_u16(), body));
        }
        let parsed: InstancesResponse = resp
            .json()
            .await
            .map_err(DiscoveryError::Parse)?;
        let instances = parsed
            .instances
            .into_iter()
            .map(|raw| {
                let pubkey = base64_decode(&raw.e2e_pubkey).unwrap_or_default();
                let quote = raw.quote.and_then(|q| base64_decode(&q).ok());
                Instance {
                    instance_id: raw.instance_id,
                    e2e_pubkey: pubkey,
                    nonces: raw.nonces,
                    quote,
                }
            })
            .collect();
        let cache = InstanceCache {
            chute_id: chute_id.to_string(),
            instances,
            nonce_expires_in: parsed.nonce_expires_in,
            fetched_at: Instant::now(),
        };
        let mut guard = self.cache.write().await;
        *guard = Some(cache);
        Ok(())
    }

    /// Take a nonce, refreshing if necessary. Returns the instance_id,
    /// e2e_pubkey, nonce, and optional quote.
    pub async fn acquire(
        &self,
        chute_id: &str,
        api_key: &str,
    ) -> Result<(String, Vec<u8>, String, Option<Vec<u8>>), DiscoveryError> {
        // Try the cache first.
        if let Some(tuple) = self.take_nonce().await {
            return Ok(tuple);
        }
        // Refresh and retry.
        self.refresh(chute_id, api_key).await?;
        self.take_nonce()
            .await
            .ok_or(DiscoveryError::NoNonces)
    }
}

#[derive(Debug)]
pub enum DiscoveryError {
    Http(reqwest::Error),
    Parse(reqwest::Error),
    Status(u16, String),
    NoNonces,
    Crypto(CryptoError),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::Http(e) => write!(f, "HTTP error: {e}"),
            DiscoveryError::Parse(e) => write!(f, "parse error: {e}"),
            DiscoveryError::Status(code, body) => write!(f, "status {code}: {body}"),
            DiscoveryError::NoNonces => write!(f, "no nonces available"),
            DiscoveryError::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<CryptoError> for DiscoveryError {
    fn from(e: CryptoError) -> Self {
        DiscoveryError::Crypto(e)
    }
}

/// Base64-decode a standard-encoded string to bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| CryptoError::InvalidKey(s.len()))
}

/// Base64-encode bytes to a standard-encoded string.
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::crypto::random_bytes;

    #[test]
    fn test_base64_encode_decode_round_trip() {
        let data = random_bytes(1184);
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_mlkem_pubkey_size() {
        // A base64-encoded 1184-byte key is 1580 chars (ceil(1184/3)*4).
        let key = random_bytes(MLKEM_EK_SIZE);
        let encoded = base64_encode(&key);
        assert_eq!(encoded.len(), 1580);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), MLKEM_EK_SIZE);
        assert_eq!(decoded, key);
    }

    #[test]
    fn test_base64_decode_invalid_returns_error() {
        assert!(base64_decode("!!!not valid base64!!!").is_err());
    }

    #[tokio::test]
    async fn test_instance_cache_take_nonce_round_robin() {
        // Build a cache directly and verify nonce consumption.
        let pubkey = vec![0u8; MLKEM_EK_SIZE];
        let inst1 = Instance {
            instance_id: "inst-1".into(),
            e2e_pubkey: pubkey.clone(),
            nonces: vec!["n1".into(), "n2".into()],
            quote: None,
        };
        let inst2 = Instance {
            instance_id: "inst-2".into(),
            e2e_pubkey: pubkey.clone(),
            nonces: vec!["n3".into()],
            quote: None,
        };
        let cache = InstanceCache {
            chute_id: "chute-1".into(),
            instances: vec![inst1, inst2],
            nonce_expires_in: 60,
            fetched_at: Instant::now(),
        };
        let discovery = Discovery {
            cache: Arc::new(RwLock::new(Some(cache))),
            client: reqwest::Client::new(),
            api_base: "http://unused".into(),
        };
        // Take 3 nonces — all should succeed.
        let (_id1, _, n1, _) = discovery.take_nonce().await.unwrap();
        let (_id2, _, n2, _) = discovery.take_nonce().await.unwrap();
        let (_id3, _, n3, _) = discovery.take_nonce().await.unwrap();
        // Nonces are consumed LIFO (pop), so inst1 yields n2, n1; inst2 yields n3.
        assert!(n1 != n2);
        assert_ne!(n3, n1);
        assert_ne!(n3, n2);
        // 4th take → None (exhausted).
        assert!(discovery.take_nonce().await.is_none());
    }

    #[tokio::test]
    async fn test_instance_cache_invalidate() {
        let pubkey = vec![0u8; MLKEM_EK_SIZE];
        let inst = Instance {
            instance_id: "inst-1".into(),
            e2e_pubkey: pubkey,
            nonces: vec!["n1".into()],
            quote: None,
        };
        let cache = InstanceCache {
            chute_id: "chute-1".into(),
            instances: vec![inst],
            nonce_expires_in: 60,
            fetched_at: Instant::now(),
        };
        let discovery = Discovery {
            cache: Arc::new(RwLock::new(Some(cache))),
            client: reqwest::Client::new(),
            api_base: "http://unused".into(),
        };
        assert!(discovery.take_nonce().await.is_some());
        // After invalidate, cache is None.
        discovery.invalidate().await;
        assert!(discovery.take_nonce().await.is_none());
    }

    #[tokio::test]
    async fn test_instance_cache_expired_returns_none() {
        let pubkey = vec![0u8; MLKEM_EK_SIZE];
        let inst = Instance {
            instance_id: "inst-1".into(),
            e2e_pubkey: pubkey,
            nonces: vec!["n1".into()],
            quote: None,
        };
        let cache = InstanceCache {
            chute_id: "chute-1".into(),
            instances: vec![inst],
            nonce_expires_in: 0, // expires immediately
            fetched_at: Instant::now() - Duration::from_secs(1),
        };
        let discovery = Discovery {
            cache: Arc::new(RwLock::new(Some(cache))),
            client: reqwest::Client::new(),
            api_base: "http://unused".into(),
        };
        assert!(discovery.take_nonce().await.is_none());
    }

    #[tokio::test]
    async fn test_discovery_refresh_and_acquire_from_mock_server() {
        use axum::{routing::get, Json, Router};
        let pubkey = base64_encode(&vec![0u8; MLKEM_EK_SIZE]);
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-uuid-1",
                "e2e_pubkey": pubkey,
                "nonces": ["nonce-a", "nonce-b"]
            }],
            "nonce_expires_in": 60
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/e2e/instances/:chute_id",
            get(move || {
                let body = resp_body.clone();
                async move { Json(body) }
            }),
        );
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });

        let discovery = Discovery::new(
            reqwest::Client::new(),
            format!("http://{}", addr),
        );
        let (instance_id, pub_key, nonce, _quote) = discovery
            .acquire("chute-x", "test-key")
            .await
            .unwrap();
        assert_eq!(instance_id, "inst-uuid-1");
        assert_eq!(pub_key.len(), MLKEM_EK_SIZE);
        assert!(nonce == "nonce-a" || nonce == "nonce-b");
        // Second acquire from cache.
        let (_, _, nonce2, _) = discovery.acquire("chute-x", "test-key").await.unwrap();
        assert_ne!(nonce, nonce2);
        // Third acquire → cache exhausted → refresh → no nonces (mock returns same).
        // Actually mock returns the same nonces again, so it should succeed.
        let result = discovery.acquire("chute-x", "test-key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_discovery_refresh_handles_403_error() {
        use axum::{http::StatusCode, routing::get, Json, Router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/e2e/instances/:chute_id",
            get(|| async { (StatusCode::FORBIDDEN, Json(serde_json::json!({"detail": "nonce expired"}))) }),
        );
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });

        let discovery = Discovery::new(
            reqwest::Client::new(),
            format!("http://{}", addr),
        );
        let result = discovery.acquire("chute-x", "test-key").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            DiscoveryError::Status(403, body) => assert!(body.contains("nonce")),
            other => panic!("expected Status(403), got {other:?}"),
        }
    }
}
