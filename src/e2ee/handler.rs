//! E2E invoke handler — ties discovery + crypto together.
//!
//! Encrypts a request, POSTs to api.chutes.ai/e2e/invoke with the required
//! X-E2E-* headers, and decrypts the response (streaming or non-streaming).

use crate::e2ee::crypto::{self, CryptoError, HKDF_INFO_RESPONSE, HKDF_INFO_STREAM};
use crate::e2ee::discovery::{self, Discovery, DiscoveryError};
use base64::Engine;

/// Error type for the E2E handler.
#[derive(Debug)]
pub enum E2EError {
    Discovery(DiscoveryError),
    Crypto(CryptoError),
    Http(reqwest::Error),
    Status(u16, String),
    Parse(String),
    NoNonce,
}

impl std::fmt::Display for E2EError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            E2EError::Discovery(e) => write!(f, "discovery: {e}"),
            E2EError::Crypto(e) => write!(f, "crypto: {e}"),
            E2EError::Http(e) => write!(f, "http: {e}"),
            E2EError::Status(c, b) => write!(f, "status {c}: {b}"),
            E2EError::Parse(m) => write!(f, "parse: {m}"),
            E2EError::NoNonce => write!(f, "no nonce available"),
        }
    }
}

impl std::error::Error for E2EError {}

impl From<DiscoveryError> for E2EError {
    fn from(e: DiscoveryError) -> Self {
        E2EError::Discovery(e)
    }
}
impl From<CryptoError> for E2EError {
    fn from(e: CryptoError) -> Self {
        E2EError::Crypto(e)
    }
}

/// The result of encrypting a request: the blob to POST, the response secret
/// key (for decrypting the response), and the headers to send.
pub struct EncryptedRequest {
    pub blob: Vec<u8>,
    pub response_secret_key: Vec<u8>,
    pub instance_id: String,
    pub nonce: String,
}

/// Encrypt a request for the E2E invoke endpoint.
///
/// `server_pubkey` is the raw 1184-byte ML-KEM-768 public key from the instance.
/// `payload` is the already-translated OpenAI-format JSON body (with
/// `e2e_response_pk` injected).
pub fn prepare_encrypted_request(
    server_pubkey: &[u8],
    payload: &[u8],
    instance_id: String,
    nonce: String,
) -> Result<EncryptedRequest, E2EError> {
    let (blob, response_sk) = crypto::encrypt_request(server_pubkey, payload)?;
    Ok(EncryptedRequest {
        blob,
        response_secret_key: response_sk,
        instance_id,
        nonce,
    })
}

/// Inject the `e2e_response_pk` field into a JSON payload.
///
/// The response public key is base64-encoded and added to the top-level JSON.
pub fn inject_response_pk(payload: &str, response_pk: &[u8]) -> Result<String, E2EError> {
    let mut value: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| E2EError::Parse(e.to_string()))?;
    if let Some(obj) = value.as_object_mut() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(response_pk);
        obj.insert("e2e_response_pk".into(), serde_json::Value::String(encoded));
    }
    serde_json::to_string(&value).map_err(|e| E2EError::Parse(e.to_string()))
}

/// POST the encrypted blob to the E2E invoke endpoint.
///
/// Returns the raw response body (for non-streaming) or the response stream
/// (for streaming). The caller is responsible for decryption.
pub async fn post_e2e_invoke(
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    encrypted: &EncryptedRequest,
    stream: bool,
    original_path: &str,
) -> Result<reqwest::Response, E2EError> {
    let url = format!("{}/e2e/invoke", api_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("X-Chute-Id", chute_id)
        .header("X-Instance-Id", &encrypted.instance_id)
        .header("X-E2E-Nonce", &encrypted.nonce)
        .header("X-E2E-Stream", if stream { "true" } else { "false" })
        .header("X-E2E-Path", original_path)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted.blob.clone())
        .send()
        .await
        .map_err(E2EError::Http)?;
    Ok(resp)
}

/// Decrypt a non-streaming E2E response body.
pub fn decrypt_non_streaming_response(
    response_secret_key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, E2EError> {
    let plaintext = crypto::decrypt_response(response_secret_key, body)?;
    Ok(plaintext)
}

/// Check if a 403 response body indicates a nonce issue (triggering retry).
pub fn is_nonce_403(status: u16, body: &str) -> bool {
    status == 403 && body.to_lowercase().contains("nonce")
}

/// The full E2E request flow: acquire nonce, encrypt, POST, decrypt.
///
/// Handles nonce retry on 403: invalidates cache, re-fetches, retries once.
pub async fn e2e_request(
    discovery: &Discovery,
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    payload: &[u8],
    stream: bool,
    original_path: &str,
) -> Result<E2EResponse, E2EError> {
    // First attempt.
    match e2e_request_once(discovery, client, api_base, api_key, chute_id, payload, stream, original_path).await {
        Ok(resp) => Ok(resp),
        Err(E2EError::Status(403, ref body)) if is_nonce_403(403, body) => {
            // Nonce issue: invalidate cache, re-fetch, retry once.
            log::warn!("E2E 403 nonce error, refreshing and retrying");
            discovery.invalidate().await;
            e2e_request_once(discovery, client, api_base, api_key, chute_id, payload, stream, original_path)
                .await
        }
        Err(e) => Err(e),
    }
}

/// Single attempt of the E2E request flow (no retry).
async fn e2e_request_once(
    discovery: &Discovery,
    client: &reqwest::Client,
    api_base: &str,
    api_key: &str,
    chute_id: &str,
    payload: &[u8],
    stream: bool,
    original_path: &str,
) -> Result<E2EResponse, E2EError> {
    let (instance_id, server_pubkey, nonce) = discovery
        .acquire(chute_id, api_key)
        .await
        .map_err(E2EError::from)?;
    // Generate ephemeral response keypair and inject e2e_response_pk into the payload.
    let response_kp = crypto::generate_response_keypair()?;
    let injected_payload = inject_response_pk(
        std::str::from_utf8(payload).map_err(|e| E2EError::Parse(e.to_string()))?,
        &response_kp.public_key,
    )?;
    let (blob, _response_sk) = crypto::encrypt_request(&server_pubkey, injected_payload.as_bytes())?;
    let encrypted = EncryptedRequest {
        blob,
        response_secret_key: response_kp.secret_key,
        instance_id,
        nonce,
    };
    let resp = post_e2e_invoke(
        client,
        api_base,
        api_key,
        chute_id,
        &encrypted,
        stream,
        original_path,
    )
    .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(E2EError::Status(status.as_u16(), body));
    }
    Ok(E2EResponse {
        response: resp,
        response_secret_key: encrypted.response_secret_key,
    })
}

/// The response from an E2E invoke: the raw reqwest response (for streaming
/// or reading the body) and the secret key to decrypt it.
pub struct E2EResponse {
    pub response: reqwest::Response,
    pub response_secret_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_response_pk_adds_field() {
        let payload = r#"{"model":"test","messages":[]}"#;
        let pk = vec![1u8; 1184];
        let result = inject_response_pk(payload, &pk).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed.get("e2e_response_pk").is_some());
        let encoded = parsed["e2e_response_pk"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn test_inject_response_pk_preserves_existing_fields() {
        let payload = r#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#;
        let pk = vec![2u8; 1184];
        let result = inject_response_pk(payload, &pk).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["model"], "test");
        assert!(parsed.get("e2e_response_pk").is_some());
    }

    #[test]
    fn test_inject_response_pk_invalid_json_returns_error() {
        let payload = "not json";
        let pk = vec![1u8; 1184];
        assert!(inject_response_pk(payload, &pk).is_err());
    }

    #[test]
    fn test_is_nonce_403_detects_nonce_error() {
        assert!(is_nonce_403(403, r#"{"detail":"nonce expired"}"#));
        assert!(is_nonce_403(403, r#"{"detail":"Invalid nonce"}"#));
        assert!(!is_nonce_403(403, r#"{"detail":"forbidden"}"#));
        assert!(!is_nonce_403(401, r#"{"detail":"nonce expired"}"#));
    }

    #[test]
    fn test_prepare_encrypted_request_produces_valid_blob() {
        let server = crypto::generate_response_keypair().unwrap();
        let payload = br#"{"model":"test"}"#;
        let enc = prepare_encrypted_request(
            &server.public_key,
            payload,
            "inst-1".into(),
            "nonce-1".into(),
        )
        .unwrap();
        assert!(enc.blob.len() > 1088 + 12 + 16);
        assert_eq!(enc.instance_id, "inst-1");
        assert_eq!(enc.nonce, "nonce-1");
        assert_eq!(enc.response_secret_key.len(), 64);
    }

    #[tokio::test]
    async fn test_full_e2e_request_cycle_with_mock_backend() {
        // Mock backend that simulates the full E2E flow:
        // 1. /e2e/instances/:chute_id returns instances+nonces
        // 2. /e2e/invoke receives the encrypted blob, decrypts it, re-encrypts
        //    a response, and returns it.
        use axum::{
            body::Bytes,
            extract::Path,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // Server keypair (the TEE instance's key).
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let server_sk = Arc::new(Mutex::new(server_kp.secret_key.clone()));

        let resp_plaintext = br#"{"id":"msg_1","type":"message","content":[{"type":"text","text":"Hello from TEE"}]}"#;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_sk_clone = server_sk.clone();
        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-test-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["nonce-1", "nonce-2"]
            }],
            "nonce_expires_in": 60
        });

        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |_headers: HeaderMap, body: Bytes| {
                    let server_sk = server_sk_clone.clone();
                    async move {
                        use axum::response::IntoResponse;
                        // Decrypt the request blob.
                        let sk = server_sk.lock().await;
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        assert!(req_json.get("e2e_response_pk").is_some());
                        assert_eq!(req_json["model"], "test-model");
                        // Encrypt a response using the client's response_pk.
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let compressed = crypto::gzip_compress(resp_plaintext).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ciphertext =
                            crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"").unwrap();
                        let (ct_part, tag_part) = ciphertext.split_at(ciphertext.len() - 16);
                        let resp_blob = crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            resp_blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });

        // Client side: discovery + e2e_request.
        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test-model","messages":[{"role":"user","content":"hi"}]}"#;
        let result = e2e_request(
            &discovery,
            &client,
            &api_base,
            "test-key",
            "test-chute",
            payload,
            false,
            "/v1/chat/completions",
        )
        .await
        .unwrap();

        let body = result.response.bytes().await.unwrap();
        let decrypted = decrypt_non_streaming_response(&result.response_secret_key, &body).unwrap();
        assert_eq!(decrypted, resp_plaintext);
    }

    #[tokio::test]
    async fn test_e2e_request_retries_on_nonce_403() {
        // Mock backend that returns 403 nonce error on first invoke, then succeeds.
        use axum::{
            body::Bytes,
            extract::State as AxumState,
            http::HeaderMap,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = discovery::base64_encode(&server_kp.public_key);
        let attempt = Arc::new(AtomicU32::new(0));

        let resp_body = serde_json::json!({
            "instances": [{
                "instance_id": "inst-1",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["n1", "n2", "n3", "n4"]
            }],
            "nonce_expires_in": 60
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let attempt_clone = attempt.clone();
        let server_sk = server_kp.secret_key.clone();
        let app = Router::new()
            .route(
                "/e2e/instances/:chute_id",
                get(move || {
                    let body = resp_body.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                post(move |headers: HeaderMap, body: Bytes| {
                    let attempt = attempt_clone.clone();
                    let sk = server_sk.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let n = attempt.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            // First attempt: return 403 nonce error.
                            return (
                                axum::http::StatusCode::FORBIDDEN,
                                [(axum::http::header::CONTENT_TYPE, "application/json")],
                                serde_json::to_vec(
                                    &serde_json::json!({"detail": "nonce expired or invalid"}),
                                )
                                .unwrap(),
                            )
                                .into_response();
                        }
                        // Second attempt: succeed.
                        let req_plaintext = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: serde_json::Value =
                            serde_json::from_slice(&req_plaintext).unwrap();
                        let resp_pk_b64 = req_json["e2e_response_pk"].as_str().unwrap();
                        let resp_pk = discovery::base64_decode(resp_pk_b64).unwrap();
                        let (mlkem_ct, shared_secret) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let salt = &mlkem_ct[..16];
                        let resp_key =
                            crypto::hkdf_sha256(&shared_secret, salt, crypto::HKDF_INFO_RESPONSE)
                                .unwrap();
                        let resp_text = br#"{"ok":true}"#;
                        let compressed = crypto::gzip_compress(resp_text).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ct = crypto::chacha20poly1305_seal(&resp_key, &nonce, &compressed, b"").unwrap();
                        let (ct_part, tag_part) = ct.split_at(ct.len() - 16);
                        let blob = crypto::build_request_blob(&mlkem_ct, &nonce, ct_part, tag_part);
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            blob,
                        )
                            .into_response()
                    }
                }),
            );
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });

        let client = reqwest::Client::new();
        let api_base = format!("http://{}", addr);
        let discovery = Discovery::new(client.clone(), api_base.clone());

        let payload = br#"{"model":"test","messages":[]}"#;
        let result = e2e_request(
            &discovery,
            &client,
            &api_base,
            "key",
            "chute",
            payload,
            false,
            "/v1/chat/completions",
        )
        .await
        .unwrap();

        let body = result.response.bytes().await.unwrap();
        let decrypted = decrypt_non_streaming_response(&result.response_secret_key, &body).unwrap();
        assert_eq!(decrypted, br#"{"ok":true}"#);
        // Verify we retried.
        assert_eq!(attempt.load(Ordering::SeqCst), 2);
    }
}
