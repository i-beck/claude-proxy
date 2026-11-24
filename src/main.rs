use axum::{
    routing::{get, post},
    Router,
};
use log::info;
use std::{env, sync::Arc, time::Duration};
use tokio::sync::RwLock;

// Import our modules
mod constants;
mod e2ee;
mod handlers;
mod models;
mod services;
mod utils;

use models::{App, CircuitBreakerState};
use services::model_cache::refresh_models_cache;

#[cfg(test)]
mod test_log;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeConfig {
    backend_url: String,
    backend_host_header: Option<String>,
    backend_timeout_secs: u64,
    circuit_breaker_enabled: bool,
    host_port: u16,
    e2e_enabled: bool,
    e2e_api_base: String,
}

impl RuntimeConfig {
    fn from_env() -> Self {
        Self::from_env_with(|key| env::var(key).ok())
    }

    fn from_env_with(mut get: impl FnMut(&str) -> Option<String>) -> Self {
        Self {
            backend_url: get("BACKEND_URL")
                .unwrap_or_else(|| "http://127.0.0.1:8000/v1/chat/completions".into()),
            backend_host_header: get("BACKEND_HOST_HEADER"),
            backend_timeout_secs: get("BACKEND_TIMEOUT_SECS")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(600),
            circuit_breaker_enabled: get("ENABLE_CIRCUIT_BREAKER")
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(false),
            host_port: get("HOST_PORT")
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(8080),
            e2e_enabled: get("E2E_ENABLED")
                .and_then(|value| value.parse::<bool>().ok())
                .unwrap_or(false),
            e2e_api_base: get("E2E_API_BASE")
                .unwrap_or_else(|| crate::e2ee::attestation::CHUTES_API_BASE.into()),
        }
    }
}

fn build_app(config: &RuntimeConfig) -> App {
    let models_cache = Arc::new(RwLock::new(None));
    let circuit_breaker = Arc::new(RwLock::new(CircuitBreakerState::new(
        config.circuit_breaker_enabled,
    )));

    App {
        client: reqwest::Client::builder()
            .pool_max_idle_per_host(1024)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(config.backend_timeout_secs))
            .build()
            .unwrap(),
        backend_url: config.backend_url.clone(),
        backend_host_header: config.backend_host_header.clone(),
        models_cache,
        circuit_breaker,
        e2e_enabled: config.e2e_enabled,
        e2e_api_base: config.e2e_api_base.clone(),
    }
}

fn build_router(app: App) -> Router {
    // When E2E is enabled, POST /v1/messages is routed to the E2E-aware
    // handler. The E2E handler takes priority: it routes TEE models
    // (`-TEE` suffix) through the encrypted/attested path and falls back to
    // plain HTTP passthrough for non-TEE models and on unrecoverable E2E
    // failure. When disabled, the plain passthrough handler is used directly.
    let messages_route = if app.e2e_enabled {
        post(handlers::messages_e2e)
    } else {
        post(handlers::messages)
    };

    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/v1/messages", messages_route)
        .route("/v1/messages/count_tokens", post(handlers::count_tokens))
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(app)
}

// NOTE: main() is the binary entry point and cannot be unit tested.
// The functions it calls (RuntimeConfig::from_env, build_app, build_router)
// are individually tested in the test module below. The graceful shutdown
// and background cache refresh task are integration concerns tested via
// the shell-based API spec tests (test.sh --all).
#[cfg(not(test))]
#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = RuntimeConfig::from_env();

    info!("🚀 Claude-to-OpenAI Proxy starting...");
    info!("   Backend URL: {}", config.backend_url);
    info!("   Backend Timeout: {}s", config.backend_timeout_secs);
    info!(
        "   Circuit Breaker: {}",
        if config.circuit_breaker_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "   E2E (TEE encryption): {}",
        if config.e2e_enabled {
            format!("enabled (API base {})", config.e2e_api_base)
        } else {
            "disabled".to_string()
        }
    );
    info!("   Mode: Passthrough with case-correction");

    let app = build_app(&config);

    // Initial model cache load (blocking - must complete before accepting requests)
    info!("🔄 Loading initial model cache...");
    if let Err(e) = refresh_models_cache(&app).await {
        log::warn!(
            "⚠️  Failed to load initial model cache: {}. Continuing anyway.",
            e
        );
    }

    // Background model cache refresh (every 60s) with graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let cache_task = {
        let app_clone = app.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = refresh_models_cache(&app_clone).await {
                    log::warn!("Failed to refresh models cache: {}", e);
                }

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        // Continue loop
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🛑 Model cache refresh task shutting down gracefully");
                        break;
                    }
                }
            }
        })
    };

    let router = build_router(app.clone());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.host_port))
        .await
        .unwrap();
    info!("   Listening on: 0.0.0.0:{}", config.host_port);

    // Graceful shutdown: use axum's built-in mechanism
    let server = axum::serve(listener, router).with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        info!("🛑 Received shutdown signal, draining connections...");
    });

    // Run server (this will complete when graceful shutdown finishes)
    if let Err(e) = server.await {
        log::error!("Server error: {}", e);
    }

    // After server is shut down, clean up background tasks
    info!("🧹 Cleaning up background tasks...");
    let _ = shutdown_tx.send(()).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), cache_task).await;
    info!("✅ Shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    #[test]
    fn test_runtime_config_uses_defaults() {
        let config = RuntimeConfig::from_env_with(|_| None);

        assert_eq!(
            config,
            RuntimeConfig {
                backend_url: "http://127.0.0.1:8000/v1/chat/completions".into(),
                backend_host_header: None,
                backend_timeout_secs: 600,
                circuit_breaker_enabled: false,
                host_port: 8080,
                e2e_enabled: false,
                e2e_api_base: "https://api.chutes.ai".into(),
            }
        );
    }

    #[test]
    fn test_runtime_config_respects_overrides_and_fallbacks() {
        let config = RuntimeConfig::from_env_with(|key| match key {
            "BACKEND_URL" => Some("https://example.com/v1/chat/completions".into()),
            "BACKEND_HOST_HEADER" => Some("llm.chutes.ai".into()),
            "BACKEND_TIMEOUT_SECS" => Some("45".into()),
            "ENABLE_CIRCUIT_BREAKER" => Some("true".into()),
            "HOST_PORT" => Some("9090".into()),
            "E2E_ENABLED" => Some("true".into()),
            "E2E_API_BASE" => Some("https://e2e.example.com".into()),
            _ => None,
        });

        assert_eq!(
            config,
            RuntimeConfig {
                backend_url: "https://example.com/v1/chat/completions".into(),
                backend_host_header: Some("llm.chutes.ai".into()),
                backend_timeout_secs: 45,
                circuit_breaker_enabled: true,
                host_port: 9090,
                e2e_enabled: true,
                e2e_api_base: "https://e2e.example.com".into(),
            }
        );

        let fallback_config = RuntimeConfig::from_env_with(|key| match key {
            "BACKEND_TIMEOUT_SECS" => Some("not-a-number".into()),
            "ENABLE_CIRCUIT_BREAKER" => Some("not-a-bool".into()),
            "HOST_PORT" => Some("70000".into()),
            _ => None,
        });
        assert_eq!(fallback_config.e2e_api_base, "https://api.chutes.ai");

        assert_eq!(fallback_config.backend_timeout_secs, 600);
        assert!(!fallback_config.circuit_breaker_enabled);
        assert_eq!(fallback_config.host_port, 8080);
        assert!(!fallback_config.e2e_enabled);
    }

    #[tokio::test]
    async fn test_build_app_uses_runtime_config() {
        let config = RuntimeConfig {
            backend_url: "http://127.0.0.1:9999/v1/chat/completions".into(),
            backend_host_header: Some("llm.chutes.ai".into()),
            backend_timeout_secs: 123,
            circuit_breaker_enabled: true,
            host_port: 8080,
            e2e_enabled: false,
            e2e_api_base: "https://api.chutes.ai".into(),
        };

        let app = build_app(&config);

        assert_eq!(app.backend_url, config.backend_url);
        assert_eq!(app.e2e_api_base, config.e2e_api_base);
        assert!(!app.e2e_enabled);
        assert!(app.models_cache.read().await.is_none());
        assert!(app.circuit_breaker.read().await.enabled);
    }

    #[tokio::test]
    async fn test_build_router_serves_health_and_count_tokens_routes() {
        let app = build_app(&RuntimeConfig::from_env_with(|_| None));
        *app.models_cache.write().await = Some(vec![]);
        let router = build_router(app);

        let health_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_response.status(), StatusCode::OK);

        let count_tokens_response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/count_tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model": "zai-org/GLM-4.5-Air",
                            "messages": [{ "role": "user", "content": "hello" }]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(count_tokens_response.status(), StatusCode::OK);
        let body = to_bytes(count_tokens_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["input_tokens"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_build_router_routes_messages_endpoint() {
        let app = build_app(&RuntimeConfig::from_env_with(|_| None));
        let router = build_router(app);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model": "zai-org/GLM-4.5-Air",
                            "messages": [{ "role": "user", "content": "hi" }],
                            "stream": false
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// When `e2e_enabled` is true, `POST /v1/messages` routes to the E2E-aware
    /// handler (priority over plain passthrough). Proof: with a `-TEE` model,
    /// a valid key, the models cache carrying a `chute_id`, and
    /// `backend_url` unreachable, the request still returns 200 — served by
    /// the E2E mock. Had the router chosen the plain handler instead, the
    /// unreachable backend would have produced 502.
    #[tokio::test]
    async fn test_build_router_e2e_priority_routes_tee_model_through_e2e() {
        use crate::e2ee::crypto;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // ── Minimal ML-KEM E2E mock (discovery + invoke) ────────────────
        let server_kp = crypto::generate_response_keypair().unwrap();
        let server_pk_b64 = crate::e2ee::discovery::base64_encode(&server_kp.public_key);
        let server_sk = Arc::new(Mutex::new(server_kp.secret_key.clone()));

        let instances_body = json!({
            "instances": [{
                "instance_id": "inst-router-e2e",
                "e2e_pubkey": server_pk_b64,
                "nonces": ["n1", "n2", "n3", "n4"]
            }],
            "nonce_expires_in": 60
        });

        let mock = axum::Router::new()
            .route(
                "/e2e/instances/:chute_id",
                axum::routing::get(move || {
                    let body = instances_body.clone();
                    async move { axum::Json(body) }
                }),
            )
            .route(
                "/e2e/invoke",
                axum::routing::post(move |_h: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let sk = server_sk.clone();
                    async move {
                        use axum::response::IntoResponse;
                        let sk = sk.lock().await;
                        let req_plain = crypto::decrypt_request_blob(&sk, &body).unwrap();
                        let req_json: Value = serde_json::from_slice(&req_plain).unwrap();
                        let resp_pk = crate::e2ee::discovery::base64_decode(
                            req_json["e2e_response_pk"].as_str().unwrap(),
                        )
                        .unwrap();
                        let (mlkem_ct, shared) =
                            crypto::encapsulate_against_server_pubkey(&resp_pk).unwrap();
                        let key = crypto::hkdf_sha256(
                            &shared,
                            &mlkem_ct[..16],
                            crypto::HKDF_INFO_RESPONSE,
                        )
                        .unwrap();
                        let oai_resp = json!({
                            "id": "chatcmpl-r",
                            "object": "chat.completion",
                            "model": "Vendor/Foo-TEE",
                            "choices": [{
                                "index": 0,
                                "message": { "role": "assistant", "content": "via E2E router" },
                                "finish_reason": "stop"
                            }],
                            "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
                        });
                        let compressed =
                            crypto::gzip_compress(oai_resp.to_string().as_bytes()).unwrap();
                        let nonce = crypto::random_bytes(12);
                        let ct =
                            crypto::chacha20poly1305_seal(&key, &nonce, &compressed, b"").unwrap();
                        let (c, t) = ct.split_at(ct.len() - 16);
                        let blob = crypto::build_request_blob(&mlkem_ct, &nonce, c, t);
                        (
                            StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                            blob,
                        )
                            .into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let e2e_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, mock).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ── App: E2E enabled, backend_url unreachable (proves E2E served) ──
        let config = RuntimeConfig::from_env_with(|key| match key {
            "E2E_ENABLED" => Some("true".into()),
            "E2E_API_BASE" => Some(format!("http://{e2e_addr}")),
            _ => None,
        });
        let app = build_app(&config);
        assert!(app.e2e_enabled);
        *app.models_cache.write().await = Some(vec![models::ModelInfo {
            id: "Vendor/Foo-TEE".into(),
            input_price_usd: None,
            output_price_usd: None,
            supported_features: vec![],
            chute_id: Some("chute-router-tee".into()),
        }]);
        let router = build_router(app);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-key")
                    .body(Body::from(
                        json!({
                            "model": "Vendor/Foo-TEE",
                            "messages": [{ "role": "user", "content": "hi" }],
                            "stream": false
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "E2E mock must have served the request (200); a plain-handler route \
             would have hit the unreachable backend (502)"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["content"][0]["text"], "via E2E router");
    }

    #[test]
    fn test_runtime_config_from_env_returns_defaults() {
        // Ensure no proxy-specific env vars are set so defaults are used.
        std::env::remove_var("BACKEND_URL");
        std::env::remove_var("BACKEND_HOST_HEADER");
        std::env::remove_var("BACKEND_TIMEOUT_SECS");
        std::env::remove_var("ENABLE_CIRCUIT_BREAKER");
        std::env::remove_var("HOST_PORT");
        std::env::remove_var("E2E_ENABLED");
        std::env::remove_var("E2E_API_BASE");

        let config = RuntimeConfig::from_env();
        assert_eq!(
            config.backend_url,
            "http://127.0.0.1:8000/v1/chat/completions"
        );
        assert_eq!(config.backend_timeout_secs, 600);
        assert!(!config.circuit_breaker_enabled);
        assert_eq!(config.host_port, 8080);
        assert!(!config.e2e_enabled);
        assert_eq!(config.e2e_api_base, "https://api.chutes.ai");
    }
}
