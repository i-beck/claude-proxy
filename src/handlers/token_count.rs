use crate::models::{App, ClaudeTokenCountRequest};
use crate::utils::content_extraction::count_input_tokens;
use axum::{extract::State, http::StatusCode, response::Result};
use serde_json::{json, Value};

/// Count tokens using tiktoken (cl100k_base encoding baseline)
pub async fn count_tokens(
    State(_app): State<App>,
    axum::Json(req): axum::Json<ClaudeTokenCountRequest>,
) -> Result<axum::Json<Value>, (StatusCode, &'static str)> {
    let token_count = tokio::task::spawn_blocking(move || {
        count_input_tokens(&req.messages, &req.system, &req.tools)
    })
    .await
    // count_input_tokens never panics, so spawn_blocking's JoinError (panic
    // propagation) cannot occur in practice.  Using expect() keeps the
    // defensive message without an llvm-cov-unreachable closure arm.
    .expect("count_input_tokens never panics");

    Ok(axum::Json(json!({ "input_tokens": token_count })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{App, CircuitBreakerState, ClaudeMessage};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_app() -> App {
        App {
            client: reqwest::Client::new(),
            backend_url: "http://127.0.0.1:8000/v1/chat/completions".into(),
            backend_host_header: None,
            e2e_enabled: false,
            e2e_api_base: "https://api.chutes.ai".into(),
            models_cache: Arc::new(RwLock::new(None)),
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::new(false))),
        }
    }

    #[tokio::test]
    async fn test_count_tokens_returns_positive_count() {
        let app = test_app();
        let request = ClaudeTokenCountRequest {
            model: "zai-org/GLM-4.5-Air".into(),
            messages: vec![ClaudeMessage {
                role: "user".into(),
                content: json!("hello from a test"),
            }],
            system: None,
            tools: None,
        };

        let axum::Json(body) = count_tokens(State(app), axum::Json(request)).await.unwrap();
        assert!(body["input_tokens"].as_u64().unwrap() > 0);
    }
    #[tokio::test]
    async fn test_count_tokens_with_system_prompt() {
        let app = test_app();
        let request = ClaudeTokenCountRequest {
            model: "zai-org/GLM-4.5-Air".into(),
            messages: vec![ClaudeMessage {
                role: "user".into(),
                content: json!("hello"),
            }],
            system: Some(json!("You are a helpful assistant")),
            tools: None,
        };
        let axum::Json(body) = count_tokens(State(app), axum::Json(request)).await.unwrap();
        assert!(body["input_tokens"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_count_tokens_with_tools() {
        let app = test_app();
        let request = ClaudeTokenCountRequest {
            model: "zai-org/GLM-4.5-Air".into(),
            messages: vec![ClaudeMessage {
                role: "user".into(),
                content: json!("use a tool"),
            }],
            system: None,
            tools: Some(vec![crate::models::ClaudeTool {
                name: "calculator".into(),
                description: Some("A calculator".into()),
                input_schema: json!({"type": "object", "properties": {"expr": {"type": "string"}}}),
            }]),
        };
        let axum::Json(body) = count_tokens(State(app), axum::Json(request)).await.unwrap();
        assert!(body["input_tokens"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_count_tokens_empty_messages() {
        let app = test_app();
        let request = ClaudeTokenCountRequest {
            model: "zai-org/GLM-4.5-Air".into(),
            messages: vec![],
            system: None,
            tools: None,
        };
        let axum::Json(body) = count_tokens(State(app), axum::Json(request)).await.unwrap();
        // Empty messages → zero tokens
        assert_eq!(body["input_tokens"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_count_tokens_with_multimodal_content() {
        let app = test_app();
        let request = ClaudeTokenCountRequest {
            model: "zai-org/GLM-4.5-Air".into(),
            messages: vec![ClaudeMessage {
                role: "user".into(),
                content: json!([
                    {"type": "text", "text": "what is this?"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}
                ]),
            }],
            system: None,
            tools: None,
        };
        let axum::Json(body) = count_tokens(State(app), axum::Json(request)).await.unwrap();
        // Should include image tokens (85 per image)
        assert!(body["input_tokens"].as_u64().unwrap() > 85);
    }
}
