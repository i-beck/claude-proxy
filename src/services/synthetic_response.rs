use axum::response::sse::Event;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Send a complete synthetic Claude SSE response with a single text content block.
/// Used for 404 model-not-found, backend errors, etc.
pub async fn send_synthetic_text_response(
    tx: &mpsc::Sender<Event>,
    model: &str,
    content: &str,
    stop_reason: &str,
    input_tokens: u32,
    output_tokens: u32,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let message_obj = json!({
        "id": format!("msg_{}", now),
        "type": "message",
        "role": "assistant",
        "content": json!([]),
        "model": model,
        "stop_reason": Value::Null,
        "stop_sequence": Value::Null,
        "usage": { "input_tokens": input_tokens, "output_tokens": 0 }
    });

    let start = json!({ "type": "message_start", "message": message_obj });
    if tx
        .send(
            Event::default()
                .event("message_start")
                .data(start.to_string()),
        )
        .await
        .is_err()
    {
        return;
    }

    let block_start = json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": { "type": "text", "text": "" }
    });
    if tx
        .send(
            Event::default()
                .event("content_block_start")
                .data(block_start.to_string()),
        )
        .await
        .is_err()
    {
        return;
    }

    let delta = json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": { "type": "text_delta", "text": content }
    });
    if tx
        .send(
            Event::default()
                .event("content_block_delta")
                .data(delta.to_string()),
        )
        .await
        .is_err()
    {
        return;
    }

    let block_stop = json!({ "type": "content_block_stop", "index": 0 });
    if tx
        .send(
            Event::default()
                .event("content_block_stop")
                .data(block_stop.to_string()),
        )
        .await
        .is_err()
    {
        return;
    }

    let msg_delta = json!({
        "type": "message_delta",
        "delta": { "stop_reason": stop_reason, "stop_sequence": Value::Null },
        "usage": { "output_tokens": output_tokens }
    });
    if tx
        .send(
            Event::default()
                .event("message_delta")
                .data(msg_delta.to_string()),
        )
        .await
        .is_err()
    {
        return;
    }

    let msg_stop = json!({ "type": "message_stop" });
    let _ = tx
        .send(
            Event::default()
                .event("message_stop")
                .data(msg_stop.to_string()),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_synthetic_text_response_emits_full_event_sequence() {
        let (tx, mut rx) = mpsc::channel(8);

        send_synthetic_text_response(&tx, "deepseek-r1", "hello world", "end_turn", 12, 7).await;
        drop(tx);

        let mut events = Vec::new();
        while let Some(event) = rx.recv().await {
            events.push(format!("{event:?}"));
        }

        assert_eq!(events.len(), 6);
        assert!(events.iter().any(|event| event.contains("message_start")));
        assert!(events
            .iter()
            .any(|event| event.contains("content_block_delta")));
        assert!(events.iter().any(|event| event.contains("hello world")));
        assert!(events.iter().any(|event| event.contains("end_turn")));
        assert!(events.iter().any(|event| event.contains("message_stop")));
    }

    #[tokio::test]
    async fn test_send_synthetic_text_response_handles_closed_receiver() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        send_synthetic_text_response(&tx, "model", "content", "error", 1, 1).await;
    }

    #[tokio::test]
    async fn test_send_synthetic_text_response_disconnect_after_message_start() {
        // Cover the early return at content_block_start send failure (line 59).
        // With a cap-1 channel the sender is at most one message ahead: send 1
        // (message_start) buffers immediately, send 2 (content_block_start)
        // blocks on the full slot. We hold rx (taking nothing), let send 2
        // block, then drop rx so send 2 fails deterministically.
        let (tx, rx) = mpsc::channel::<Event>(1);
        let mut rx = rx;
        let sender = tokio::spawn(async move {
            send_synthetic_text_response(&tx, "model", "content", "end_turn", 1, 1).await;
        });
        // send 1 buffers; send 2 blocks. Give it a moment to block.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(rx); // send 2 (content_block_start) fails → return at line 59
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sender).await;
    }

    #[tokio::test]
    async fn test_send_synthetic_text_response_disconnect_after_block_start() {
        // Cover the early return at content_block_delta send failure (line 76).
        let (tx, rx) = mpsc::channel::<Event>(1);
        let mut rx = rx;
        let sender = tokio::spawn(async move {
            send_synthetic_text_response(&tx, "model", "content", "end_turn", 1, 1).await;
        });
        let _ = rx.recv().await; // message_start → send 2 buffers, send 3 blocks
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(rx); // send 3 (content_block_delta) fails → return at line 76
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sender).await;
    }

    #[tokio::test]
    async fn test_send_synthetic_text_response_disconnect_after_delta() {
        // Cover the early return at content_block_stop send failure (line 89).
        let (tx, rx) = mpsc::channel::<Event>(1);
        let mut rx = rx;
        let sender = tokio::spawn(async move {
            send_synthetic_text_response(&tx, "model", "content", "end_turn", 1, 1).await;
        });
        let _ = rx.recv().await; // message_start
        let _ = rx.recv().await; // content_block_start → send 4 blocks
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(rx); // send 4 (content_block_stop) fails → return at line 89
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sender).await;
    }

    #[tokio::test]
    async fn test_send_synthetic_text_response_disconnect_after_block_stop() {
        // Cover the early return at message_delta send failure (line 106).
        let (tx, rx) = mpsc::channel::<Event>(1);
        let mut rx = rx;
        let sender = tokio::spawn(async move {
            send_synthetic_text_response(&tx, "model", "content", "end_turn", 1, 1).await;
        });
        let _ = rx.recv().await; // message_start
        let _ = rx.recv().await; // content_block_start
        let _ = rx.recv().await; // content_block_delta → send 5 blocks
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(rx); // send 5 (message_delta) fails → return at line 106
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sender).await;
    }
}
