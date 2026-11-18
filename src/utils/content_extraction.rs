use crate::constants::*;
use serde_json::{json, Value};

/// Count input tokens for a Claude request using tiktoken (cl100k_base).
/// Falls back to character-based estimation if tiktoken init fails.
pub fn count_input_tokens(
    messages: &[crate::models::ClaudeMessage],
    system: &Option<Value>,
    tools: &Option<Vec<crate::models::ClaudeTool>>,
) -> u32 {
    let mut text_parts = Vec::new();
    let mut image_count = 0;

    if let Some(sys) = system {
        let sys_text = match sys {
            Value::String(s) => s.clone(),
            _ => serde_json::to_string(sys).unwrap_or_default(),
        };
        if !sys_text.is_empty() {
            text_parts.push(sys_text);
        }
    }

    for msg in messages {
        let (msg_text, msg_image_count) = extract_text_from_content(&msg.content);
        if !msg_text.is_empty() {
            text_parts.push(format!("{}: {}", msg.role, msg_text));
        }
        image_count += msg_image_count;
    }

    if let Some(tools) = tools {
        for tool in tools {
            text_parts.push(tool.name.clone());
            if let Some(desc) = &tool.description {
                text_parts.push(desc.clone());
            }
            // serde_json::to_string on a Value never fails; unwrap_or_default avoids
            // an unreachable `if let Ok` false branch.
            let schema_str = serde_json::to_string(&tool.input_schema).unwrap_or_default();
            text_parts.push(schema_str);
        }
    }

    let combined_text = text_parts.join("\n");

    match tiktoken_rs::cl100k_base() {
        Ok(encoder) => {
            let text_tokens = encoder.encode_with_special_tokens(&combined_text).len();
            let image_tokens = image_count * TOKENS_PER_IMAGE;
            (text_tokens + image_tokens) as u32
        }
        // coverage: unreachable — tiktoken_rs::cl100k_base() always returns Ok in practice;
        // the Err branch is a defensive fallback that never triggers
        Err(_) => estimate_tokens_fallback(&combined_text, image_count),
    }
}

/// Estimate token count from text length and image count when tiktoken
/// is unavailable. Uses character-based approximation (4 chars ≈ 1 token).
/// Extracted from count_input_tokens so the fallback logic is independently
/// testable even though the Err branch of cl100k_base() never triggers.
fn estimate_tokens_fallback(combined_text: &str, image_count: usize) -> u32 {
    let text_estimate = std::cmp::max(1, combined_text.len() / CHARS_PER_TOKEN);
    let image_tokens = image_count * TOKENS_PER_IMAGE;
    (text_estimate + image_tokens) as u32
}

/// Extract text content from Claude content value (string or array of blocks)
/// Returns tuple: (text_content, image_count)
pub fn extract_text_from_content(content: &Value) -> (String, usize) {
    if let Some(s) = content.as_str() {
        return (s.to_string(), 0);
    }
    if let Some(blocks) = content.as_array() {
        let mut texts: Vec<String> = Vec::new();
        let mut image_count = 0;
        for block in blocks {
            if let Some(obj) = block.as_object() {
                let block_type = obj.get("type").and_then(|t| t.as_str());
                match block_type {
                    Some("text") => {
                        if let Some(text) = obj.get("text").and_then(|t| t.as_str()) {
                            texts.push(text.to_string());
                        }
                    }
                    Some("image") => {
                        image_count += 1;
                    }
                    Some("document") => {
                        // Documents are roughly equivalent to images for token estimation
                        // A full page PDF is ~1500 tokens, but we use image constant as baseline
                        image_count += 1;
                    }
                    Some("tool_result") => {
                        if let Some(result_content) = obj.get("content") {
                            if let Some(text) = result_content.as_str() {
                                texts.push(text.to_string());
                            } else if let Some(arr) = result_content.as_array() {
                                for item in arr {
                                    if let Some(text_obj) = item.as_object() {
                                        if text_obj.get("type").and_then(|t| t.as_str())
                                            == Some("text")
                                        {
                                            if let Some(text) =
                                                text_obj.get("text").and_then(|t| t.as_str())
                                            {
                                                texts.push(text.to_string());
                                            }
                                        }
                                    } else if let Some(text) = item.as_str() {
                                        texts.push(text.to_string());
                                    }
                                }
                            }
                        }
                    }
                    Some("tool_use") => {
                        if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
                            texts.push(name.to_string());
                        }
                        if let Some(input) = obj.get("input") {
                            // serde_json::to_string on a Value never fails.
                            let input_str = serde_json::to_string(input).unwrap_or_default();
                            texts.push(input_str);
                        }
                    }
                    _ => {}
                }
            } else if let Some(s) = block.as_str() {
                texts.push(s.to_string());
            }
        }
        return (texts.join("\n"), image_count);
    }
    (String::new(), 0)
}

/// Convert Claude system prompt value (string or array of blocks) into OpenAI system content
pub fn convert_system_content(sys: &Value) -> Value {
    if sys.is_string() {
        sys.clone()
    } else if let Some(blocks) = sys.as_array() {
        let combined_text = blocks
            .iter()
            .filter_map(|block| block.as_object())
            .filter(|obj| obj.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|obj| obj.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        serde_json::json!(combined_text)
    } else {
        sys.clone()
    }
}

/// Serialize tool_result content to a string for OpenAI
pub fn serialize_tool_result_content(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(arr) = content.as_array() {
        let parts: Vec<String> = arr
            .iter()
            .filter_map(|item| {
                if let Some(obj) = item.as_object() {
                    if obj.get("type").and_then(|t| t.as_str()) == Some("text") {
                        obj.get("text").and_then(|t| t.as_str()).map(String::from)
                    } else {
                        Some(serde_json::to_string(item).unwrap_or_else(|_| "{}".into()))
                    }
                } else if let Some(s) = item.as_str() {
                    Some(s.to_string())
                } else {
                    Some(serde_json::to_string(item).unwrap_or_else(|_| "{}".into()))
                }
            })
            .collect();
        return parts.join("\n");
    }
    serde_json::to_string(content).unwrap_or_else(|_| "{}".into())
}

/// Build OpenAI tools array from Claude tools.
/// Returns None when no tools are provided (avoids sending empty tools array to backend).
pub fn build_oai_tools(
    tools: Option<Vec<crate::models::ClaudeTool>>,
) -> Option<Vec<crate::models::OAITool>> {
    match tools {
        Some(ts) if !ts.is_empty() => Some(
            ts.into_iter()
                .map(|t| crate::models::OAITool {
                    type_: "function".into(),
                    function: crate::models::OAIFunction {
                        name: t.name,
                        description: t.description,
                        parameters: t.input_schema,
                    },
                })
                .collect::<Vec<_>>(),
        ),
        _ => None,
    }
}

/// Convert Claude `tool_choice` schema to OpenAI-compatible values.
/// Returns (tool_choice_value, parallel_tool_calls_bool)
pub fn convert_tool_choice(tool_choice: Option<Value>) -> (Option<Value>, Option<bool>) {
    let Some(choice) = tool_choice else {
        return (None, None);
    };

    match choice {
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "auto" => (Some(Value::String("auto".into())), None),
            "none" => (Some(Value::String("none".into())), None),
            "any" => {
                log::info!("🔧 tool_choice: 'any' → 'required' for OpenAI compatibility");
                (Some(Value::String("required".into())), None)
            }
            "required" => (Some(Value::String("required".into())), None),
            other => {
                log::warn!("⚠️ Unknown string tool_choice '{}'; passing through", other);
                (Some(Value::String(s)), None)
            }
        },
        Value::Object(obj) => {
            let parallel_disabled = if let Some(val) = obj.get("disable_parallel_tool_use") {
                val.as_bool().map(|b| !b) // if disable=true, parallel=false
            } else {
                None
            };

            let Some(kind) = obj.get("type").and_then(|v| v.as_str()) else {
                log::warn!("⚠️ tool_choice object missing 'type'; passing through");
                return (Some(Value::Object(obj)), parallel_disabled);
            };
            match kind.to_ascii_lowercase().as_str() {
                "tool" => {
                    let name = obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .or_else(|| obj.get("tool_name").and_then(|v| v.as_str()));
                    if let Some(name) = name {
                        log::info!(
                            "🔧 tool_choice: forcing tool '{}' via function format",
                            name
                        );
                        (
                            Some(json!({
                                "type": "function",
                                "function": { "name": name }
                            })),
                            parallel_disabled,
                        )
                    } else {
                        log::warn!("⚠️ tool_choice 'tool' missing 'name'; dropping constraint");
                        (None, parallel_disabled)
                    }
                }
                "function" => (Some(Value::Object(obj)), parallel_disabled),
                "auto" => (Some(Value::String("auto".into())), parallel_disabled),
                "none" => (Some(Value::String("none".into())), parallel_disabled),
                "any" => {
                    log::info!("🔧 tool_choice: type 'any' → 'required'");
                    (Some(Value::String("required".into())), parallel_disabled)
                }
                "required" => (Some(Value::String("required".into())), parallel_disabled),
                other => {
                    log::warn!("⚠️ Unknown tool_choice type '{}'; passing through", other);
                    (Some(Value::Object(obj)), parallel_disabled)
                }
            }
        }
        other => {
            log::warn!(
                "⚠️ tool_choice should be string or object; received {:?}, passing through",
                other
            );
            (Some(other), None)
        }
    }
}

/// Translate OpenAI finish_reason to Claude stop_reason
pub fn translate_finish_reason(oai_reason: Option<&str>) -> &'static str {
    match oai_reason {
        Some("stop") => "end_turn",
        Some("length") => "max_tokens",
        Some("tool_calls") | Some("function_call") => "tool_use",
        Some("content_filter") => "end_turn", // No direct equivalent
        Some("error") => "error",
        Some(other) => {
            log::debug!("⚠️  Unknown finish_reason '{}', using 'end_turn'", other);
            "end_turn"
        }
        None => "end_turn",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ============================================================================
    // extract_text_from_content tests
    // ============================================================================

    #[test]
    fn test_extract_text_simple_string() {
        let content = json!("Hello, world!");
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Hello, world!");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_empty_string() {
        let content = json!("");
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_single_text_block() {
        let content = json!([
            {"type": "text", "text": "This is a test"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "This is a test");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_multiple_text_blocks() {
        let content = json!([
            {"type": "text", "text": "First block"},
            {"type": "text", "text": "Second block"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "First block\nSecond block");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_with_image() {
        let content = json!([
            {"type": "text", "text": "Description"},
            {"type": "image", "source": {"type": "base64", "data": "..."}}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Description");
        assert_eq!(images, 1);
    }

    #[test]
    fn test_extract_text_multiple_images() {
        let content = json!([
            {"type": "image", "source": {}},
            {"type": "text", "text": "Between images"},
            {"type": "image", "source": {}}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Between images");
        assert_eq!(images, 2);
    }

    #[test]
    fn test_extract_text_counts_document_as_multimodal_input() {
        let content = json!([
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "ZmFrZQ=="}},
            {"type": "text", "text": "Attached document"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Attached document");
        assert_eq!(images, 1);
    }

    #[test]
    fn test_extract_text_tool_use() {
        let content = json!([
            {"type": "tool_use", "name": "calculator", "input": {"a": 1, "b": 2}}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert!(text.contains("calculator"));
        assert!(text.contains(r#""a":1"#) || text.contains(r#""a": 1"#));
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_string() {
        let content = json!([
            {"type": "tool_result", "content": "Result text"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Result text");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_array() {
        let content = json!([
            {
                "type": "tool_result",
                "content": [
                    {"type": "text", "text": "First"},
                    {"type": "text", "text": "Second"}
                ]
            }
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "First\nSecond");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_unknown_block_type() {
        let content = json!([
            {"type": "unknown", "data": "ignored"},
            {"type": "text", "text": "Visible"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "Visible");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_null() {
        let content = json!(null);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_empty_array() {
        let content = json!([]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_block_missing_text_field() {
        // Line 78: text block without a "text" field → `if let Some(text)` is false.
        let content = json!([{"type": "text"}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_block_text_not_string() {
        // Line 78: text block where "text" is not a string → `if let Some(text)` is false.
        let content = json!([{"type": "text", "text": 42}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_array_item_missing_text_field() {
        // Line 102: tool_result content array item typed "text" but without a "text" field.
        let content = json!([
            {"type": "tool_result", "content": [
                {"type": "text"},
                {"type": "text", "text": "visible"}
            ]}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "visible");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_no_content_field() {
        // Line 109: tool_result block without a "content" field → `if let Some` is false.
        let content = json!([
            {"type": "tool_result", "tool_use_id": "tool_1"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_use_no_name() {
        // Line 114: tool_use block without a "name" field → `if let Some(name)` is false.
        let content = json!([
            {"type": "tool_use", "input": {"a": 1}}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert!(text.contains("\"a\":1") || text.contains("\"a\": 1"));
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_use_no_input() {
        // Lines 118-119: tool_use block without an "input" field → `if let Some(input)` is false.
        let content = json!([
            {"type": "tool_use", "name": "calculator"}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "calculator");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_array_with_bare_string() {
        // Line 125: array containing a bare string element (not an object) → `else if let Some(s)`.
        let content = json!(["a bare string", {"type": "text", "text": "block"}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "a bare string\nblock");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_array_with_non_string_non_object_element() {
        // Line 133: array element that is neither an object nor a string (e.g. a number)
        // → both `block.as_object()` and `block.as_str()` are None → the else-if false branch.
        let content = json!([42, {"type": "text", "text": "block"}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "block");
        assert_eq!(images, 0);
    }

    // ============================================================================
    // convert_system_content tests
    // ============================================================================

    #[test]
    fn test_convert_system_simple_string() {
        let system = json!("You are a helpful assistant");
        let result = convert_system_content(&system);
        assert_eq!(result, json!("You are a helpful assistant"));
    }

    #[test]
    fn test_convert_system_empty_string() {
        let system = json!("");
        let result = convert_system_content(&system);
        assert_eq!(result, json!(""));
    }

    #[test]
    fn test_convert_system_single_block() {
        let system = json!([
            {"type": "text", "text": "System instruction"}
        ]);
        let result = convert_system_content(&system);
        assert_eq!(result, json!("System instruction"));
    }

    #[test]
    fn test_convert_system_multiple_blocks() {
        let system = json!([
            {"type": "text", "text": "First instruction"},
            {"type": "text", "text": "Second instruction"}
        ]);
        let result = convert_system_content(&system);
        assert_eq!(result, json!("First instruction\nSecond instruction"));
    }

    #[test]
    fn test_convert_system_mixed_blocks() {
        let system = json!([
            {"type": "text", "text": "Visible"},
            {"type": "image", "data": "ignored"},
            {"type": "text", "text": "Also visible"}
        ]);
        let result = convert_system_content(&system);
        assert_eq!(result, json!("Visible\nAlso visible"));
    }

    #[test]
    fn test_convert_system_empty_array() {
        let system = json!([]);
        let result = convert_system_content(&system);
        assert_eq!(result, json!(""));
    }

    #[test]
    fn test_convert_system_null() {
        let system = json!(null);
        let result = convert_system_content(&system);
        assert_eq!(result, json!(null));
    }

    // ============================================================================
    // serialize_tool_result_content tests
    // ============================================================================

    #[test]
    fn test_serialize_tool_result_simple_string() {
        let content = json!("Success");
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "Success");
    }

    #[test]
    fn test_serialize_tool_result_empty_string() {
        let content = json!("");
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "");
    }

    #[test]
    fn test_serialize_tool_result_array_of_text() {
        let content = json!([
            {"type": "text", "text": "Line 1"},
            {"type": "text", "text": "Line 2"}
        ]);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "Line 1\nLine 2");
    }

    #[test]
    fn test_serialize_tool_result_array_of_strings() {
        let content = json!(["First", "Second", "Third"]);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "First\nSecond\nThird");
    }

    #[test]
    fn test_serialize_tool_result_mixed_array() {
        let content = json!([
            "Plain string",
            {"type": "text", "text": "Text block"}
        ]);
        let result = serialize_tool_result_content(&content);
        assert!(result.contains("Plain string"));
        assert!(result.contains("Text block"));
    }

    #[test]
    fn test_serialize_tool_result_complex_object() {
        let content = json!({"result": "success", "data": [1, 2, 3]});
        let result = serialize_tool_result_content(&content);
        assert!(result.contains("result"));
        assert!(result.contains("success"));
    }

    #[test]
    fn test_serialize_tool_result_empty_array() {
        let content = json!([]);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "");
    }

    // ============================================================================
    // convert_tool_choice tests
    // ============================================================================

    #[test]
    fn test_convert_tool_choice_string_auto() {
        let (result, parallel) = convert_tool_choice(Some(json!("auto")));
        assert_eq!(result, Some(json!("auto")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_string_any() {
        let (result, parallel) = convert_tool_choice(Some(json!("any")));
        assert_eq!(result, Some(json!("required")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_tool_object() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "tool",
            "name": "calculator"
        })));
        assert_eq!(
            result,
            Some(json!({
                "type": "function",
                "function": { "name": "calculator" }
            }))
        );
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_auto_object() {
        let (result, parallel) = convert_tool_choice(Some(json!({ "type": "auto" })));
        assert_eq!(result, Some(json!("auto")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_invalid_tool() {
        let (result, parallel) = convert_tool_choice(Some(json!({ "type": "tool" })));
        assert_eq!(result, None);
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_disable_parallel() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "auto",
            "disable_parallel_tool_use": true
        })));
        assert_eq!(result, Some(json!("auto")));
        assert_eq!(parallel, Some(false));
    }

    // ============================================================================
    // translate_finish_reason tests
    // ============================================================================

    #[test]
    fn test_translate_finish_reason_stop() {
        assert_eq!(translate_finish_reason(Some("stop")), "end_turn");
    }

    #[test]
    fn test_translate_finish_reason_length() {
        assert_eq!(translate_finish_reason(Some("length")), "max_tokens");
    }

    #[test]
    fn test_translate_finish_reason_tool_calls() {
        assert_eq!(translate_finish_reason(Some("tool_calls")), "tool_use");
    }

    #[test]
    fn test_translate_finish_reason_function_call() {
        assert_eq!(translate_finish_reason(Some("function_call")), "tool_use");
    }

    #[test]
    fn test_translate_finish_reason_content_filter() {
        assert_eq!(translate_finish_reason(Some("content_filter")), "end_turn");
    }

    #[test]
    fn test_translate_finish_reason_error() {
        assert_eq!(translate_finish_reason(Some("error")), "error");
    }

    #[test]
    fn test_translate_finish_reason_unknown() {
        assert_eq!(translate_finish_reason(Some("unknown_reason")), "end_turn");
    }

    #[test]
    fn test_translate_finish_reason_none() {
        assert_eq!(translate_finish_reason(None), "end_turn");
    }

    #[test]
    fn test_translate_finish_reason_empty_string() {
        assert_eq!(translate_finish_reason(Some("")), "end_turn");
    }

    // ============================================================================
    // count_input_tokens tests (system prompt + tools branches)
    // ============================================================================

    #[test]
    fn test_count_input_tokens_includes_non_empty_string_system() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hi"),
        }];
        let count_with_system = count_input_tokens(&messages, &Some(json!("You are helpful")), &None);
        let count_without = count_input_tokens(&messages, &None, &None);
        assert!(count_with_system > count_without);
    }

    #[test]
    fn test_count_input_tokens_includes_non_string_system() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hi"),
        }];
        // System as an array of blocks (non-string Value) exercises the to_string branch.
        let count = count_input_tokens(
            &messages,
            &Some(json!([{"type": "text", "text": "system rule"}])),
            &None,
        );
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_includes_tools() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hi"),
        }];
        let tools = vec![crate::models::ClaudeTool {
            name: "calculator".into(),
            description: Some("A calculator".into()),
            input_schema: json!({"type": "object", "properties": {"expr": {"type": "string"}}}),
        }];
        let count_with_tools = count_input_tokens(&messages, &None, &Some(tools));
        let count_without = count_input_tokens(&messages, &None, &None);
        assert!(count_with_tools > count_without);
    }

    // ============================================================================
    // extract_text_from_content — additional branches
    // ============================================================================

    #[test]
    fn test_extract_text_tool_result_array_with_non_text_objects() {
        // tool_result content array with a non-text object block (uses to_string fallback)
        let content = json!([
            {
                "type": "tool_result",
                "content": [
                    {"type": "image", "source": {"data": "..."}},
                    {"type": "text", "text": "visible"}
                ]
            }
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert!(text.contains("visible"));
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_array_with_string_items() {
        let content = json!([
            {
                "type": "tool_result",
                "content": ["plain string in array", "another"]
            }
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert!(text.contains("plain string in array"));
        assert!(text.contains("another"));
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_array_with_bare_string_items() {
        // Array containing plain strings (not objects) — exercises block.as_str() branch
        let content = json!(["just a string", "second string"]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "just a string\nsecond string");
        assert_eq!(images, 0);
    }

    // ============================================================================
    // serialize_tool_result_content — additional branches
    // ============================================================================

    #[test]
    fn test_serialize_tool_result_array_with_non_text_object() {
        let content = json!([
            {"type": "image", "source": {"data": "..."}}
        ]);
        let result = serialize_tool_result_content(&content);
        // Non-text object is JSON-serialized via to_string fallback
        assert!(result.contains("image"));
    }

    #[test]
    fn test_serialize_tool_result_array_with_number() {
        let content = json!([42, "text"]);
        let result = serialize_tool_result_content(&content);
        assert!(result.contains("42"));
        assert!(result.contains("text"));
    }

    // ============================================================================
    // convert_tool_choice — additional branches
    // ============================================================================

    #[test]
    fn test_convert_tool_choice_string_none() {
        let (result, parallel) = convert_tool_choice(Some(json!("none")));
        assert_eq!(result, Some(json!("none")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_string_required() {
        let (result, parallel) = convert_tool_choice(Some(json!("required")));
        assert_eq!(result, Some(json!("required")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_string_unknown() {
        let (result, parallel) = convert_tool_choice(Some(json!("weird")));
        assert_eq!(result, Some(json!("weird")));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_object_missing_type() {
        let (result, parallel) = convert_tool_choice(Some(json!({"disable_parallel_tool_use": true})));
        assert_eq!(result, Some(json!({"disable_parallel_tool_use": true})));
        assert_eq!(parallel, Some(false));
    }

    #[test]
    fn test_convert_tool_choice_object_tool_with_tool_name_alias() {
        let (result, _parallel) = convert_tool_choice(Some(json!({
            "type": "tool",
            "tool_name": "my_tool"
        })));
        assert_eq!(
            result,
            Some(json!({"type": "function", "function": {"name": "my_tool"}}))
        );
    }

    #[test]
    fn test_convert_tool_choice_object_function() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "function",
            "function": {"name": "foo"}
        })));
        assert_eq!(result, Some(json!({"type": "function", "function": {"name": "foo"}})));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_object_none() {
        let (result, _parallel) = convert_tool_choice(Some(json!({"type": "none"})));
        assert_eq!(result, Some(json!("none")));
    }

    #[test]
    fn test_convert_tool_choice_object_any() {
        let (result, _parallel) = convert_tool_choice(Some(json!({"type": "any"})));
        assert_eq!(result, Some(json!("required")));
    }

    #[test]
    fn test_convert_tool_choice_object_required() {
        let (result, _parallel) = convert_tool_choice(Some(json!({"type": "required"})));
        assert_eq!(result, Some(json!("required")));
    }

    #[test]
    fn test_convert_tool_choice_object_unknown_type() {
        let (result, _parallel) = convert_tool_choice(Some(json!({"type": "weird"})));
        assert_eq!(result, Some(json!({"type": "weird"})));
    }

    #[test]
    fn test_convert_tool_choice_non_string_non_object() {
        let (result, parallel) = convert_tool_choice(Some(json!(42)));
        assert_eq!(result, Some(json!(42)));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_count_input_tokens_with_non_string_system() {
        // Line 21: system as non-string JSON object
        let messages = vec![];
        let system = Some(json!({"key": "value"}));
        let count = count_input_tokens(&messages, &system, &None);
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_with_empty_string_system() {
        // Line 19-20: system is empty string → not added to text_parts
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hello"),
        }];
        let system = Some(json!(""));
        let count = count_input_tokens(&messages, &system, &None);
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_with_tools_with_description() {
        // Line 37: tool with description
        let messages = vec![];
        let tools = Some(vec![crate::models::ClaudeTool {
            name: "my_tool".into(),
            description: Some("A test tool".into()),
            input_schema: json!({"type": "object"}),
        }]);
        let count = count_input_tokens(&messages, &None, &tools);
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_with_tools_without_description() {
        // Line 40: tool without description (None)
        let messages = vec![];
        let tools = Some(vec![crate::models::ClaudeTool {
            name: "my_tool".into(),
            description: None,
            input_schema: json!({"type": "object"}),
        }]);
        let count = count_input_tokens(&messages, &None, &tools);
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_includes_image_tokens() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!([
                {"type": "text", "text": "describe this"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}},
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "ZmFrZQ=="}}
            ]),
        }];
        let count = count_input_tokens(&messages, &None, &None);
        // Should include image tokens (2 images × 85 = 170) plus text tokens
        assert!(count >= 170);
    }

    #[test]
    fn test_extract_text_from_content_tool_result_object_items() {
        // Line 100-104, 106-107: tool_result with array of objects and non-text items
        let content = json!([
            {"type": "tool_result", "content": [
                {"type": "image", "source": {}},
                {"type": "text", "text": "visible text"}
            ]}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert!(text.contains("visible text"));
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_from_content_tool_result_with_string_array() {
        // Line 112, 116-117: tool_result with array of plain strings
        let content = json!([
            {"type": "tool_result", "content": ["raw string", "another"]}
        ]);
        let (text, _) = extract_text_from_content(&content);
        assert!(text.contains("raw string"));
        assert!(text.contains("another"));
    }

    #[test]
    fn test_extract_text_from_content_tool_result_non_text_non_string() {
        // Line 123: tool_result with items that are neither objects nor strings
        let content = json!([
            {"type": "tool_result", "content": [42, true]}
        ]);
        let (text, _) = extract_text_from_content(&content);
        // Numbers and bools in array — they're not text type and not strings
        // so they're skipped via the else branch at line 102 (as_str returns None)
        // Actually these are primitives, so block.as_object() is None and block.as_str() is None
        // so nothing is extracted
        assert_eq!(text, "");
    }

    #[test]
    fn test_extract_text_from_content_tool_result_empty_content() {
        // tool_result with empty content field
        let content = json!([
            {"type": "tool_result", "content": json!(null)}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_from_content_tool_result_empty_array() {
        // tool_result with empty array content
        let content = json!([
            {"type": "tool_result", "content": []}
        ]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_from_content_tool_use_without_name() {
        // tool_use block with missing name field
        let content = json!([
            {"type": "tool_use", "input": {"a": 1}}
        ]);
        let (text, _) = extract_text_from_content(&content);
        // name is missing, so only input is extracted
        assert!(text.contains("\"a\""));
    }

    #[test]
    fn test_extract_text_from_content_tool_use_without_input() {
        // tool_use block with missing input field
        let content = json!([
            {"type": "tool_use", "name": "my_tool"}
        ]);
        let (text, _) = extract_text_from_content(&content);
        assert!(text.contains("my_tool"));
    }

    #[test]
    fn test_extract_text_from_content_block_as_string_in_array() {
        // Array with plain string items (not objects)
        let content = json!(["just a string", "another"]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "just a string\nanother");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_serialize_tool_result_content_number() {
        // Line 238: non-string, non-array value → serde_json::to_string fallback
        let content = json!(42);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "42");
    }

    #[test]
    fn test_build_oai_tools_none() {
        assert_eq!(build_oai_tools(None), None);
    }

    #[test]
    fn test_build_oai_tools_empty_vec() {
        assert_eq!(build_oai_tools(Some(vec![])), None);
    }

    #[test]
    fn test_build_oai_tools_with_tools() {
        let tools = Some(vec![crate::models::ClaudeTool {
            name: "calculator".into(),
            description: Some("A calculator".into()),
            input_schema: json!({"type": "object"}),
        }]);
        let result = build_oai_tools(tools);
        assert!(result.is_some());
        let tools = result.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].type_, "function");
        assert_eq!(tools[0].function.name, "calculator");
        assert!(tools[0].function.description.is_some());
    }

    #[test]
    fn test_convert_tool_choice_none() {
        let (result, parallel) = convert_tool_choice(None);
        assert_eq!(result, None);
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_object_tool_with_tool_name() {
        let (result, _) = convert_tool_choice(Some(json!({
            "type": "tool",
            "tool_name": "my_tool"
        })));
        assert_eq!(result, Some(json!({
            "type": "function",
            "function": {"name": "my_tool"}
        })));
    }

    #[test]
    fn test_convert_tool_choice_object_disable_parallel_false() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "auto",
            "disable_parallel_tool_use": false
        })));
        assert_eq!(result, Some(json!("auto")));
        assert_eq!(parallel, Some(true));
    }

    #[test]
    fn test_convert_tool_choice_object_auto_with_parallel() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "auto",
            "disable_parallel_tool_use": true
        })));
        assert_eq!(result, Some(json!("auto")));
        assert_eq!(parallel, Some(false));
    }

    #[test]
    fn test_convert_tool_choice_object_none_with_parallel() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "none",
            "disable_parallel_tool_use": true
        })));
        assert_eq!(result, Some(json!("none")));
        assert_eq!(parallel, Some(false));
    }

    #[test]
    fn test_convert_tool_choice_object_any_with_parallel() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "any",
            "disable_parallel_tool_use": false
        })));
        assert_eq!(result, Some(json!("required")));
        assert_eq!(parallel, Some(true));
    }

    #[test]
    fn test_convert_tool_choice_object_required_with_parallel() {
        let (result, parallel) = convert_tool_choice(Some(json!({
            "type": "required",
            "disable_parallel_tool_use": true
        })));
        assert_eq!(result, Some(json!("required")));
        assert_eq!(parallel, Some(false));
    }
    #[test]
    fn test_count_input_tokens_empty_all() {
        let messages: Vec<crate::models::ClaudeMessage> = vec![];
        let count = count_input_tokens(&messages, &None, &None);
        assert_eq!(count, 0); // empty input produces zero tokens
    }

    #[test]
    fn test_count_input_tokens_system_non_string_value() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hi"),
        }];
        // System as a number (non-string, non-array)
        let count = count_input_tokens(&messages, &Some(json!(42)), &None);
        assert!(count > 0);
    }

    #[test]
    fn test_count_input_tokens_tool_without_description() {
        let messages = vec![crate::models::ClaudeMessage {
            role: "user".into(),
            content: json!("hi"),
        }];
        let tools = vec![crate::models::ClaudeTool {
            name: "simple_tool".into(),
            description: None,
            input_schema: json!({"type": "object"}),
        }];
        let count = count_input_tokens(&messages, &None, &Some(tools));
        assert!(count > 0);
    }

    #[test]
    fn test_build_oai_tools_empty_returns_none() {
        assert_eq!(build_oai_tools(Some(vec![])), None);
    }

    #[test]
    fn test_build_oai_tools_none_returns_none() {
        assert_eq!(build_oai_tools(None), None);
    }

    #[test]
    fn test_build_oai_tools_with_tools_returns_some() {
        let tools = vec![crate::models::ClaudeTool {
            name: "test".into(),
            description: Some("desc".into()),
            input_schema: json!({"type": "object"}),
        }];
        let result = build_oai_tools(Some(tools));
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0].type_, "function");
    }

    #[test]
    fn test_extract_text_tool_result_non_string_non_array() {
        // tool_result content is a number (not string, not array)
        let content = json!([{"type": "tool_result", "content": 42}]);
        let (text, images) = extract_text_from_content(&content);
        // Non-string, non-array content falls through without adding text
        assert_eq!(text, "");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_result_array_with_number_items() {
        let content = json!([{
            "type": "tool_result",
            "content": [42, "text item", {"type": "text", "text": "block"}]
        }]);
        let (text, _images) = extract_text_from_content(&content);
        // Number items are ignored, text items are extracted
        assert!(text.contains("text item"));
        assert!(text.contains("block"));
    }

    #[test]
    fn test_convert_tool_choice_empty_object_with_parallel() {
        let (_result, parallel) = convert_tool_choice(Some(json!({"disable_parallel_tool_use": false})));
        assert_eq!(parallel, Some(true));
    }

    #[test]
    fn test_convert_tool_choice_number_value() {
        let (result, parallel) = convert_tool_choice(Some(json!(3.14)));
        assert_eq!(result, Some(json!(3.14)));
        assert_eq!(parallel, None);
    }

    #[test]
    fn test_convert_tool_choice_object_with_name_and_tool_name() {
        // Both name and tool_name present — name takes precedence
        let (result, _) = convert_tool_choice(Some(json!({
            "type": "tool",
            "name": "primary",
            "tool_name": "secondary"
        })));
        assert_eq!(
            result,
            Some(json!({"type": "function", "function": {"name": "primary"}}))
        );
    }

    #[test]
    fn test_convert_tool_choice_log_args_evaluated_with_logger() {
        // The warn!/info! format arguments are only evaluated when a logger is
        // registered. Install it and drive every logging branch so the
        // argument lines execute (otherwise the macro short-circuits them).
        crate::test_log::init_test_logger();
        let _ = convert_tool_choice(Some(json!("mystery")));
        let _ = convert_tool_choice(Some(json!({"name": "x"})));
        let _ = convert_tool_choice(Some(json!({"type": "tool", "name": "calc"})));
        let _ = convert_tool_choice(Some(json!({"type": "tool"})));
        let _ = convert_tool_choice(Some(json!({"type": "any"})));
        let _ = convert_tool_choice(Some(json!({"type": "weird"})));
        let _ = convert_tool_choice(Some(json!(42)));
    }


    #[test]
    fn test_convert_system_object() {
        // System is an object (not string, not array) — should clone
        let system = json!({"key": "value"});
        let result = convert_system_content(&system);
        assert_eq!(result, json!({"key": "value"}));
    }

    #[test]
    fn test_convert_system_number() {
        let system = json!(42);
        let result = convert_system_content(&system);
        assert_eq!(result, json!(42));
    }

    #[test]
    fn test_convert_system_bool() {
        let system = json!(true);
        let result = convert_system_content(&system);
        assert_eq!(result, json!(true));
    }

    #[test]
    fn test_serialize_tool_result_null() {
        let content = json!(null);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "null");
    }

    #[test]
    fn test_serialize_tool_result_number() {
        let content = json!(42);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "42");
    }

    #[test]
    fn test_serialize_tool_result_bool() {
        let content = json!(true);
        let result = serialize_tool_result_content(&content);
        assert_eq!(result, "true");
    }

    #[test]
    fn test_serialize_tool_result_array_empty_object() {
        let content = json!([{}]);
        let result = serialize_tool_result_content(&content);
        // Non-text object without type field → JSON-serialized
        assert!(result.contains("{}"));
    }

    #[test]
    fn test_extract_text_text_block_missing_text_field() {
        // A "text" block whose "text" field is absent → the if-let-Some is
        // None, exercising the not-entered path (line 78).
        let content = json!([{"type": "text"}, {"type": "text", "text": "ok"}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "ok");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_text_block_non_string_text_field() {
        // "text" field present but not a string → as_str() None → not entered.
        let content = json!([{"type": "text", "text": 123}, {"type": "text", "text": "yes"}]);
        let (text, _) = extract_text_from_content(&content);
        assert_eq!(text, "yes");
    }

    #[test]
    fn test_extract_text_tool_use_missing_name_and_input() {
        // tool_use block with neither "name" nor "input" → both if-let-Some
        // paths are None (lines 114, 119). Also no "input" → to_string not
        // reached (line 118 stays a defensive unreachable brace).
        let content = json!([{"type": "tool_use"}, {"type": "text", "text": "after"}]);
        let (text, images) = extract_text_from_content(&content);
        assert_eq!(text, "after");
        assert_eq!(images, 0);
    }

    #[test]
    fn test_extract_text_tool_use_name_but_no_input() {
        // tool_use with name but no "input" key → name extracted, input
        // if-let-Some is None (line 119).
        let content = json!([{"type": "tool_use", "name": "calc"}]);
        let (text, _) = extract_text_from_content(&content);
        assert!(text.contains("calc"));
    }

    // ========================================================================
    // estimate_tokens_fallback — character-based estimation used when
    // tiktoken_rs::cl100k_base() fails (defensive fallback). Extracted
    // into a separate function so the fallback logic is independently
    // testable even though the Err branch never triggers in practice.
    // ========================================================================

    #[test]
    fn test_estimate_tokens_fallback_empty_text_returns_minimum_one() {
        // Empty text → max(1, 0) = 1 text token, 0 image tokens → 1 total
        assert_eq!(estimate_tokens_fallback("", 0), 1);
    }

    #[test]
    fn test_estimate_tokens_fallback_short_text_returns_at_least_one() {
        // 3 chars → 3/4 = 0 → max(1, 0) = 1 text token
        assert_eq!(estimate_tokens_fallback("abc", 0), 1);
    }

    #[test]
    fn test_estimate_tokens_fallback_long_text_estimates_by_char_ratio() {
        // 40 chars → 40/4 = 10 text tokens
        let text = "a".repeat(40);
        assert_eq!(estimate_tokens_fallback(&text, 0), 10);
    }

    #[test]
    fn test_estimate_tokens_fallback_adds_image_tokens() {
        // 40 chars → 10 text tokens + 2 images * 85 = 170 → 180 total
        let text = "a".repeat(40);
        assert_eq!(
            estimate_tokens_fallback(&text, 2),
            10 + 2 * TOKENS_PER_IMAGE as u32
        );
    }

    #[test]
    fn test_estimate_tokens_fallback_only_images() {
        // Empty text → 1 text token + 3 images * 85 = 255 → 256 total
        assert_eq!(
            estimate_tokens_fallback("", 3),
            1 + 3 * TOKENS_PER_IMAGE as u32
        );
    }
}
