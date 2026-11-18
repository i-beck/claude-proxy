use crate::constants::DEFAULT_THINKING_BUDGET_TOKENS;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn default_thinking_budget_tokens() -> u32 {
    DEFAULT_THINKING_BUDGET_TOKENS
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ThinkingConfig {
    #[serde(rename = "enabled")]
    Enabled {
        #[serde(default = "default_thinking_budget_tokens", alias = "budgetTokens")]
        budget_tokens: u32,
    },
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "adaptive")]
    Adaptive,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct BackendThinkingConfig {
    #[serde(rename = "type")]
    pub type_: String, // "enabled"
    pub budget_tokens: u32,
}

impl ThinkingConfig {
    pub fn into_backend_config(self) -> Option<BackendThinkingConfig> {
        match self {
            Self::Enabled { budget_tokens } => Some(BackendThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens,
            }),
            Self::Adaptive => Some(BackendThinkingConfig {
                type_: "enabled".to_string(),
                budget_tokens: DEFAULT_THINKING_BUDGET_TOKENS,
            }),
            Self::Disabled => None,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ClaudeImageSource {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub source_type: String,
    pub media_type: String,
    pub data: String,
}

#[derive(Deserialize, Debug)]
pub struct ClaudeDocumentSource {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    pub source_type: String, // "base64", "url", "file"
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, alias = "id")]
    pub file_id: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ClaudeContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(default)]
        #[allow(dead_code)]
        cache_control: Option<Value>,
    },
    #[serde(rename = "image")]
    Image {
        source: ClaudeImageSource,
        #[serde(default)]
        #[allow(dead_code)]
        cache_control: Option<Value>,
    },
    #[serde(rename = "document")]
    Document {
        source: ClaudeDocumentSource,
        #[serde(default)]
        #[allow(dead_code)]
        cache_control: Option<Value>,
    },
    #[serde(rename = "thinking")]
    Thinking {
        thinking: String,
        #[serde(default)]
        #[allow(dead_code)]
        signature: Option<String>,
    },
    #[serde(rename = "redacted_thinking")]
    RedactedThinking {
        #[allow(dead_code)]
        data: String,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
        #[serde(default)]
        #[allow(dead_code)]
        cache_control: Option<Value>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: Value,
        #[serde(default)]
        #[allow(dead_code)]
        is_error: Option<bool>,
        #[serde(default)]
        #[allow(dead_code)]
        cache_control: Option<Value>,
    },
}

#[derive(Deserialize)]
pub struct ClaudeMessage {
    pub role: String,
    pub content: Value, // String or Vec<ClaudeContentBlock>
}

#[derive(Deserialize)]
pub struct ClaudeTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Deserialize)]
pub struct ClaudeRequest {
    pub model: String,
    pub messages: Vec<ClaudeMessage>,
    #[serde(default)]
    pub system: Option<Value>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub top_p: Option<f32>,
    #[serde(default)]
    pub top_k: Option<u32>,
    #[serde(default)]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(default)]
    pub tools: Option<Vec<ClaudeTool>>,
    #[serde(default)]
    pub tool_choice: Option<Value>,
    #[serde(default)]
    pub thinking: Option<ThinkingConfig>,
    #[serde(default)]
    pub output_config: Option<ClaudeOutputConfig>,
    #[serde(default)]
    #[allow(dead_code)]
    pub stream: Option<bool>,
    // Fields for validation warnings (accepted but not used)
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub service_tier: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct ClaudeOutputConfig {
    #[serde(default, alias = "effortLevel")]
    pub effort: Option<String>,
}

#[derive(Deserialize)]
pub struct ClaudeTokenCountRequest {
    #[allow(dead_code)]
    pub model: String,
    pub messages: Vec<ClaudeMessage>,
    #[serde(default)]
    pub system: Option<Value>,
    #[serde(default)]
    pub tools: Option<Vec<ClaudeTool>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_thinking_config_deserializes_adaptive() {
        let config: ThinkingConfig = serde_json::from_value(json!({
            "type": "adaptive"
        }))
        .unwrap();

        assert_eq!(config, ThinkingConfig::Adaptive);
        assert_eq!(
            config.into_backend_config(),
            Some(BackendThinkingConfig {
                type_: "enabled".into(),
                budget_tokens: DEFAULT_THINKING_BUDGET_TOKENS,
            })
        );
    }

    #[test]
    fn test_thinking_config_defaults_budget_when_enabled_budget_missing() {
        let config: ThinkingConfig = serde_json::from_value(json!({
            "type": "enabled"
        }))
        .unwrap();

        assert_eq!(
            config.into_backend_config(),
            Some(BackendThinkingConfig {
                type_: "enabled".into(),
                budget_tokens: DEFAULT_THINKING_BUDGET_TOKENS,
            })
        );
    }

    #[test]
    fn test_thinking_config_accepts_camel_case_budget_tokens() {
        let config: ThinkingConfig = serde_json::from_value(json!({
            "type": "enabled",
            "budgetTokens": 2048
        }))
        .unwrap();

        assert_eq!(
            config.into_backend_config(),
            Some(BackendThinkingConfig {
                type_: "enabled".into(),
                budget_tokens: 2048,
            })
        );
    }

    #[test]
    fn test_claude_request_deserializes_output_config_effort() {
        let request: ClaudeRequest = serde_json::from_value(json!({
            "model": "zai-org/GLM-5-TEE",
            "messages": [{ "role": "user", "content": "hello" }],
            "output_config": {
                "effort": "low"
            }
        }))
        .unwrap();

        assert_eq!(
            request
                .output_config
                .as_ref()
                .and_then(|cfg| cfg.effort.as_deref()),
            Some("low")
        );
    }

    #[test]
    fn test_document_block_deserializes_base64_source() {
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "document",
            "source": {
                "type": "base64",
                "media_type": "application/pdf",
                "data": "ZmFrZQ=="
            }
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { source, .. } => {
                assert_eq!(source.source_type, "base64");
                assert_eq!(source.media_type.as_deref(), Some("application/pdf"));
                assert_eq!(source.data.as_deref(), Some("ZmFrZQ=="));
                assert_eq!(source.url, None);
                assert_eq!(source.file_id, None);
            }
            _ => panic!("expected document block"),
        }
    }

    #[test]
    fn test_document_block_deserializes_url_source() {
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "document",
            "source": {
                "type": "url",
                "url": "https://example.com/file.pdf"
            }
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { source, .. } => {
                assert_eq!(source.source_type, "url");
                assert_eq!(source.url.as_deref(), Some("https://example.com/file.pdf"));
                assert_eq!(source.data, None);
                assert_eq!(source.file_id, None);
            }
            _ => panic!("expected document block"),
        }
    }

    #[test]
    fn test_document_block_deserializes_file_source() {
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "document",
            "source": {
                "type": "file",
                "file_id": "file_123"
            }
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { source, .. } => {
                assert_eq!(source.source_type, "file");
                assert_eq!(source.file_id.as_deref(), Some("file_123"));
                assert_eq!(source.data, None);
                assert_eq!(source.url, None);
            }
            _ => panic!("expected document block"),
        }
    }

    #[test]
    #[should_panic(expected = "expected document block")]
    fn test_text_block_panics_when_matched_as_document() {
        // Line 288: cover the `_ => panic!` arm by deserializing a non-document
        // block and matching on the Document variant.
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "text",
            "text": "hello"
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { .. } => {}
            _ => panic!("expected document block"),
        }
    }

    #[test]
    #[should_panic(expected = "expected document block")]
    fn test_image_block_panics_when_matched_as_document() {
        // Line 310: cover the `_ => panic!` arm with an image block.
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": "iVBOR"
            }
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { .. } => {}
            _ => panic!("expected document block"),
        }
    }

    #[test]
    #[should_panic(expected = "expected document block")]
    fn test_tool_use_block_panics_when_matched_as_document() {
        // Line 332: cover the `_ => panic!` arm with a tool_use block.
        let block: ClaudeContentBlock = serde_json::from_value(json!({
            "type": "tool_use",
            "id": "tool_1",
            "name": "calculator",
            "input": {}
        }))
        .unwrap();

        match block {
            ClaudeContentBlock::Document { .. } => {}
            _ => panic!("expected document block"),
        }
    }
    #[test]
    fn test_thinking_config_enabled_with_custom_budget() {
        let config: ThinkingConfig = serde_json::from_value(json!({
            "type": "enabled",
            "budget_tokens": 5000
        })).unwrap();
        assert_eq!(
            config.into_backend_config(),
            Some(BackendThinkingConfig {
                type_: "enabled".into(),
                budget_tokens: 5000,
            })
        );
    }

    #[test]
    fn test_thinking_config_disabled_returns_none() {
        let config: ThinkingConfig = serde_json::from_value(json!({
            "type": "disabled"
        })).unwrap();
        assert_eq!(config.into_backend_config(), None);
    }

    #[test]
    fn test_claude_request_with_all_optional_fields() {
        let request: ClaudeRequest = serde_json::from_value(json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}]
        })).unwrap();
        assert!(request.max_tokens.is_none());
        assert!(request.temperature.is_none());
        assert!(request.top_p.is_none());
        assert!(request.top_k.is_none());
        assert!(request.stop_sequences.is_none());
        assert!(request.tools.is_none());
        assert!(request.tool_choice.is_none());
        assert!(request.thinking.is_none());
        assert!(request.output_config.is_none());
        assert!(request.metadata.is_none());
        assert!(request.service_tier.is_none());
        assert!(request.system.is_none());
    }

    #[test]
    fn test_claude_request_with_camel_case_output_config() {
        let request: ClaudeRequest = serde_json::from_value(json!({
            "model": "test-model",
            "messages": [{"role": "user", "content": "hi"}],
            "output_config": {"effortLevel": "high"}
        })).unwrap();
        assert_eq!(
            request.output_config.as_ref().and_then(|c| c.effort.as_deref()),
            Some("high")
        );
    }

    #[test]
    fn test_claude_output_config_default() {
        let config = ClaudeOutputConfig::default();
        assert!(config.effort.is_none());
    }

    #[test]
    fn test_claude_token_count_request_minimal() {
        let request: ClaudeTokenCountRequest = serde_json::from_value(json!({
            "model": "test",
            "messages": [{"role": "user", "content": "hi"}]
        })).unwrap();
        assert_eq!(request.model, "test");
        assert_eq!(request.messages.len(), 1);
        assert!(request.system.is_none());
        assert!(request.tools.is_none());
    }

    #[test]
    fn test_claude_tool_with_description() {
        let tool: ClaudeTool = serde_json::from_value(json!({
            "name": "test_tool",
            "description": "A test tool",
            "input_schema": {"type": "object"}
        })).unwrap();
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description.as_deref(), Some("A test tool"));
    }

    #[test]
    fn test_claude_tool_without_description() {
        let tool: ClaudeTool = serde_json::from_value(json!({
            "name": "test_tool",
            "input_schema": {"type": "object"}
        })).unwrap();
        assert_eq!(tool.name, "test_tool");
        assert!(tool.description.is_none());
    }


}
