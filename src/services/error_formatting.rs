use serde_json::Value;

/// Format backend error into user-friendly structured message
pub fn format_backend_error(error_msg: &str, raw_json: &str) -> String {
    // Try to extract model name from context if available
    let model_name = if let Ok(val) = serde_json::from_str::<Value>(raw_json) {
        val.get("model").and_then(|m| m.as_str()).map(String::from)
    } else {
        None
    };

    let mut formatted = String::from("⚠️ Backend Error\n\n");

    if let Some(model) = model_name {
        formatted.push_str(&format!("Model: {}\n", model));
    }

    formatted.push_str(&format!("Error: {}\n\n", error_msg));

    // Add specific suggestions based on error type
    if error_msg.contains("token") && error_msg.contains("exceed") {
        if let Some(requested) = error_msg
            .split("total of ")
            .nth(1)
            .and_then(|s| s.split(" tokens").next())
        {
            formatted.push_str(&format!("Requested: {} tokens\n", requested));
        }
        if let Some(limit) = error_msg
            .split("maximum context length of ")
            .nth(1)
            .and_then(|s| s.split(" tokens").next())
        {
            formatted.push_str(&format!("Limit: {} tokens\n\n", limit));
        }
        formatted.push_str("💡 Suggestions:\n");
        formatted.push_str("• Reduce message history\n");
        formatted.push_str("• Use a model with larger context\n");
        formatted.push_str("• Decrease max_tokens parameter\n");
    } else if error_msg.contains("rate limit") {
        formatted.push_str("💡 Suggestions:\n");
        formatted.push_str("• Wait a moment before retrying\n");
        formatted.push_str("• Check your API quota\n");
    } else if error_msg.contains("insufficient") || error_msg.contains("quota") {
        formatted.push_str("💡 Suggestions:\n");
        formatted.push_str("• Check your account balance\n");
        formatted.push_str("• Verify API key permissions\n");
    }

    formatted
}

/// Build markdown content for synthetic 404 response listing available models
pub fn build_model_list_content(
    requested_model: &str,
    models: &[crate::models::ModelInfo],
) -> String {
    let mut content = format!(
        "❌ Model `{}` not found.\n\n## 📋 Available Models ({} total)\n\n",
        requested_model,
        models.len()
    );

    let mut reasoning_models: Vec<&crate::models::ModelInfo> = vec![];
    let mut standard_models: Vec<&crate::models::ModelInfo> = vec![];

    for model in models {
        let has_reasoning = model
            .supported_features
            .iter()
            .any(|f| f.to_lowercase().contains("reasoning"));

        if has_reasoning {
            reasoning_models.push(model);
        } else {
            standard_models.push(model);
        }
    }

    let sort_models =
        |a: &&crate::models::ModelInfo, b: &&crate::models::ModelInfo| -> std::cmp::Ordering {
            let a_parts: Vec<&str> = a.id.split('/').collect();
            let b_parts: Vec<&str> = b.id.split('/').collect();

            let first_cmp = a_parts
                .first()
                .unwrap_or(&"")
                .to_lowercase()
                .cmp(&b_parts.first().unwrap_or(&"").to_lowercase());

            if first_cmp != std::cmp::Ordering::Equal {
                return first_cmp;
            }

            b_parts
                .get(1)
                .unwrap_or(&"")
                .to_lowercase()
                .cmp(&a_parts.get(1).unwrap_or(&"").to_lowercase())
        };

    reasoning_models.sort_by(sort_models);
    standard_models.sort_by(sort_models);

    let format_two_columns = |models: &[&crate::models::ModelInfo]| -> String {
        let mut result = String::new();
        let half = models.len().div_ceil(2);
        for i in 0..half {
            // i < half = div_ceil(len/2) <= len, so models[i] is always valid.
            let &left_model = &models[i];
            let left_price = crate::constants::get_price_tier(
                left_model.input_price_usd,
                left_model.output_price_usd,
            );
            let left_formatted = format!("{:4} {}", left_price, left_model.id);
            if let Some(&right_model) = models.get(i + half) {
                    let right_price = crate::constants::get_price_tier(
                        right_model.input_price_usd,
                        right_model.output_price_usd,
                    );
                    let right_formatted = format!("{:4} {}", right_price, right_model.id);
                    result.push_str(&format!("  {:48} {}\n", left_formatted, right_formatted));
                } else {
                    result.push_str(&format!("  {}\n", left_formatted));
                }
        }
        result
    };

    if !reasoning_models.is_empty() {
        content.push_str("### 🧠 REASONING (Extended Thinking)\n\n");
        content.push_str(&format_two_columns(&reasoning_models));
        content.push('\n');
    }
    if !standard_models.is_empty() {
        content.push_str("### ⚡ STANDARD\n\n");
        content.push_str(&format_two_columns(&standard_models));
        content.push('\n');
    }

    content.push_str("---\n\n💡 **To switch models:** Use `/model <model-name>`");
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ModelInfo;

    #[test]
    fn test_format_backend_error_includes_model_and_token_suggestions() {
        let message = format_backend_error(
            "requested a total of 120000 tokens which exceed maximum context length of 64000 tokens",
            r#"{"model":"deepseek-r1"}"#,
        );

        assert!(message.contains("Model: deepseek-r1"));
        assert!(message.contains("Requested: 120000"));
        assert!(message.contains("Limit: 64000"));
        assert!(message.contains("Reduce message history"));
    }

    #[test]
    fn test_format_backend_error_adds_rate_limit_suggestions() {
        let message = format_backend_error("rate limit exceeded", "{}");
        assert!(message.contains("Wait a moment before retrying"));
        assert!(message.contains("Check your API quota"));
    }

    #[test]
    fn test_format_backend_error_adds_quota_suggestions() {
        let message = format_backend_error("insufficient quota", "{}");
        assert!(message.contains("Check your account balance"));
        assert!(message.contains("Verify API key permissions"));
    }

    #[test]
    fn test_build_model_list_content_groups_reasoning_and_standard_models() {
        let models = vec![
            ModelInfo {
                id: "zai-org/GLM-4.5-Air".into(),
                input_price_usd: Some(0.1),
                output_price_usd: Some(0.2),
                supported_features: vec![],
            },
            ModelInfo {
                id: "deepseek-r1".into(),
                input_price_usd: Some(0.2),
                output_price_usd: Some(0.4),
                supported_features: vec!["reasoning".into()],
            },
        ];

        let content = build_model_list_content("missing-model", &models);
        assert!(content.contains("Model `missing-model` not found"));
        assert!(content.contains("### 🧠 REASONING"));
        assert!(content.contains("deepseek-r1"));
        assert!(content.contains("### ⚡ STANDARD"));
        assert!(content.contains("zai-org/GLM-4.5-Air"));
        assert!(content.contains("To switch models"));
    }

    #[test]
    fn test_format_backend_error_with_invalid_json_raw() {
        // Line 9: raw_json is not valid JSON → model_name = None
        let message = format_backend_error("some error", "not-json-at-all");
        assert!(message.contains("⚠️ Backend Error"));
        assert!(message.contains("Error: some error"));
        // Should NOT contain "Model:" since model_name is None
        assert!(!message.contains("Model:"));
    }

    #[test]
    fn test_format_backend_error_token_exceed_without_limit() {
        // Line 28: "total of X tokens" present but "maximum context length" absent
        let message = format_backend_error(
            "requested a total of 120000 tokens which exceed",
            "{}",
        );
        assert!(message.contains("Requested: 120000"));
        // No "Limit:" since "maximum context length of" is not in the message
        assert!(!message.contains("Limit:"));
    }

    #[test]
    fn test_format_backend_error_token_exceed_without_requested() {
        // Line 35: "maximum context length" present but "total of" absent
        let message = format_backend_error(
            "token exceed maximum context length of 64000 tokens",
            "{}",
        );
        assert!(message.contains("Limit: 64000"));
        // No "Requested:" since "total of" is not in the message
        assert!(!message.contains("Requested:"));
    }

    #[test]
    fn test_format_backend_error_generic_no_suggestions() {
        // None of the special cases match → no suggestions
        let message = format_backend_error("some random error", "{}");
        assert!(message.contains("Error: some random error"));
        assert!(!message.contains("💡"));
    }

    #[test]
    fn test_build_model_list_content_empty_models() {
        // Line 139: empty models list — no reasoning or standard sections
        let content = build_model_list_content("ghost-model", &[]);
        assert!(content.contains("Model `ghost-model` not found"));
        assert!(content.contains("0 total"));
        assert!(!content.contains("### 🧠 REASONING"));
        assert!(!content.contains("### ⚡ STANDARD"));
    }

    #[test]
    fn test_build_model_list_content_model_without_slash() {
        // Line 93: model IDs without '/' separator (e.g., "deepseek-r1")
        let models = vec![
            ModelInfo {
                id: "model-a".into(),
                input_price_usd: Some(0.1),
                output_price_usd: Some(0.2),
                supported_features: vec![],
            },
            ModelInfo {
                id: "model-b".into(),
                input_price_usd: None,
                output_price_usd: None,
                supported_features: vec!["reasoning".into()],
            },
        ];
        let content = build_model_list_content("test", &models);
        assert!(content.contains("model-a"));
        assert!(content.contains("model-b"));
    }

    #[test]
    fn test_build_model_list_content_same_prefix_different_suffix() {
        // Lines 95-99: sort comparison where first parts are equal
        let models = vec![
            ModelInfo {
                id: "org/zzz".into(),
                input_price_usd: None,
                output_price_usd: None,
                supported_features: vec![],
            },
            ModelInfo {
                id: "org/aaa".into(),
                input_price_usd: None,
                output_price_usd: None,
                supported_features: vec![],
            },
        ];
        let content = build_model_list_content("test", &models);
        // Both should appear; sort is by first part then reverse by second
        assert!(content.contains("org/zzz"));
        assert!(content.contains("org/aaa"));
    }

    #[test]
    fn test_build_model_list_content_odd_count_no_right_column() {
        // Line 125: odd number of models → last row has no right column
        let models: Vec<ModelInfo> = (0..3).map(|i| ModelInfo {
            id: format!("model-{i}"),
            input_price_usd: None,
            output_price_usd: None,
            supported_features: vec![],
        }).collect();
        let content = build_model_list_content("test", &models);
        assert!(content.contains("model-0"));
        assert!(content.contains("model-1"));
        assert!(content.contains("model-2"));
    }
    #[test]
    fn test_format_backend_error_no_model_in_raw() {
        let message = format_backend_error("some error", "not json");
        assert!(message.contains("Error: some error"));
        assert!(!message.contains("Model:"));
    }

    #[test]
    fn test_format_backend_error_token_exceed_without_numbers() {
        // Has 'token' and 'exceed' but not the specific patterns
        let message = format_backend_error("token limit exceed", "{}");
        assert!(message.contains("token limit exceed"));
    }

    #[test]
    fn test_build_model_list_content_only_reasoning() {
        let models = vec![ModelInfo {
            id: "deepseek-r1".into(),
            input_price_usd: Some(0.2),
            output_price_usd: Some(0.4),
            supported_features: vec!["reasoning".into()],
        }];
        let content = build_model_list_content("missing", &models);
        assert!(content.contains("REASONING"));
        assert!(!content.contains("STANDARD"));
        assert!(content.contains("deepseek-r1"));
    }

    #[test]
    fn test_build_model_list_content_only_standard() {
        let models = vec![ModelInfo {
            id: "zai-org/GLM-4.5-Air".into(),
            input_price_usd: Some(0.1),
            output_price_usd: Some(0.2),
            supported_features: vec![],
        }];
        let content = build_model_list_content("missing", &models);
        assert!(!content.contains("REASONING"));
        assert!(content.contains("STANDARD"));
        assert!(content.contains("zai-org/GLM-4.5-Air"));
    }

    #[test]
    fn test_build_model_list_content_empty() {
        let content = build_model_list_content("missing", &[]);
        assert!(content.contains("0 total"));
        assert!(content.contains("To switch models"));
    }

    #[test]
    fn test_build_model_list_content_odd_count() {
        let models = vec![
            ModelInfo { id: "a/model1".into(), input_price_usd: None, output_price_usd: None, supported_features: vec![] },
            ModelInfo { id: "b/model2".into(), input_price_usd: None, output_price_usd: None, supported_features: vec![] },
            ModelInfo { id: "c/model3".into(), input_price_usd: None, output_price_usd: None, supported_features: vec![] },
        ];
        let content = build_model_list_content("missing", &models);
        assert!(content.contains("model1"));
        assert!(content.contains("model2"));
        assert!(content.contains("model3"));
    }

    #[test]
    fn test_format_backend_error_with_no_suggestions() {
        let message = format_backend_error("unknown error type", r#"{"model":"test"}"#);
        assert!(message.contains("Model: test"));
        assert!(message.contains("Error: unknown error type"));
        assert!(!message.contains("Suggestions"));
    }

    #[test]
    fn test_format_backend_error_invalid_json_omits_model() {
        // Line 9: raw_json is not valid JSON → model_name is None → no "Model:" line.
        let message = format_backend_error("some error", "not-valid-json");
        assert!(!message.contains("Model:"));
        assert!(message.contains("Error: some error"));
    }

    #[test]
    fn test_build_model_list_content_same_org_exercises_second_level_sort() {
        // Lines 93-99: two models with the SAME org prefix force the sort
        // comparison to fall through to the second-level (model-name) key.
        let models = vec![
            ModelInfo {
                id: "zai-org/GLM-Beta".into(),
                input_price_usd: None,
                output_price_usd: None,
                supported_features: vec!["reasoning".into()],
            },
            ModelInfo {
                id: "zai-org/GLM-Alpha".into(),
                input_price_usd: None,
                output_price_usd: None,
                supported_features: vec!["reasoning".into()],
            },
        ];
        let content = build_model_list_content("missing", &models);
        assert!(content.contains("zai-org/GLM-Beta"));
        assert!(content.contains("zai-org/GLM-Alpha"));
        assert!(content.contains("### 🧠 REASONING"));
    }

}
