//! 进出模型的脱敏，规则与客户端 `src/core/ai/evidence.mjs` 的 redactForModel 相同：
//! 键名像秘密整体替换；文本里的 `sk-…`、合成秘密标记、`Bearer …` 与 Windows 本地路径遮盖。
//! 服务端用它计算 turn 幂等签名，并在把模型回复交回客户端前再过一遍。

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

fn sensitive_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)(api[_-]?key|authorization|auth[_-]?token|password|secret|cookie|credential|private[_-]?key|refresh[_-]?token|session)")
            .expect("固定的键名规则")
    })
}

fn sensitive_value() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(?:sk-[A-Za-z0-9_-]{8,}|SYNTHETIC_[A-Z0-9_]*(?:TOKEN|SECRET|COOKIE|KEY)[A-Z0-9_]*|Bearer\s+[^\s]+)\b")
            .expect("固定的秘密值规则")
    })
}

fn local_path() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r#"(?:[A-Za-z]:\\|\\\\)[^\r\n"']+"#).expect("固定的本地路径规则"))
}

pub fn redact_text(text: &str) -> String {
    let masked = sensitive_value().replace_all(text, "[REDACTED]");
    local_path().replace_all(&masked, "[LOCAL_PATH]").into_owned()
}

fn redact_with_key(value: &Value, key: &str) -> Value {
    if !key.is_empty() && sensitive_key().is_match(key) {
        return Value::String("[REDACTED]".to_string());
    }
    match value {
        Value::String(text) => Value::String(redact_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(|item| redact_with_key(item, "")).collect()),
        Value::Object(map) => {
            let mut copy = Map::new();
            for (child_key, child) in map {
                copy.insert(child_key.clone(), redact_with_key(child, child_key));
            }
            Value::Object(copy)
        }
        other => other.clone(),
    }
}

pub fn redact_for_model(value: &Value) -> Value {
    redact_with_key(value, "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_client_rules() {
        let value = json!({
            "api_key": "anything",
            "note": "use sk-abcdefgh12345 with Bearer abc.def and C:\\Users\\someone\\file.txt end",
            "nested": [{"sessionToken": "x"}, "SYNTHETIC_MODEL_KEY_1"],
            "count": 3
        });
        let redacted = redact_for_model(&value);
        assert_eq!(redacted["api_key"], "[REDACTED]");
        let note = redacted["note"].as_str().unwrap();
        assert!(!note.contains("sk-abcdefgh12345"));
        assert!(!note.contains("abc.def"));
        assert!(note.contains("[LOCAL_PATH]"));
        assert_eq!(redacted["nested"][0]["sessionToken"], "[REDACTED]");
        assert_eq!(redacted["nested"][1], "[REDACTED]");
        assert_eq!(redacted["count"], 3);
    }
}
