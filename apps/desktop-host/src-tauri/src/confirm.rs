use serde_json::Value;

/// 本地用户交互：`steward_user_confirm` 只有在这里拿到真人确认之后才签发授权记录。
/// WebView 传来的 `confirmed: true` 从不进入这条路径。
///
/// 窗口正文由宿主在 `commands::user_confirm` 里按已测得的事实拼好后放进 `body`；
/// 实现只负责把它原样呈现，不再另取调用方字段。
pub trait ConfirmationPrompt: Send + Sync {
    /// 向用户展示这次确认的范围、动作、目标、指纹与有效期，返回用户是否点了确认。
    fn ask(&self, prompt: &Value) -> Result<bool, String>;
}

fn title(prompt: &Value) -> String {
    prompt
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("确认本次处理")
        .to_string()
}

/// 宿主生成的正文；缺失时不退回调用方的说明，而是明确报错。
fn body(prompt: &Value) -> Result<String, String> {
    prompt
        .get("body")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "NATIVE_CONFIRMATION_PROMPT_INVALID: the host did not compose a prompt body".to_string())
}

/// 产品实现：Tauri v2 的对话框在 `tauri-plugin-dialog` 里，经 `DialogExt` 取得。
#[cfg(feature = "tauri")]
pub struct NativeDialogPrompt {
    pub app: tauri::AppHandle,
}

#[cfg(feature = "tauri")]
impl ConfirmationPrompt for NativeDialogPrompt {
    fn ask(&self, prompt: &Value) -> Result<bool, String> {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
        Ok(self
            .app
            .dialog()
            .message(body(prompt)?)
            .title(title(prompt))
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "确认执行".to_string(),
                "取消".to_string(),
            ))
            .blocking_show())
    }
}

/// 没有窗口时不存在“本地用户交互”，一律拒绝签发，不退化成自动同意。
pub struct UnavailablePrompt;

impl ConfirmationPrompt for UnavailablePrompt {
    fn ask(&self, _prompt: &Value) -> Result<bool, String> {
        Err("NATIVE_CONFIRMATION_UI_UNAVAILABLE: this host cannot show a local confirmation".into())
    }
}

/// 注入实现：只给宿主自身测试用，产品构建不会选到它。
/// 它同样要求宿主已经拼好正文，免得测试掩盖掉 prompt 缺字段的问题。
pub struct InjectedPrompt<F: Fn(&Value) -> Result<bool, String> + Send + Sync> {
    pub decide: F,
}

impl<F: Fn(&Value) -> Result<bool, String> + Send + Sync> ConfirmationPrompt for InjectedPrompt<F> {
    fn ask(&self, prompt: &Value) -> Result<bool, String> {
        body(prompt)?;
        (self.decide)(prompt)
    }
}
