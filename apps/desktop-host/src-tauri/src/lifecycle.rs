//! 桌面生命周期：关窗进托盘、托盘菜单、第二次启动、危急系统通知。
//!
//! - 纯逻辑在这里：菜单项与动作映射、通知种类与固定文案、页面通知请求的校验、第一次后台运行提示的标记。
//! - Tauri 接线（插件、托盘图标、窗口事件）在 `lib.rs` 与本文件带 `tauri` 特性的部分。
//! - 这里不发任何产品网络服务命令：隐藏窗口、退出界面都不解除保护，停止管理仍走独立的本地确认。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::commands::{iso_from_millis, now_millis};

pub const TRAY_ID: &str = "steward-main";
pub const MAIN_WINDOW: &str = "main";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    ShowMainWindow,
    OpenLogFolder,
    QuitInterface,
}

/// 托盘菜单固定三项。不放代理模式、配置导入、解除保护或停止管理的快捷入口。
pub const TRAY_MENU: [(&str, &str); 3] = [("show", "显示主窗口"), ("open_logs", "打开日志目录"), ("quit_ui", "退出界面（保护继续）")];

pub fn tray_action(id: &str) -> Option<TrayAction> {
    match id {
        "show" => Some(TrayAction::ShowMainWindow),
        "open_logs" => Some(TrayAction::OpenLogFolder),
        "quit_ui" => Some(TrayAction::QuitInterface),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    WrongRoute,
    ProtectionNotConfirmed,
    ProtectionFailed,
    RunningInBackground,
}

impl Notice {
    /// 页面只能请求这三类危急通知；后台运行提示只由宿主在第一次关窗时自己发。
    pub fn critical(event: &str) -> Option<Notice> {
        match event {
            "WRONG_ROUTE" => Some(Notice::WrongRoute),
            "PROTECTION_NOT_CONFIRMED" => Some(Notice::ProtectionNotConfirmed),
            "PROTECTION_FAILED" => Some(Notice::ProtectionFailed),
            _ => None,
        }
    }

    /// 固定文案：不带目标、进程、路径、地址、令牌或日志正文，细节只在应用窗口里看。
    pub fn text(self) -> (&'static str, &'static str) {
        match self {
            Notice::WrongRoute => ("Claude 连接走了错误出口", "正在按预授权阻断受保护程序的新连接。请打开 AI Environmental Steward 查看结果。"),
            Notice::ProtectionNotConfirmed => ("阻断没有确认生效", "受保护程序可能仍能连出。请打开 AI Environmental Steward 查看并处理。"),
            Notice::ProtectionFailed => ("阻断失败", "保护动作没有完成。请打开 AI Environmental Steward 查看并处理。"),
            Notice::RunningInBackground => ("AI Environmental Steward 仍在后台运行", "监测与网络保护继续。可以从托盘图标重新打开，或选择退出界面。"),
        }
    }
}

/// 系统通知通道。窗口可见（且没有最小化）时页面横幅已经在，不另弹。
pub trait NoticeSink: Send + Sync {
    fn main_window_hidden(&self) -> bool;
    fn show(&self, title: &str, body: &str) -> Result<(), String>;
}

/// 没有通知通道的装配（非 Tauri 构建、注入宿主）：如实回报不可用，不假装已通知。
pub struct UnavailableNotices;

impl NoticeSink for UnavailableNotices {
    fn main_window_hidden(&self) -> bool {
        true
    }

    fn show(&self, _title: &str, _body: &str) -> Result<(), String> {
        Err("NOTIFICATION_UNAVAILABLE: this host has no system notification channel".to_string())
    }
}

/// 宿主自身测试用：记下弹出的标题与正文，可切换窗口可见与通知失败。
#[derive(Default)]
pub struct RecordingNotices {
    pub visible: Mutex<bool>,
    pub failure: Mutex<Option<String>>,
    pub shown: Mutex<Vec<(String, String)>>,
}

impl NoticeSink for RecordingNotices {
    fn main_window_hidden(&self) -> bool {
        !self.visible.lock().map(|value| *value).unwrap_or(false)
    }

    fn show(&self, title: &str, body: &str) -> Result<(), String> {
        if let Some(failure) = self.failure.lock().ok().and_then(|value| value.clone()) {
            return Err(failure);
        }
        self.shown
            .lock()
            .map_err(|_| "NOTIFICATION_FAILED: recorder unavailable".to_string())?
            .push((title.to_string(), body.to_string()));
        Ok(())
    }
}

fn valid_reference(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

fn failure_code(error: &str) -> String {
    let head = error.split(':').next().unwrap_or("").trim();
    if !head.is_empty() && head.len() <= 64 && head.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
        head.to_string()
    } else {
        "NOTIFICATION_FAILED".to_string()
    }
}

/// `NotifyCritical`：只收 `event`（固定枚举）与 `ref`（提示编号）。标题与正文由宿主按枚举取固定文案。
/// 弹不出来回 `ok:false`、`FAILED` 与错误码，失败的原生操作照常记进应用日志；页面据此保留危急状态。
pub fn notify_critical(sink: &dyn NoticeSink, payload: &Value) -> Result<Value, String> {
    let object = payload.as_object().ok_or("NATIVE_PAYLOAD_INVALID: payload must be an object")?;
    if object.keys().any(|key| key != "event" && key != "ref") {
        return Err("NOTIFY_FIELD_FORBIDDEN: only event and ref are accepted; title and body are fixed by the host".to_string());
    }
    let event = object.get("event").and_then(Value::as_str).unwrap_or_default();
    let notice = Notice::critical(event)
        .ok_or("NOTIFY_EVENT_UNKNOWN: event must be WRONG_ROUTE, PROTECTION_NOT_CONFIRMED or PROTECTION_FAILED")?;
    let reference = object.get("ref").and_then(Value::as_str).unwrap_or_default();
    if !valid_reference(reference) {
        return Err("NOTIFY_REF_INVALID: ref must be a short alert reference".to_string());
    }
    if !sink.main_window_hidden() {
        return Ok(json!({"ok": true, "status": "SKIPPED_WINDOW_VISIBLE", "event": event}));
    }
    let (title, body) = notice.text();
    match sink.show(title, body) {
        Ok(()) => Ok(json!({"ok": true, "status": "SHOWN", "event": event})),
        Err(error) => Ok(json!({"ok": false, "status": "FAILED", "code": failure_code(&error), "event": event})),
    }
}

/// 第一次后台运行提示的标记：放在工作区旁的宿主状态目录，受限原生桥到不了。
pub fn background_marker(workspace_root: &Path) -> PathBuf {
    workspace_root.parent().unwrap_or(workspace_root).join("host-state").join("background-notice.json")
}

/// 第一次关窗进托盘时提示一次；通知真正弹出后才写标记，弹不出来下次关窗还会再试。
pub fn announce_background(sink: &dyn NoticeSink, marker: &Path) -> Result<bool, String> {
    if marker.exists() {
        return Ok(false);
    }
    let (title, body) = Notice::RunningInBackground.text();
    sink.show(title, body)?;
    if let Some(dir) = marker.parent() {
        std::fs::create_dir_all(dir).map_err(|error| format!("HOST_STATE_WRITE_FAILED: {error}"))?;
    }
    std::fs::write(marker, json!({"shown_at": iso_from_millis(now_millis())}).to_string())
        .map_err(|error| format!("HOST_STATE_WRITE_FAILED: {error}"))?;
    Ok(true)
}

#[cfg(feature = "tauri")]
pub struct TauriNotices {
    pub app: tauri::AppHandle,
}

#[cfg(feature = "tauri")]
impl NoticeSink for TauriNotices {
    fn main_window_hidden(&self) -> bool {
        use tauri::Manager;
        match self.app.get_webview_window(MAIN_WINDOW) {
            Some(window) => !window.is_visible().unwrap_or(false) || window.is_minimized().unwrap_or(false),
            None => true,
        }
    }

    fn show(&self, title: &str, body: &str) -> Result<(), String> {
        use tauri_plugin_notification::NotificationExt;
        self.app
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show()
            .map_err(|error| format!("NOTIFICATION_FAILED: {error}"))
    }
}

#[cfg(feature = "tauri")]
pub fn show_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(feature = "tauri")]
fn handle_tray(app: &tauri::AppHandle, id: &str) {
    use crate::logs::FolderOpener as _;
    use tauri::Manager;
    let Some(action) = tray_action(id) else { return };
    match action {
        TrayAction::ShowMainWindow => show_main_window(app),
        TrayAction::OpenLogFolder => {
            let state = app.state::<crate::HostState>();
            if let Err(error) = state.folders.open(&state.logs.host) {
                crate::logs::record_outcome(&state.app_log, "TrayOpenLogFolder", &Err(error));
            }
        }
        // 退出界面：只结束 GUI；退出事件里再停本宿主托管的控制端。产品网络服务与保护不受影响。
        TrayAction::QuitInterface => app.exit(0),
    }
}

#[cfg(feature = "tauri")]
pub fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{IsMenuItem, MenuBuilder, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let items = TRAY_MENU
        .iter()
        .map(|(id, label)| MenuItem::with_id(app, *id, *label, true, None::<&str>))
        .collect::<tauri::Result<Vec<_>>>()?;
    let refs: Vec<&dyn IsMenuItem<tauri::Wry>> = items.iter().map(|item| item as &dyn IsMenuItem<tauri::Wry>).collect();
    let menu = MenuBuilder::new(app).items(&refs).build()?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("AI Environmental Steward")
        .menu(&menu)
        .show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    let tray = builder.build(app)?;
    tray.on_menu_event(|app, event| handle_tray(app, event.id.as_ref()));
    tray.on_tray_icon_event(|tray, event| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
            show_main_window(tray.app_handle());
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("steward-lifecycle-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("workspace")).unwrap();
        dir
    }

    #[test]
    fn the_tray_offers_only_show_open_logs_and_quit_interface() {
        let ids: Vec<&str> = TRAY_MENU.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec!["show", "open_logs", "quit_ui"]);
        assert_eq!(tray_action("quit_ui"), Some(TrayAction::QuitInterface));
        for forbidden in ["stop_management", "release_protection", "proxy_mode", "import_config", "tray_exit"] {
            assert_eq!(tray_action(forbidden), None, "{forbidden}");
        }
    }

    #[test]
    fn a_critical_notice_carries_only_a_fixed_event_and_reference() {
        let sink = RecordingNotices::default();
        let shown = notify_critical(&sink, &json!({"event": "WRONG_ROUTE", "ref": "alert-1790000000000-0"})).unwrap();
        assert_eq!(shown["status"], "SHOWN");
        let (title, body) = sink.shown.lock().unwrap()[0].clone();
        assert_eq!((title.as_str(), body.as_str()), Notice::WrongRoute.text());
        assert!(!body.contains("alert-"), "提示编号不进通知正文");

        for payload in [
            json!({"event": "WRONG_ROUTE", "ref": "a", "title": "x"}),
            json!({"event": "WRONG_ROUTE", "ref": "a", "body": "api.anthropic.com"}),
        ] {
            assert!(notify_critical(&sink, &payload).unwrap_err().starts_with("NOTIFY_FIELD_FORBIDDEN"));
        }
        assert!(notify_critical(&sink, &json!({"event": "ARCHIVE_DONE", "ref": "a"})).unwrap_err().starts_with("NOTIFY_EVENT_UNKNOWN"));
        assert!(notify_critical(&sink, &json!({"event": "RUNNING_IN_BACKGROUND", "ref": "a"})).unwrap_err().starts_with("NOTIFY_EVENT_UNKNOWN"), "页面不能请求后台提示");
        assert!(notify_critical(&sink, &json!({"event": "WRONG_ROUTE", "ref": "C:\\Users\\x"})).unwrap_err().starts_with("NOTIFY_REF_INVALID"));
        assert_eq!(sink.shown.lock().unwrap().len(), 1, "被拒的请求什么都没弹");
    }

    #[test]
    fn a_visible_window_is_not_notified_and_a_failed_notification_is_not_reported_as_shown() {
        let sink = RecordingNotices::default();
        *sink.visible.lock().unwrap() = true;
        let skipped = notify_critical(&sink, &json!({"event": "PROTECTION_FAILED", "ref": "a"})).unwrap();
        assert_eq!(skipped["status"], "SKIPPED_WINDOW_VISIBLE");
        *sink.visible.lock().unwrap() = false;
        *sink.failure.lock().unwrap() = Some("NOTIFICATION_FAILED: toast service unavailable".to_string());
        let failed = notify_critical(&sink, &json!({"event": "PROTECTION_NOT_CONFIRMED", "ref": "a"})).unwrap();
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["status"], "FAILED");
        assert_eq!(failed["code"], "NOTIFICATION_FAILED");
        let unavailable = notify_critical(&UnavailableNotices, &json!({"event": "WRONG_ROUTE", "ref": "a"})).unwrap();
        assert_eq!(unavailable["code"], "NOTIFICATION_UNAVAILABLE");
    }

    #[test]
    fn fixed_texts_carry_no_variable_content() {
        for notice in [Notice::WrongRoute, Notice::ProtectionNotConfirmed, Notice::ProtectionFailed, Notice::RunningInBackground] {
            let (title, body) = notice.text();
            for text in [title, body] {
                assert!(!text.contains('{') && !text.contains('/') && !text.contains('\\'), "{text}");
            }
        }
    }

    #[test]
    fn the_background_notice_is_shown_once_and_retried_when_it_could_not_be_shown() {
        let base = root("background");
        let marker = background_marker(&base.join("workspace"));
        assert!(marker.starts_with(base.join("host-state")), "标记在工作区外");
        let sink = RecordingNotices::default();
        *sink.failure.lock().unwrap() = Some("NOTIFICATION_FAILED: off".to_string());
        assert!(announce_background(&sink, &marker).is_err());
        assert!(!marker.exists(), "没弹出来就不写标记");
        *sink.failure.lock().unwrap() = None;
        assert_eq!(announce_background(&sink, &marker).unwrap(), true);
        assert_eq!(announce_background(&sink, &marker).unwrap(), false, "之后关窗不再提示");
        assert_eq!(sink.shown.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }
}
