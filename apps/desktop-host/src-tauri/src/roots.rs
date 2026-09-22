//! 授权根：用户本地确认过、允许本应用只读扫描的真实目录或文件。
//!
//! - 登记表存在授权保险库（工作区之外），整份带宿主 HMAC；受限原生桥的文件操作到不了它，页面也造不出一条登记。
//! - 页面只能用 `roots/<root_ref>/<相对路径>` 指代真实对象；解析时只认登记表里的根，拒绝越界、`..`、绝对路径与链接。
//! - 登记只放行读。改写真实对象仍要单次确认绑定精确目标；工作区自有授权的路径前缀不含 `roots/`，碰不到这里。
//! - 路径在授权当时由宿主重新发现、自己测得，确认框里显示的就是这份路径；调用方给的路径一律不作数。
//!
//! 本机没有 cargo/rustc，这个模块尚未编译。

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::workspace;

pub const ROOTS_PREFIX: &str = "roots/";
const REGISTRY_FILE: &str = "authorized-roots.json";
const MAX_ROOTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    Directory,
    File,
}

impl RootKind {
    pub fn label(self) -> &'static str {
        match self {
            RootKind::Directory => "directory",
            RootKind::File => "file",
        }
    }

    pub fn parse(text: &str) -> Option<RootKind> {
        match text {
            "directory" => Some(RootKind::Directory),
            "file" => Some(RootKind::File),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedRoot {
    pub root_ref: String,
    pub path: PathBuf,
    pub kind: RootKind,
    pub client_ref: String,
    pub category: String,
    pub environment_ref: String,
    pub authorized_at: String,
}

/// 根引用只用小写字母、数字与连字符，避免与路径分隔或大小写折叠混淆。
pub fn valid_root_ref(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !text.starts_with('-')
}

fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|meta| meta.file_type().is_symlink()).unwrap_or(false)
}

impl AuthorizedRoot {
    pub fn to_value(&self) -> Value {
        json!({
            "root_ref": self.root_ref,
            "path": self.path.to_string_lossy(),
            "kind": self.kind.label(),
            "client_ref": self.client_ref,
            "category": self.category,
            "environment_ref": self.environment_ref,
            "authorized_at": self.authorized_at,
        })
    }

    pub fn from_value(value: &Value) -> Option<AuthorizedRoot> {
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
        let root_ref = text("root_ref")?;
        if !valid_root_ref(&root_ref) {
            return None;
        }
        Some(AuthorizedRoot {
            root_ref,
            path: PathBuf::from(text("path")?),
            kind: RootKind::parse(&text("kind")?)?,
            client_ref: text("client_ref")?,
            category: text("category")?,
            environment_ref: text("environment_ref")?,
            authorized_at: text("authorized_at")?,
        })
    }

    /// 根内解析：文件根没有子路径；目录根按工作区同一规则收窄，根本身和途经的任何一段都不能是链接。
    pub fn resolve(&self, inner: &str) -> Result<PathBuf, String> {
        if is_link(&self.path) {
            return Err(format!("NATIVE_PATH_OUT_OF_SCOPE: authorized root {} is a link", self.root_ref));
        }
        let inner = inner.trim_end_matches('/');
        match self.kind {
            RootKind::File if inner.is_empty() => Ok(self.path.clone()),
            RootKind::File => Err(format!("NATIVE_PATH_OUT_OF_SCOPE: {} is a single-file root", self.root_ref)),
            RootKind::Directory if inner.is_empty() => Ok(self.path.clone()),
            RootKind::Directory => workspace::resolve(&self.path, inner),
        }
    }
}

fn registry_path(vault_root: &Path) -> PathBuf {
    vault_root.join(REGISTRY_FILE)
}

fn registry_mac(key: &[u8], rows: &[Value]) -> Result<String, String> {
    let canonical = serde_json::to_string(&Value::Array(rows.to_vec())).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    Ok(workspace::hmac_hex(key, canonical.as_bytes()))
}

/// 读登记表并核对宿主签名；文件不存在就是还没有授权任何根。签名对不上时整份作废，不猜哪几条还可信。
pub fn load(vault_root: &Path) -> Result<Vec<AuthorizedRoot>, String> {
    let text = match fs::read_to_string(registry_path(vault_root)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("NATIVE_IO_FAILED: {error}")),
    };
    let parsed: Value = serde_json::from_str(&text).map_err(|_| "NATIVE_ROOTS_TAMPERED: the authorized root registry is not valid JSON".to_string())?;
    let rows = parsed.get("roots").and_then(Value::as_array).cloned().unwrap_or_default();
    let key = workspace::vault_key(vault_root)?;
    let stored = parsed.get("mac").and_then(Value::as_str).unwrap_or_default();
    if !workspace::constant_time_eq(stored, &registry_mac(&key, &rows)?) {
        return Err("NATIVE_ROOTS_TAMPERED: the authorized root registry does not match its host signature".into());
    }
    rows.iter()
        .map(|row| AuthorizedRoot::from_value(row).ok_or_else(|| "NATIVE_ROOTS_TAMPERED: the registry holds a malformed root".to_string()))
        .collect()
}

pub fn save(vault_root: &Path, roots: &[AuthorizedRoot]) -> Result<(), String> {
    if roots.len() > MAX_ROOTS {
        return Err(format!("NATIVE_PAYLOAD_INVALID: at most {MAX_ROOTS} roots can be authorized"));
    }
    let key = workspace::vault_key(vault_root)?;
    let rows: Vec<Value> = roots.iter().map(AuthorizedRoot::to_value).collect();
    let document = json!({"version": 1, "roots": rows, "mac": registry_mac(&key, &rows)?});
    fs::create_dir_all(vault_root).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let text = serde_json::to_string_pretty(&document).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    let staging = vault_root.join(format!("{REGISTRY_FILE}.tmp"));
    fs::write(&staging, format!("{text}\n")).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))?;
    fs::rename(&staging, registry_path(vault_root)).map_err(|error| format!("NATIVE_IO_FAILED: {error}"))
}

/// 新授权覆盖同名旧授权，其余保留；撤销只删点名的根。
pub fn merged(existing: &[AuthorizedRoot], added: &[AuthorizedRoot]) -> Vec<AuthorizedRoot> {
    let mut next: Vec<AuthorizedRoot> = existing.iter().filter(|item| !added.iter().any(|new| new.root_ref == item.root_ref)).cloned().collect();
    next.extend(added.iter().cloned());
    next.sort_by(|left, right| left.root_ref.cmp(&right.root_ref));
    next
}

pub fn without(existing: &[AuthorizedRoot], refs: &[String]) -> Vec<AuthorizedRoot> {
    existing.iter().filter(|item| !refs.contains(&item.root_ref)).cloned().collect()
}

/// 受限文件能力的解析范围：普通相对路径落在产品工作区，`roots/<ref>/…` 只落在已登记的根里。
pub struct Scope<'a> {
    pub workspace: &'a Path,
    pub roots: &'a [AuthorizedRoot],
}

impl<'a> Scope<'a> {
    pub fn workspace_only(workspace: &'a Path) -> Scope<'a> {
        Scope { workspace, roots: &[] }
    }

    pub fn is_real(relative: &str) -> bool {
        let normalized = relative.replace('\\', "/");
        normalized == "roots" || normalized.starts_with(ROOTS_PREFIX)
    }

    pub fn resolve(&self, relative: &str) -> Result<PathBuf, String> {
        let normalized = relative.replace('\\', "/");
        if !Scope::is_real(&normalized) {
            return workspace::resolve(self.workspace, relative);
        }
        let rest = normalized.strip_prefix(ROOTS_PREFIX).unwrap_or("");
        let (root_ref, inner) = rest.split_once('/').unwrap_or((rest, ""));
        if !valid_root_ref(root_ref) {
            return Err("NATIVE_PATH_OUT_OF_SCOPE: a real path must name an authorized root".into());
        }
        let root = self
            .roots
            .iter()
            .find(|item| item.root_ref == root_ref)
            .ok_or_else(|| format!("NATIVE_PATH_OUT_OF_SCOPE: {root_ref} is not an authorized root"))?;
        root.resolve(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(label: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("steward-roots-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn root(reference: &str, path: PathBuf, kind: RootKind) -> AuthorizedRoot {
        AuthorizedRoot {
            root_ref: reference.to_string(),
            path,
            kind,
            client_ref: "claude-code".to_string(),
            category: "claude_code".to_string(),
            environment_ref: "windows-host".to_string(),
            authorized_at: "2026-09-17T00:00:00.000Z".to_string(),
        }
    }

    #[test]
    fn real_paths_resolve_only_inside_registered_roots() {
        let base = temp("resolve");
        let workspace = base.join("workspace");
        let home = base.join("home").join(".claude");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(home.join("projects")).unwrap();
        fs::write(home.join("settings.json"), "{}").unwrap();
        fs::write(base.join("home").join(".claude.json"), "{}").unwrap();
        let roots = vec![
            root("claude-code-home", home.clone(), RootKind::Directory),
            root("claude-code-state", base.join("home").join(".claude.json"), RootKind::File),
        ];
        let scope = Scope { workspace: &workspace, roots: &roots };
        assert_eq!(scope.resolve("roots/claude-code-home/settings.json").unwrap(), home.join("settings.json"));
        assert_eq!(scope.resolve("roots/claude-code-home").unwrap(), home);
        assert_eq!(scope.resolve("roots/claude-code-state").unwrap(), base.join("home").join(".claude.json"));
        assert!(scope.resolve("roots/claude-code-state/x").is_err(), "文件根没有子路径");
        assert!(scope.resolve("roots/claude-code-home/../../secret").is_err(), "不能越出根");
        assert!(scope.resolve("roots/chrome-default/Network/Cookies").is_err(), "没登记的根不解析");
        assert!(scope.resolve("roots/Claude-Code-Home/settings.json").is_err(), "根引用大小写敏感");
        assert!(scope.resolve("roots").is_err());
        assert_eq!(scope.resolve("records/a.json").unwrap(), workspace.join("records").join("a.json"), "普通路径仍在工作区");
        let workspace_only = Scope::workspace_only(&workspace);
        assert!(workspace_only.resolve("roots/claude-code-home/settings.json").is_err(), "工作区范围碰不到真实根");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_registry_is_signed_and_rejects_edits_made_outside_the_host() {
        let base = temp("registry");
        let vault = base.join("vault");
        assert!(load(&vault).unwrap().is_empty(), "还没有授权");
        let first = vec![root("claude-code-home", base.join("home"), RootKind::Directory)];
        save(&vault, &first).unwrap();
        assert_eq!(load(&vault).unwrap(), first);

        let added = merged(&first, &[root("cc-switch", base.join("cc"), RootKind::Directory)]);
        assert_eq!(added.len(), 2);
        save(&vault, &added).unwrap();
        assert_eq!(load(&vault).unwrap().len(), 2);
        assert_eq!(without(&added, &["cc-switch".to_string()]).len(), 1);

        let path = registry_path(&vault);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("cc-switch", "cc-switcx")).unwrap();
        assert!(load(&vault).unwrap_err().starts_with("NATIVE_ROOTS_TAMPERED"), "改一条引用整份作废");
        let _ = fs::remove_dir_all(&base);
    }
}
