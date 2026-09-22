//! 产品命名空间与状态目录。上游 `paths.rs` 固定 `clash-verge-service` 名称与 `\\.\pipe\clash-verge-service`，
//! 这里整体改为本产品标识；客户端（桌面宿主）与服务端共用同一份常量。

use std::path::{Component, Path, PathBuf};

pub const PRODUCT_APP_ID: &str = "local.ai-environmental-steward.desktop";
pub const SERVICE_NAME: &str = "ai_environmental_steward_service";
pub const SERVICE_DISPLAY_NAME: &str = "AI Environmental Steward Network Service";
pub const SERVICE_EXE: &str = "ai-environmental-steward-service.exe";
pub const SERVICE_PIPE: &str = r"\\.\pipe\ai-environmental-steward-service";
pub const CORE_PIPE: &str = r"\\.\pipe\ai-environmental-steward-mihomo";
pub const TEST_SERVICE_PIPE: &str = r"\\.\pipe\ai-environmental-steward-service-test";
pub const STATE_DIR_NAME: &str = "ai-environmental-steward-service";
pub const CORE_BINARY_NAME: &str = "mihomo-windows-amd64-v1.19.30.exe";
pub const PROTOCOL: &str = "steward-network-service-1";
pub const KERNEL_VERSION: &str = "v1.19.30";

/// Mihomo 控制 pipe 默认允许所有本机用户（BU）读写且不校验 secret；
/// 服务启动内核时用 `LISTEN_NAMEDPIPE_SDDL` 收窄到只有 LocalSystem（即本服务）。
pub const CORE_PIPE_SDDL: &str = "D:PAI(A;OICI;GWGR;;;SY)";

/// 产品常量与正式依赖路径里不得出现的上游身份与默认控制器地址。
pub const FORBIDDEN_IDENTITY_MARKERS: [&str; 5] =
    ["clash-verge", "clash_verge", "verge-mihomo", "127.0.0.1:9090", "localhost:9090"];

pub fn identity_constants() -> Vec<(&'static str, &'static str)> {
    vec![
        ("app_id", PRODUCT_APP_ID),
        ("service_name", SERVICE_NAME),
        ("service_display_name", SERVICE_DISPLAY_NAME),
        ("service_exe", SERVICE_EXE),
        ("service_pipe", SERVICE_PIPE),
        ("core_pipe", CORE_PIPE),
        ("test_pipe", TEST_SERVICE_PIPE),
        ("state_dir", STATE_DIR_NAME),
        ("core_binary", CORE_BINARY_NAME),
        ("protocol", PROTOCOL),
    ]
}

pub fn forbidden_marker(text: &str) -> Option<&'static str> {
    let lowered = text.to_ascii_lowercase();
    FORBIDDEN_IDENTITY_MARKERS.iter().copied().find(|marker| lowered.contains(marker))
}

pub fn valid_user_sid(sid: &str) -> bool {
    sid.len() <= 184
        && sid.starts_with("S-1-5-21-")
        && sid["S-1-5-21-".len()..].split('-').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// 与 FILE_APPEND_DATA 同值；FILE_GENERIC_WRITE（SDDL 的 GW）因此包含它。
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;

/// 批准用户连服务 pipe 的精确权限：读（数据、属性、扩展属性、DACL、SYNCHRONIZE）+ 写数据 + 写属性。
/// Microsoft「Named Pipe Security and Access Rights」：FILE_GENERIC_WRITE 含 FILE_CREATE_PIPE_INSTANCE，应改用单项权限；
/// 否则批准用户下的任意进程都能给同名 pipe 再建实例、冒充服务收请求。客户端打开 pipe 时请求的正是这个掩码。
pub const PIPE_CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;

/// 服务 pipe 的所有者：服务以 LocalSystem 运行并在安全描述符里显式声明，客户端发送前核对它。
pub const SERVICE_PIPE_OWNER_SID: &str = "S-1-5-18";

/// 服务 IPC 的 pipe 安全描述符：所有者与主组为 LocalSystem；LocalSystem 与 Administrators 全权，安装时批准的本机用户只有 `PIPE_CLIENT_ACCESS`。
/// 取代上游 `D:(A;;GA;;;WD)`（Everyone 全权）；没有批准用户时只剩 SY/BA，普通用户连不上。
pub fn service_pipe_sddl(approved_user_sid: Option<&str>) -> String {
    let mut sddl = String::from("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = approved_user_sid.filter(|sid| valid_user_sid(sid)) {
        sddl.push_str(&format!("(A;;0x{PIPE_CLIENT_ACCESS:08x};;;{sid})"));
    }
    sddl
}

#[derive(Debug, Clone)]
pub struct ServicePaths {
    state_dir: PathBuf,
    install_dir: PathBuf,
}

impl ServicePaths {
    /// 正式路径：状态在 `%ProgramData%\ai-environmental-steward-service`，程序与内核在服务程序所在目录。
    /// 取不到 ProgramData 时报错，不退回当前目录。
    pub fn product() -> Result<ServicePaths, String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "SERVICE_PATHS_UNAVAILABLE: ProgramData is not set".to_string())?;
        let exe = std::env::current_exe().map_err(|error| format!("SERVICE_PATHS_UNAVAILABLE: {error}"))?;
        let install_dir = exe
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "SERVICE_PATHS_UNAVAILABLE: service executable has no directory".to_string())?;
        Ok(ServicePaths::rooted(PathBuf::from(program_data).join(STATE_DIR_NAME), install_dir))
    }

    pub fn rooted(state_dir: PathBuf, install_dir: PathBuf) -> ServicePaths {
        ServicePaths { state_dir, install_dir }
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.state_dir.join("run")
    }

    pub fn core_home(&self) -> PathBuf {
        self.state_dir.join("core")
    }

    pub fn configs_dir(&self) -> PathBuf {
        self.core_home().join("configs")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.state_dir.join("logs")
    }

    pub fn install_record(&self) -> PathBuf {
        self.state_dir.join("install.json")
    }

    /// 宿主与服务共用的 envelope 密钥：安装器写入，只有 SY/BA 与批准用户可读。
    pub fn host_link_key(&self) -> PathBuf {
        self.state_dir.join("link").join("host-link.key")
    }

    pub fn runtime_state(&self) -> PathBuf {
        self.state_dir.join("runtime-state.json")
    }

    pub fn owner_lock(&self) -> PathBuf {
        self.runtime_dir().join(format!("{STATE_DIR_NAME}.owner.lock"))
    }

    pub fn pid_file(&self) -> PathBuf {
        self.runtime_dir().join(format!("{STATE_DIR_NAME}.pid"))
    }

    pub fn core_runtime(&self) -> PathBuf {
        self.runtime_dir().join(format!("{STATE_DIR_NAME}.core.json"))
    }

    /// 固定内核程序：只认服务程序目录下 `core\` 里的 v1.19.30，不从 IPC 接受路径，也不下载 latest。
    pub fn core_binary(&self) -> PathBuf {
        self.install_dir.join("core").join(CORE_BINARY_NAME)
    }

    pub fn service_binary(&self) -> PathBuf {
        self.install_dir.join(SERVICE_EXE)
    }
}

/// 词法核对：候选路径是绝对路径、不含 `.`/`..`，且逐段落在 root 之下（大小写不敏感）。
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    if !root.is_absolute() || !candidate.is_absolute() {
        return false;
    }
    if candidate.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    let lower = |path: &Path| -> Vec<String> {
        path.components().map(|part| part.as_os_str().to_string_lossy().to_lowercase()).collect()
    };
    let root_parts = lower(root);
    let parts = lower(candidate);
    parts.len() > root_parts.len() && parts[..root_parts.len()] == root_parts[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_identity_constant_uses_the_product_namespace() {
        for (name, value) in identity_constants() {
            assert_eq!(forbidden_marker(value), None, "{name} = {value}");
            assert!(!value.contains("9090"), "{name} 不得指向默认控制器端口");
        }
        assert!(SERVICE_PIPE.starts_with(r"\\.\pipe\ai-environmental-steward"));
        assert!(CORE_PIPE.starts_with(r"\\.\pipe\ai-environmental-steward"));
        assert_ne!(SERVICE_PIPE, TEST_SERVICE_PIPE);
        let paths = ServicePaths::rooted(std::env::temp_dir().join(STATE_DIR_NAME), std::env::temp_dir().join("install"));
        for path in [paths.owner_lock(), paths.pid_file(), paths.core_runtime(), paths.runtime_state(), paths.core_binary(), paths.host_link_key()] {
            assert_eq!(forbidden_marker(&path.to_string_lossy()), None, "{}", path.display());
        }
        let upstream_pipe = format!(r"\\.\pipe\{}-{}-service", "clash", "verge");
        assert!(forbidden_marker(&upstream_pipe).is_some());
        assert!(forbidden_marker(&format!("http://127.0.0.1:{}", 9090)).is_some());
    }

    #[test]
    fn service_pipe_acl_replaces_the_upstream_world_writable_descriptor() {
        let upstream = "D:(A;;GA;;;WD)";
        let closed = service_pipe_sddl(None);
        assert!(!closed.contains(";;;WD)"), "不能再给 Everyone");
        assert!(!closed.contains(";;;BU)"), "不能给所有本机用户");
        assert_eq!(closed, "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert!(closed.starts_with("O:SY"), "所有者显式为 LocalSystem，客户端据此认证服务端");
        assert_eq!(SERVICE_PIPE_OWNER_SID, "S-1-5-18");
        assert_ne!(closed, upstream);
        let approved = service_pipe_sddl(Some("S-1-5-21-1000-2000-3000-1001"));
        assert!(approved.ends_with("(A;;0x0012018b;;;S-1-5-21-1000-2000-3000-1001)"), "{approved}");
        let user_rights = approved.trim_start_matches("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert!(!user_rights.contains("GW") && !user_rights.contains("GA"), "批准用户不能拿到泛型写或全权");
        assert_eq!(PIPE_CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0, "批准用户不能给服务 pipe 建实例");
        assert_eq!(PIPE_CLIENT_ACCESS & (FILE_READ_DATA | FILE_WRITE_DATA), FILE_READ_DATA | FILE_WRITE_DATA, "仍能读写数据");
        assert_eq!(PIPE_CLIENT_ACCESS, 0x0012_018b);
        assert_eq!(service_pipe_sddl(Some("WD")), closed, "非法 SID 不能混进 ACL");
        assert_eq!(service_pipe_sddl(Some("S-1-5-21-1)(A;;GA;;;WD")), closed);
        assert!(CORE_PIPE_SDDL.contains(";;;SY)") && !CORE_PIPE_SDDL.contains(";;;BU)"));
    }

    #[test]
    fn draft_paths_must_stay_inside_the_approved_root() {
        let root = std::env::temp_dir().join("steward-network").join("drafts");
        assert!(is_within(&root, &root.join("op-1.yaml")));
        assert!(!is_within(&root, &root), "根目录本身不是草稿文件");
        assert!(!is_within(&root, &root.join("..").join("escape.yaml")));
        assert!(!is_within(&root, &std::env::temp_dir().join("elsewhere.yaml")));
        assert!(!is_within(&root, Path::new("relative.yaml")));
    }
}
