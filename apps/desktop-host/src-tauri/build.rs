fn main() {
    // 只有 tauri 特性需要：生成权限清单、嵌入图标与 Windows 清单，并核对 tauri.conf.json 引用的资源存在。
    // 默认特性（纯逻辑单元测试）不跑它，也不依赖装配目录。
    #[cfg(feature = "tauri")]
    tauri_build::build();
}
