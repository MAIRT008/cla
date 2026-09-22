# AI Environmental Steward：组件、许可与对应源码

本发布包里的程序与许可如下。版本号以同目录 `release-manifest.json`（安装目录根下）为准；本文件由发布清单 `tools/release/release-inputs.json` 维护。

| 组件 | 安装位置 | 来源 | 许可 |
|---|---|---|---|
| 桌面宿主与页面 | `<安装目录>\*.exe`、内嵌页面 | 本项目源码（`apps/desktop-host/src-tauri`、`apps/desktop-ui`、`src`） | GPL-3.0-only，见 `GPL-3.0.txt` |
| 本地控制端 | `control\ai-steward-control.exe` | 本项目源码 `services/control-rs` | GPL-3.0-only，见 `GPL-3.0.txt` |
| 产品网络服务及安装、卸载助手 | `service\` | 本项目 `apps/desktop-host/vendor/service-ipc`，改自 clash-verge-service-ipc 2.3.3（提交 `b964ed2992599fadefd589425c1acdabcb875623`） | GPL-3.0，见 `service-ipc-LICENSE.txt` |
| Mihomo v1.19.30 | `service\core\mihomo-windows-amd64-v1.19.30.exe` | MetaCubeX/mihomo，标签 v1.19.30，提交 `ac017cdd246ce8bd547653d927e7bf77d7ee73d5` | GPL-3.0，见 `GPL-3.0.txt` |
| 日志收集脚本 | `support\collect-logs.ps1`、`support\collect-logs.cmd` | 本项目源码 `tools/release` | GPL-3.0-only |
| js-yaml 4.3.0 | 内嵌页面（受管配置 YAML 编译） | npm `js-yaml@4.3.0`，与 CVR v2.5.2 锁定版本相同 | MIT，见 `js-yaml-LICENSE.txt` |
| Rust 依赖（Tauri 等） | 编进上述程序 | crates.io，版本见各自 `Cargo.lock` | 见 `THIRD-PARTY-RUST.txt` |
| WebView2 运行时 | 系统组件，安装器按需引导安装 | Microsoft | 微软再分发条款 |

对应源码：以上 GPL 组件的完整对应源码（含本项目源码、上游固定提交与构建用 `Cargo.lock`）随发布一同提供。提供方式（随包附带或书面提供）由发布方在公开分发前确定，确定前本发布候选不公开分发。
