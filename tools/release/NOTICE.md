# AI Environmental Steward：组件、许可与对应源码

本发布包里的程序与许可如下。版本号以同目录 `release-manifest.json`（安装目录根下）为准；本文件由发布清单 `tools/release/release-inputs.json` 维护。

| 组件 | 安装位置 | 来源 | 许可 |
|---|---|---|---|
| 桌面宿主与页面 | `<安装目录>\*.exe`、内嵌页面 | 本项目源码（`apps/desktop-host/src-tauri`、`apps/desktop-ui`、`src`） | GPL-3.0-only，见 `GPL-3.0.txt` |
| 本地控制端 | `control\ai-steward-control.exe` | 本项目源码 `services/control-rs` | GPL-3.0-only，见 `GPL-3.0.txt` |
| 产品网络服务及安装、卸载助手 | `service\` | 本项目 `apps/desktop-host/vendor/service-ipc`，改自 clash-verge-service-ipc 2.3.3（提交 `b964ed2992599fadefd589425c1acdabcb875623`） | GPL-3.0-only（上游清单旧标识 GPL-3.0，经本次澄清），见 `service-ipc-LICENSE.txt` |
| Mihomo v1.19.30 | `service\core\mihomo-windows-amd64-v1.19.30.exe` | MetaCubeX/mihomo，标签 v1.19.30，提交 `ac017cdd246ce8bd547653d927e7bf77d7ee73d5` | GPL-3.0，见 `GPL-3.0.txt` |
| 日志收集脚本 | `support\collect-logs.ps1`、`support\collect-logs.cmd` | 本项目源码 `tools/release` | GPL-3.0-only |
| js-yaml 4.3.0 | 内嵌页面（受管配置 YAML 编译） | npm `js-yaml@4.3.0`，与 CVR v2.5.2 锁定版本相同 | MIT，见 `js-yaml-LICENSE.txt` |
| Rust 依赖（Tauri 等） | 编进上述程序 | crates.io，版本见各自 `Cargo.lock` | 见 `THIRD-PARTY-RUST.txt` |
| Mozilla 根证书数据（crate `webpki-roots`，已核对版本 1.0.9） | 编进 `control\ai-steward-control.exe`，经 `ureq` 3.4.2 的默认 TLS 配置引入 | crates.io `webpki-roots`，内容是 Mozilla 的根证书列表；实际版本以 `services/control-rs/Cargo.lock` 与 `THIRD-PARTY-RUST.txt` 为准 | CDLA-Permissive-2.0，协议全文见随包的 `THIRD-PARTY-RUST.txt` |
| WebView2 运行时 | 系统组件，安装器按需引导安装 | Microsoft | 微软再分发条款 |

## 对应源码

本安装包的对应源码归档是 `e54-corresponding-source.zip`，与安装包放在同一个候选产物（GitHub Actions 产物 `e54-candidate`）里提供。其中有一个组件没有源码，见本节末尾。取得步骤：

1. 在取得本安装包的同一处，下载同一次构建运行的 `e54-candidate` 产物，并解压。
2. 取出 `build/source/e54-corresponding-source.zip`，核对它的 SHA-256 与同目录 `build/source/e54-corresponding-source.json` 里 `archive.sha256` 一致。
3. 解压源码 ZIP。`e54-corresponding-source/SOURCE-MANIFEST.json` 的 `mirror_commit` 是这次构建所用的本项目精确提交（40 位），`mihomo.commit` 是 Mihomo 的固定提交 `ac017cdd246ce8bd547653d927e7bf77d7ee73d5`；该文件还写明四份 `Cargo.lock` 的哈希，以及每个文件的来源和 SHA-256。`BUILD.md` 写明构建步骤与工具版本。
4. 可以离线复核：`node e54-corresponding-source/first-party/tools/release/e54/corresponding-source.mjs verify e54-corresponding-source.zip`。

安装包本身的 SHA-256 与构建提交也记在同一产物里：分别在 `build/logs/e54-hashes.json` 和 `build/logs/e54-run.json` 的 `sha` 字段。

源码 ZIP 包含：

- 本项目在构建提交的全部源码与构建、安装脚本，包括改造后的 service-ipc 和四份 `Cargo.lock`；
- Mihomo 固定提交的官方源码归档；
- 构建所用的全部 Rust crate 原始包，以及 Mihomo 的 Go 模块包；
- Mihomo 经 Go 模块 `sing-tun` 内嵌的 Wintun 0.14.1：官方标签源码快照（提交 `bfef136abfa1665c2592be09a7e383d646cdbe6e`，源码许可见其中的 `COPYING`）和附预编译件许可的官方发布件。内嵌的 `wintun.dll` 与官方发布件逐字节相同。

各组件的许可与版权声明都原样保留。安装器自带的 NSIS 运行时与插件、WebView2 引导程序不属于 GPL 作品，不随附源码，已在 `SOURCE-MANIFEST.json` 的 `not_included` 里列明。

**没有源码的组件**：桌面宿主在 MSVC 目标下静态链接了微软 WebView2 加载器库（`WebView2LoaderStatic.lib`，来自 crate `webview2-com-sys`）。它没有源码，源码 ZIP 里只有 crate 自带的预编译原件，也在 `not_included` 里列明。
