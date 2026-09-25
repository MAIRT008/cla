# 发布输入、来源、校验与许可

日期：2026-09-21（RC6）。权威清单是 `tools/release/release-inputs.json`（显式 allowlist）；本页是它的人读版本，「本机状态」一列是 2026-09-21 在开发机上跑 `node tools/release/release.mjs check` 的结果，总体 `NOT_READY`（RC6 Round 2 复跑：七个构建工具都是必需项，只有探测到才算数；本机只有 node 与 powershell）。构建机步骤见 [build-packaging.md](build-packaging.md)。2026-09-25 按 E54 首次 pin 的 Codex 裁决同步：Mihomo 的 EXE 哈希已固定，本机仍没有程序本身，所以该项只剩 `MISSING`；其余各项与 2026-09-21 的检查结果相同。

分类：**普通用户运行文件**进 `install\` 随安装包安装；**许可与对应源码材料**进 `install\licenses\`；**构建输入**只把哈希记进 `release-manifest.json`；**构建机工具**与**异机测试材料**不入包。清单没列的文件，装配工具不会复制。

| 编号 | 分类 | 来源 → 安装位置 | 本机状态 | 校验 | 许可 | 固定来源 / 说明 |
|---|---|---|---|---|---|---|
| control | 普通用户运行文件 | `services/control-rs/target/release/ai-steward-control.exe` → `control/ai-steward-control.exe` | MISSING | 装配时记录 SHA-256 | license-gpl | cargo build --release --manifest-path services/control-rs/Cargo.toml |
| service | 普通用户运行文件 | `apps/desktop-host/vendor/service-ipc/target/release/ai-environmental-steward-service.exe` → `service/ai-environmental-steward-service.exe` | MISSING | 装配时记录 SHA-256 | license-service-ipc | cargo build --release --features service --manifest-path apps/desktop-host/vendor/service-ipc/Cargo.toml |
| service-install | 普通用户运行文件 | `apps/desktop-host/vendor/service-ipc/target/release/ai-environmental-steward-service-install.exe` → `service/ai-environmental-steward-service-install.exe` | MISSING | 装配时记录 SHA-256 | license-service-ipc | 同上 |
| service-uninstall | 普通用户运行文件 | `apps/desktop-host/vendor/service-ipc/target/release/ai-environmental-steward-service-uninstall.exe` → `service/ai-environmental-steward-service-uninstall.exe` | MISSING | 装配时记录 SHA-256 | license-service-ipc | 同上 |
| mihomo | 普通用户运行文件 | `build/inputs/mihomo-windows-amd64-v1.19.30.exe` → `service/core/mihomo-windows-amd64-v1.19.30.exe` | MISSING（哈希已固定） | 固定 SHA-256 f55b3028d916…（解压后的 EXE） | license-gpl | MetaCubeX/mihomo release v1.19.30（release id 371291937），对应源码提交 ac017cdd246ce8bd547653d927e7bf77d7ee73d5。E54 首次 pin 于 2026-09-22 在 GitHub runner 上按官方 release 元数据核对：资产 `mihomo-windows-amd64-v1.19.30.zip` 18,499,620 字节，归档 SHA-256 22c09fd67673…；其中唯一的 `mihomo-windows-amd64.exe` 是 AMD64 程序，SHA-256 f55b3028d9160beb9044f21b05dd7405b46524614a19642d6291492f5f985761 |
| collect-logs | 普通用户运行文件 | `tools/release/collect-logs.ps1` → `support/collect-logs.ps1` | 有 | 装配时记录 SHA-256 | license-gpl | 本仓库 |
| collect-logs-cmd | 普通用户运行文件 | `tools/release/collect-logs.cmd` → `support/collect-logs.cmd` | 有 | 装配时记录 SHA-256 | license-gpl | 本仓库 |
| license-gpl | 许可与对应源码材料 | `tools/release/licenses/GPL-3.0.txt` → `licenses/GPL-3.0.txt` | 有 | 固定 SHA-256 3972dc9744f6… | （本身是许可材料） | 与 Mihomo v1.19.30、CVR v2.5.2 固定源码的 LICENSE 逐字节一致 |
| license-service-ipc | 许可与对应源码材料 | `apps/desktop-host/vendor/service-ipc/LICENSE` → `licenses/service-ipc-LICENSE.txt` | 有 | 固定 SHA-256 8b1ba204bb69… | （本身是许可材料） | 上游 clash-verge-service-ipc 2.3.3 @ b964ed29 的 LICENSE |
| license-js-yaml | 许可与对应源码材料 | `vendor/deps/js-yaml-4.3.0/LICENSE` → `licenses/js-yaml-LICENSE.txt` | 有 | 固定 SHA-256 a07bc24468b9… | （本身是许可材料） | js-yaml 4.3.0（npm，CVR pnpm-lock 锁定版本；vendor/deps/js-yaml-4.3.0/SOURCE.json），随页面装入 |
| notice | 许可与对应源码材料 | `tools/release/NOTICE.md` → `licenses/NOTICE.md` | 有 | 装配时记录 SHA-256 | （本身是许可材料） | 本仓库：组件、版本、许可与对应源码取得方式 |
| rust-third-party | 许可与对应源码材料 | `build/inputs/THIRD-PARTY-RUST.txt` → `licenses/THIRD-PARTY-RUST.txt` | MISSING | 装配时记录 SHA-256 | （本身是许可材料） | 构建机按三份 Cargo.lock 用 cargo-about 生成的 Rust 依赖许可汇总 |
| lock-host | 构建输入（只记哈希） | `apps/desktop-host/src-tauri/Cargo.lock` | MISSING | 装配时记录 SHA-256 | — | 构建机 cargo 生成；哈希记进 release-manifest.json |
| lock-control | 构建输入（只记哈希） | `services/control-rs/Cargo.lock` | MISSING | 装配时记录 SHA-256 | — | 同上 |
| lock-service | 构建输入（只记哈希） | `apps/desktop-host/vendor/service-ipc/Cargo.lock` | MISSING | 装配时记录 SHA-256 | — | 同上 |
| rustc | 构建机工具 | — | TOOL_MISSING | 探测 rustc --version | — | ≥ 1.85；复用决策记 1.95 |
| cargo | 构建机工具 | — | TOOL_MISSING | 探测 cargo --version | — |  |
| tauri-cli | 构建机工具 | — | TOOL_MISSING | 探测 cargo tauri --version | — | 2.x，与 tauri 2.11.5 配套 |
| cargo-about | 构建机工具 | — | TOOL_MISSING | 探测 cargo about --version | — | 生成 THIRD-PARTY-RUST.txt；版本在构建机固定并记录 |
| node | 构建机工具 | — | 有 | 探测 node --version | — | ≥ 22，只跑 tools/release 与页面包生成 |
| powershell | 构建机工具 | — | 有 | 探测 powershell.exe -NoProfile -Command $PSVersionTable.PSVersion.ToString() | — | Windows PowerShell 5.1，构建脚本与日志收集器 |
| nsis | 构建机工具 | — | TOOL_MISSING | 探测 `%LOCALAPPDATA%/tauri/NSIS/makensis.exe` 存在 | — | tauri-cli 在 Windows 上只用这个缓存目录里的 NSIS 与 nsis_tauri_utils，不找系统 PATH；准备方式见 build-packaging.md 第 4 节第 1 步 |
| field-experiments | 异机测试材料 | `evidence/delivery/t10-real-experiments.md` | 有 | 装配时记录 SHA-256 | — | 异机实验清单，随测试批次另行转交 |
| loopback-collector | 异机测试材料 | `tools/acceptance/collect-loopback-endpoints.ps1` | 有 | 装配时记录 SHA-256 | — | E40 回环端点采集脚本 |

另外两项由 `cargo tauri build` 直接生成或取得，不经装配工具：桌面宿主主程序（`apps/desktop-host/src-tauri`）与页面（取自装配目录 `frontend\`，本机实算 80 个文件，含 js-yaml 4.3.0 的 ESM 构建）；WebView2 引导程序按 `webviewInstallMode=embedBootstrapper` 内嵌。

## 缺件与谁来补

| 缺件 | 补的方式 | 由谁 |
|---|---|---|
| 控制端、网络服务与两个助手程序 | 构建机编译 | 构建机（E54） |
| Mihomo v1.19.30 windows-amd64 程序（SHA-256 已于 2026-09-22 核对并固定） | 构建机每次从官方发布取得，与固定哈希比对，不一致就失败 | 构建机 |
| 三份 `Cargo.lock` | 构建机 cargo 生成 | 构建机 |
| Rust、tauri-cli、cargo-about 与 tauri-cli 缓存里的 NSIS | 构建机准备，检查逐个探测 | 构建机 |
| `THIRD-PARTY-RUST.txt` | 构建机 `cargo-about` 按锁文件生成 | 构建机 |
| 代码签名证书与签名方式、发布渠道 | 没有就保持 UNVERIFIED | Owner（E58） |
| 对应源码的提供方式（随包或书面提供） | `NOTICE.md` 已写明提供前不公开分发 | Owner |

## 不采用、不进发布清单

| 组件 | 原因 |
|---|---|
| `tauri-plugin-mihomo` 0.5.4 | 历史候选，三份 Cargo.toml 与调用链都不使用 |
| `tauri-plugin-updater` 与远程更新地址、公钥 | 没有发布地址、签名与 Owner 裁决；更新只通过新的安装包 |
| autostart、deep-link、shell、http、window-state 插件 | 不注册 |
| CVR 固定端口 HTTP 单实例（33331/11233）与 scheme/PAC 入口 | 改用官方单实例插件，按产品标识命名，只聚焦既有窗口 |
| CVR 自定义 NSIS 模板 | 按上游进程名批量结束进程并操作上游服务；改用 Tauri 模板加产品钩子 |
| CVR 图标 | 上游商标；产品图标由 `tools/release/make-icons.mjs` 生成 |
| `services/control/` 与 JavaScript OpenAI SDK | 只是行为基线，产品运行路径是 Rust 控制端 |
