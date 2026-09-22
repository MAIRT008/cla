# 构建、打包与依赖源配置

日期：2026-09-21（RC6 按当前代码重写；2026-09-14 版被 RC1—RC5 推翻的口径已改掉）。本页记录发布候选的构建输入、构建机步骤和本机做不到的部分。**当前开发机没有 Rust 工具链，没有构建、签名或安装过任何安装包；第 4 节的构建流程还没在任何机器上跑过，由 E54 首次执行。**

逐项的发布输入、来源、校验、许可与入包分类见 [release-inputs.md](release-inputs.md)；调用链见 [release-call-chain.md](release-call-chain.md)；机器可读的就绪清单是 [release-readiness.json](release-readiness.json)。

## 1. 本机能跑的检查

| 步骤 | 命令 | 结果 |
|---|---|---|
| 页面脚本包 | `node apps/desktop-ui/build-offline-bundle.mjs`、`node --check apps/desktop-ui/app.bundle.js` | 生成并通过语法检查 |
| 发布输入检查 | `node tools/release/release.mjs check` | 本机按预期得 `NOT_READY`（退出码 2），逐项列出缺的二进制、锁文件、第三方许可汇总、Mihomo 固定哈希与 Rust 工具 |
| 装配逻辑 | `tests/delivery/release-candidate.test.mjs` 用合成目录跑 `release.mjs assemble` 同一套逻辑的成功与各种失败 | 见 RC6 交接 |
| 页面闭包 | `release.mjs check` 的 `frontend` 部分 | 从 `apps/desktop-ui/index.html` 出发 80 个文件，0 处解析问题 |
| 模拟验收 | `tests/ui`、`tests/delivery`、`tests/control-runtime` 等运行器 | 数量见最近一次交接 |
| 实现映射 | `node tools/build-traceability.mjs` | `traceability.{json,md}`，352 行 |

构建工具（Node、PowerShell）只在构建机与开发机上用；普通用户运行时不需要 Node、Rust 或 Python。

## 2. 发布组成

| 部分 | 安装后位置 | 来源 |
|---|---|---|
| 桌面宿主（Tauri 2.11.5） | `<安装目录>\<主程序>.exe` | `apps/desktop-host/src-tauri`，由 `cargo tauri build` 生成 |
| 页面 | 内嵌在宿主里 | 装配出的页面闭包 `build/release-staging/frontend/`（含 `src/**` 里被引用的模块与 js-yaml 4.3.0） |
| Rust 控制端 | `control\ai-steward-control.exe` | `services/control-rs`，宿主启动它、退出时停它 |
| 产品网络服务及安装、卸载助手 | `service\ai-environmental-steward-service*.exe` | `apps/desktop-host/vendor/service-ipc`（改自 service-ipc 2.3.3 @ `b964ed2`） |
| Mihomo v1.19.30 | `service\core\mihomo-windows-amd64-v1.19.30.exe` | MetaCubeX/mihomo 官方发布包，对应源码提交 `ac017cd`；**本机没有，哈希未固定** |
| 统一日志收集 | `support\collect-logs.cmd`、`collect-logs.ps1` | `tools/release` |
| 许可与来源 | `licenses\` | GPL-3.0 文本、service-ipc 与 js-yaml 许可、`NOTICE.md`、构建机生成的 `THIRD-PARTY-RUST.txt` |
| 本地版本清单 | `release-manifest.json` | 装配时生成：每个文件的来源、SHA-256 与锁文件哈希 |

不采用、也不进发布清单：`tauri-plugin-mihomo`（历史候选，没有任何 manifest 或调用链使用）、`tauri-plugin-updater` 与远程更新地址、CVR 固定端口 HTTP 单实例与 scheme/PAC 入口、CVR 自定义 NSIS 模板与图标、Node 控制端 `services/control/` 与 JavaScript OpenAI SDK（二者只是行为基线）。

## 3. 构建输入（按当前代码）

- **宿主 `Cargo.toml`**：`serde`、`serde_json`、`steward-service-ipc`（本地 path，`client` 特性）、`rusqlite 0.37`（`bundled`）、`getrandom =0.4.3`；`tauri` 特性下另有 `tauri 2.11.5`（开 `tray-icon`）、`tauri-plugin-dialog 2`、`tauri-plugin-single-instance =2.4.5`、`tauri-plugin-notification =2.3.3`，构建依赖 `tauri-build =2.6.3`（`build.rs` 只在 `tauri` 特性下调用）。
- **`tauri.conf.json`**：标识 `local.ai-environmental-steward.desktop`（与产品命名空间一致，单实例互斥名、NSIS 注册表键、删除应用数据的目录都跟它走）；`frontendDist` 指向装配目录，主窗口加载 `apps/desktop-ui/index.html`；`bundle.active=true`，目标 NSIS，`installMode=perMachine`，产品自有图标（`tools/release/make-icons.mjs` 生成）；资源只从 `build/release-staging/install/` 映射；`installerHooks` 指向 `vendor/service-ipc/resources/installer.nsi`；`createUpdaterArtifacts=false`，不注册 updater。
- **原生桥**：`registered_ops()` 共 45 个操作，与 `apps/desktop-host/bridge-contract.mjs` 一一对应（RC6 新增 `NotifyCritical`，只收固定事件与提示编号）；能力组 12 个。
- **Rust 控制端**：44 条业务路由（`services/control-rs/src/router.rs` 的 `ROUTES`），宿主从资源目录的 `control\` 启动，经 stdin 交付一次性首启凭据。
- **产品网络服务**：三个 bin；服务名 `ai_environmental_steward_service`，pipe `\\.\pipe\ai-environmental-steward-service`，状态目录 `%ProgramData%\ai-environmental-steward-service`。

## 4. 构建机步骤（顺序固定）

1. 准备 Windows 构建机：Rust ≥ 1.85（复用决策记 1.95）与 MSVC、`cargo-tauri`（tauri-cli 2.x）、`cargo-about`、Node ≥ 22、Windows PowerShell 5.1，以及 NSIS。tauri-cli 在 Windows 上只用自己缓存目录 `%LOCALAPPDATA%\tauri\NSIS\` 里的 NSIS 与 `nsis_tauri_utils`，不找系统 PATH；缺了才在 `tauri build` 的打包阶段下载。发布检查要求它先就位（探测 `makensis.exe`），所以准备阶段先让 tauri-cli 取得它：在构建机上对任意一个 Tauri 2 示例工程跑一次 `cargo tauri build --bundles nsis`，或按该 tauri-cli 版本打包器源码里的固定下载地址与校验值放好。七个构建工具都是必需项，任何一个没探测到，检查都是 `NOT_READY`。
2. 先跑 `powershell -NoProfile -ExecutionPolicy Bypass -File tools\release\build-release.ps1 -PlanOnly`，看 `build\logs\<时间>-<进程号>\check.json` 里缺什么。
3. 从 Mihomo v1.19.30 官方发布页取得 windows-amd64 发布包，核对后把程序放到 `build\inputs\mihomo-windows-amd64-v1.19.30.exe`，再把它的 SHA-256 写进 `tools/release/release-inputs.json` 的 `mihomo` 项。没写之前检查一直报 `PIN_REQUIRED`。
4. 三个 crate 各生成 `Cargo.lock` 后，用 `cargo-about` 生成 Rust 依赖许可汇总，放到 `build\inputs\THIRD-PARTY-RUST.txt`。
5. 跑 `build-release.ps1`：编控制端 → 编网络服务 → `node tools/release/release.mjs check` → `node tools/release/release.mjs assemble` → `cargo tauri build --features tauri`。任一步失败就停，不生成安装包。
6. `tauri-build` 会核对 `frontendDist` 与资源存在，所以宿主的 `cargo check --features tauri`（E01）也要在 `assemble` 之后跑。
7. 日志：每步的命令、退出码与输出都在 `build\logs\<时间>-<进程号>\`，失败也保留，不覆盖上一轮。连日志目录都建不了时，脚本提示先 `Start-Transcript` 保存控制台输出。
8. 产出的 NSIS 安装包要记录文件清单与哈希，与 `release-manifest.json` 对照（E54）。代码签名与更新渠道没有配置（E58）。

装配规则：`assemble` 只按清单复制到临时目录，逐个复核哈希，`release-manifest.json` 最后写，全部成功才改名成 `build\release-staging\`。缺件、哈希不符、未固定哈希、目标重名、越界路径、许可不全、中途失败都非零退出，不留正式目录；输出目录已存在就拒绝，从不覆盖。

## 5. 本机做不到的部分

| 缺口 | 现状 | 需要什么 |
|---|---|---|
| Rust 工具链 | 没有 `cargo`、`rustc` | 构建机 |
| 三个 crate 的编译与单测 | 宿主、网络服务、控制端都没编译过，`#[cfg(test)]` 用例都没运行 | 构建机，E01 起 |
| crate 下载与锁文件 | 三份 `Cargo.lock` 都不存在，不能在本机生成 | 构建机 |
| Mihomo 二进制 | 仓库里只有源码，没有二进制与发布包哈希 | 构建机取得并固定哈希 |
| 第三方许可汇总 | 依赖锁文件，没法在本机生成 | 构建机 `cargo-about` |
| NSIS 安装包 | 从未生成，钩子从未执行 | 构建机 + 测试机（E54—E56） |
| 代码签名 | 没有证书、没有签名配置 | Owner 提供（E58） |
| 文档工具 | `tools/verify_documents.py` 需要 Python | 有 Python 的环境 |

## 6. 入包与不入包

入包只看 `tools/release/release-inputs.json`：`runtime` 与 `source_license` 两类按目标路径进 `install\`，页面闭包进 `frontend\`，`build_input`（三份锁文件）只把哈希记进 `release-manifest.json`，`build_tool` 与 `test_material` 不入包（异机材料随测试批次另交）。

`services/control/`、`fixtures/`、`tests/`、`experiments/`、`dist/`、`evidence/`、`node_modules/` 不会进发布目录。清单里没列的文件，装配工具不会复制。

## 7. 产物目录

| 目录 | 内容 | 说明 |
|---|---|---|
| `build\inputs\` | 构建机放入的 Mihomo 程序与第三方许可汇总 | 构建机专用，不进仓库 |
| `build\release-staging\` | 装配结果：`install\`、`frontend\`、`release-manifest.json` | `tauri.conf.json` 从这里取页面与资源 |
| `build\logs\` | 每次构建的日志目录 | 统一日志收集按 `build` 类别带走 |
| `fixtures/_transient/` | 测试的一次性产物 | 可整目录删除 |
| `dist/` | 历史文档 ZIP | 不入包 |
