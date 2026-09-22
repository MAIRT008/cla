# desktop-host（桌面宿主与产品网络服务）

- `src-tauri/`：Tauri 2 桌面宿主。受限原生桥 45 个操作（与 `bridge-contract.mjs` 一一对应），托管本地 Rust 控制端，经签名 envelope 把网络命令转给产品网络服务；GUI 进程不直连 Mihomo、不调 WFP。
- `vendor/service-ipc/`：产品网络服务、安装助手与卸载助手（改自 service-ipc 2.3.3 @ `b964ed2`，来源与改动见 `UPSTREAM.md`）；`resources/installer.nsi` 是 Tauri NSIS 安装器钩子。
- 产品标识：`local.ai-environmental-steward.desktop`（`tauri.conf.json` 与服务的 `PRODUCT_APP_ID` 一致）；服务名、pipe 与状态目录都在产品命名空间，不连接也不停止任何 Clash Verge Rev 服务或 pipe。

桌面生命周期（`src-tauri/src/lifecycle.rs`）：单实例插件第一个注册，第二次启动只把既有窗口带到前面；关窗隐藏到托盘，第一次提示一次；托盘只有显示主窗口、打开日志目录、退出界面三项；退出界面只结束 GUI 和托管控制端，产品网络服务与保护不受影响，停止管理仍走独立确认。窗口隐藏时，页面经 `NotifyCritical` 请求危急系统通知，只给固定事件与提示编号，文案由宿主定。

构建：先按 `evidence/delivery/build-packaging.md` 第 4 节编控制端与网络服务、跑 `node tools/release/release.mjs assemble`，再编宿主（`tauri-build` 会核对装配目录里的页面与资源存在）。

当前开发机没有 Rust 工具链：三个 crate 都没编译，原生行为一律记 UNVERIFIED。
