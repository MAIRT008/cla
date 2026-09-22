# 上游来源与产品改动

本目录是 AI Environmental Steward 的产品网络服务 crate，由固定来源复制后改名、收窄。许可沿用上游 GPL-3.0，`LICENSE` 与上游逐字节相同（SHA-256 `8b1ba204bb69a0ade2bfcf65ef294a920f6bb361b317dba43c7ef29d96332b9b`）。

| 项 | 值 |
|---|---|
| 上游项目 | clash-verge-service-ipc |
| 声明版本 | 2.3.3 |
| 固定提交 | `b964ed2992599fadefd589425c1acdabcb875623` |
| 来源记录 | `experiments/p0-desktop/service-ipc-b964ed2992599fadefd589425c1acdabcb875623/SOURCE.json` |
| 源码归档 SHA-256 | `05173AF1E5C80B099E90ED5DE128EC567B7CDABD044028145626D546C02D494B` |
| 本地源码根 | `experiments/p0-desktop/service-ipc-b964ed2992599fadefd589425c1acdabcb875623/src/clash-verge-service-ipc-b964ed2992599fadefd589425c1acdabcb875623/` |
| 产品包名 | `steward-service-ipc`（lib `steward_service_ipc`），版本 `2.3.3-steward.1` |

`experiments/` 下的固定来源没有改动。依赖改用 crates.io 固定版本；上游唯一的 Git 依赖 `clash_verge_logger` 已删除。上游 `Cargo.lock` 与改动后的依赖不再对应，没有复制，也没有伪造新的锁文件；本机没有 cargo/rustc，本 crate **未编译、未运行**。

## 产品命名空间

| 用途 | 上游 | 产品 |
|---|---|---|
| 服务名 | `clash_verge_service` | `ai_environmental_steward_service` |
| 服务程序 | `clash-verge-service.exe` | `ai-environmental-steward-service.exe` |
| 服务 pipe | `\\.\pipe\clash-verge-service` | `\\.\pipe\ai-environmental-steward-service` |
| 测试 pipe | `\\.\pipe\clash-verge-service-test` | `\\.\pipe\ai-environmental-steward-service-test` |
| 内核控制 pipe | `\\.\pipe\verge-mihomo` | `\\.\pipe\ai-environmental-steward-mihomo` |
| 状态目录 | `%ProgramData%\clash-verge-service` | `%ProgramData%\ai-environmental-steward-service` |
| owner lock / pid / core 记录 | `%TEMP%\clash-verge-service\clash-verge-service.*` | `<状态目录>\run\ai-environmental-steward-service.*` |
| 应用标识 | — | `local.ai-environmental-steward.desktop` |

常量集中在 `src/core/paths.rs`，桌面宿主经本 crate 的 `client` 特性引用同一份。

## 逐文件处置

| 上游文件 | 处置 | 产品位置与改动 |
|---|---|---|
| `Cargo.toml` | 改写 | 改名；特性改为 `client`/`service`；删 Git 依赖、flexi_logger、tracing、once_cell、strum、compact_str、nix/libc；加 sha2、getrandom、serde_yaml_ng、windows-sys（WFP；RC6 Round 2 加安全、授权、远程桌面会话与注册表四个特性，供安装助手取会话用户；Round 3 加 Environment，展开 `REG_EXPAND_SZ` 的配置文件目录） |
| `Cargo.lock` | 未复制 | 依赖已变，锁文件须在构建机生成 |
| `LICENSE` | 原样复制 | `LICENSE` |
| `src/lib.rs` | 改写 | 删固定 magic 文本与上游 pipe；导出产品常量、命令、服务状态机 |
| `src/core/mod.rs` | 改写 | 按特性组织产品模块 |
| `src/core/command.rs` | 改写 | `IpcCommand`（/clash/start 接任意 core_path、/writer 接任意日志目录、/clash/logs、/magic）换成 12 个固定 `ServiceCommand` |
| `src/core/structure.rs` | 改写 | 删 `ClashConfig`/`CoreConfig`/`WriterConfig`（调用方给路径）；改为结构化请求/回执 |
| `src/core/auth.rs` | 改写 | 固定 magic 头比对换成宿主链接密钥签的 HMAC-SHA256 envelope（命令、环境、计划/分配版本、载荷摘要、期限） |
| `src/core/paths.rs` | 改写 | 产品命名空间、ProgramData 状态目录、固定内核路径、pipe SDDL |
| `src/core/server.rs` | 改写 | pipe ACL 由 `D:(A;;GA;;;WD)` 收窄为 SY/BA + 批准用户；路由只剩 12 个命令；保留监听器重建与上限；删 unix socket 目录权限逻辑 |
| `src/core/manager.rs` | 改写 | 保留串行启停、守护、退避重启、运行记录；固定程序路径，缺失报 `CORE_BINARY_MISSING`；有限重启 3 次/10 分钟只用 last-valid；内核 pipe 经 `LISTEN_NAMEDPIPE_SDDL` 收窄、secret 经环境变量；日志改产品文件 |
| `src/core/owner.rs` | 改写 | 单实例锁改产品路径；健康检查改发 Handshake |
| `src/core/process.rs` | 改写 | 保留 tasklist/taskkill 做法，删 unix 分支；加受保护程序运行探针 |
| `src/core/reconcile.rs` | 改写 | 保留按记录 PID 结束遗留内核；保护与 last-valid 恢复移到状态机 |
| `src/core/runtime.rs` | 并入 | 运行记录写入并入 `manager.rs`，socket 清理（unix）删除 |
| `src/core/state.rs` | 改写 | 保留生命周期原子状态；IPC server 句柄改在 `server.rs` |
| `src/core/logger.rs` | 改写 | 删 clash_verge_logger/flexi_logger，改按大小轮转的追加日志 |
| `src/core/desired.rs` | 删除 | desired-state（记录任意 ClashConfig 并在启动时照原样拉起）由 `core/network` 的 last-valid 与保护先行恢复取代 |
| `src/core/status.rs` | 删除 | 由 `ObserveRuntime` 的实际运行记录取代 |
| `src/client/mod.rs` | 改写 | 删 start_clash/stop_clash/update_writer 原语与 magic 头；只保留按命令发送结构化请求的同步调用 |
| `src/bin/service.rs` | 改写 | 产品服务名；多线程运行时；非 SCM 启动只在 `--console` 时前台运行；删 unix 分支 |
| `src/bin/install_service.rs` | 改写 | 只保留 Windows；核验同目录产品程序，同名服务指向别的程序时拒绝；写批准记录、链接密钥与目录 ACL；删 macOS/Linux 分支。RC6 加 `repair`、`prepare-upgrade`（先回读保护、备份 `install.json` 与 `runtime-state.json`、再停服务）、`complete-upgrade`（失败就停服务并非零退出，由安装器把整份旧安装目录放回）、`rollback-upgrade`（放回服务状态并启动旧服务）与每次运行一份 `install-*.log`；RC6 Round 2 加 `--user-from-session`：按安装器进程所在桌面会话取登录用户，查账号 SID 与配置文件目录，不用提权账号。RC6 Round 3：配置文件目录接受 `REG_SZ` 与 `REG_EXPAND_SZ` 并自己展开；加 `stop-for-rollback`（安装器回滚前停服务）；`prepare-upgrade` 停不下来时把服务重新启动再拒绝 |
| `src/bin/uninstall_service.rs` | 改写 | 只保留 Windows；只删程序路径核验一致的产品服务；可选撤本产品保护；删 macOS/Linux 分支。RC6 改为先停服务、再撤保护、撤净才删服务，撤不净就重启服务并非零退出；加 `--delete-state`。RC6 Round 2 改为先证明服务已停止，按运行状态里的保护、进行中与待定操作合并出各环境，逐个撤除并回读基线与受管路径都为零才删服务；运行状态读不了也中止。RC6 Round 3 改为不看运行状态，直接枚举本产品 WFP 子层清扫并复核为零（`core/wfp.rs#product_sublayer_sweep`）；不给 `--release-protection` 时子层里还有本产品过滤器就不删服务。RC6 Round 4：子层清干净之后、删服务之前把已保存的保护请求作废（`core/network#revoke_saved_protection`），保留数据时也要，重装后服务启动不按旧请求装回保护；写不进就重启服务并中止 |
| `src/bin/mock_binary.rs`、`crash_binary.rs`、`owner_lock_holder.rs`、`service_integration_driver.rs` | 未复制 | 上游集成测试辅助程序，会起真实进程与 pipe |
| `tests/*.rs`（6 个） | 未复制 | 上游集成测试会启动服务、pipe 与子进程，本单禁止；产品改用注入后端的单元测试 |
| `resources/installer.nsi` | 改写 | RC6 起是 Tauri NSIS 安装器钩子（`installerHooks`），不再是独立安装器，也没有占位替换：宿主路径在安装时取实际值，批准用户 SID 与网络状态根由安装助手按会话取；只调用本产品安装、卸载助手。RC6 Round 2 起修复与升级先整份复制安装目录，失败时整份放回并写回卸载项旧版本号。RC6 Round 3：停服务之前先征得同意关掉桌面程序；`AllowSkipFiles off` 与 `.onInstFailed` 覆盖模板里的失败出口；回滚改为目录改名对调；下次运行发现未提交的标记先回滚；去掉走不到的 `/UPDATE` 卸载分支。RC6 Round 4：标记改为安装目录旁边的独立文件 `<安装目录>.rollback.ini`，旧版助手 `rollback-upgrade` 退出码为 0 才删；目录已换回、服务未恢复时下次运行只重做这一段；每次 `ExecWait` 前把退出码置为 -1 |
| `resources/info.plist.tmpl`、`launchd.plist.tmpl`、`systemd_service_unit.tmpl` | 未复制 | 产品只交付 Windows |
| `scripts/mihomo.sh`、`Makefile`、`.github/**`、`renovate.json`、`SECURITY.md`、`.gitignore` | 未复制 | 上游构建/发布/下载 latest 内核脚本，不作为产品构建输入 |

## 产品新增

| 文件 | 内容 |
|---|---|
| `src/core/network/mod.rs` | 服务状态机：配置 downloaded/validated/applied/verified 分阶段、保护先行、实际回读、last-valid、幂等回执、应急路径、启动恢复。RC6 Round 4（Codex 裁决的最小扩展）：`revoke_protection_for_uninstall` / `revoke_saved_protection`，卸载时先对账没落盘的意图、再把保护请求作废，其他状态不动 |
| `src/core/network/tests.rs` | 注入进程/内核接口/校验器/WFP/文件/时钟的状态机用例 |
| `src/core/config.rs` | serde_yaml_ng 解析受管配置，拒绝控制面与 provider 字段，抽取并比较回读事实 |
| `src/core/controller.rs` | kode-bridge 0.4.0 经内核 pipe 调 Mihomo 控制接口 |
| `src/core/store.rs` | 状态文件、批准记录、链接密钥、按摘要保存的受管配置 |
| `src/core/wfp.rs` | 从桌面宿主移入的 WFP 保护：环境隔离键、回读、只回滚本次新建、只撤本产品键。RC6 Round 3（Owner 批准的范围扩展）：单键读取只把「不存在」当不在，其他错误写 `NATIVE_FILTER_READ_FAILED`；新增不分层枚举本产品子层的卸载清扫 `product_sublayer_sweep`。RC6 Round 4：清扫时放行删除没有报错、重新枚举只剩阻断，才删阻断 |
