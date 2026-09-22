# 可迁移数据说明

日期：2026-09-21（RC6 按当前代码重写；2026-09-14 版按 Node 控制端与 Node 工作区适配器写的落点已不适用）。列出正式桌面产品实际写下来的数据、它们在哪、换机或重装时哪些能带走、哪些带不走也不该带走。所有路径来自当前代码里真实存在的写入点；真实 Windows 用户目录下的落点与权限没有在真机上看过（E55、E56）。

## 1. 数据落在哪

### 1.1 用户数据根 `%LOCALAPPDATA%\local.ai-environmental-steward.desktop\`

| 子目录 | 写入方 | 内容 |
|---|---|---|
| `workspace\state\native-records.json` | 宿主 `workspace.rs`（`RecordsLoad` / `RecordSave`） | 业务记录与备份索引（`records`、`backups` 两个数组） |
| `workspace\backups\<backup_ref>.bin`、`backups\isolation\<ref>\`、`backups\<ref>.directory.json` | 宿主 `BackupSave`、`DirIsolate` | 执行前的原字节、目录隔离的原内容与元数据 |
| `workspace\state\restore-source-*.sqlite`、`snapshot-*.sqlite`、`sim-*.sqlite` | 宿主数据库操作 | 恢复源副本、一致快照与模拟副本（临时） |
| `workspace\audit\archive\<日期>\raw\` | 审计运行时经桥写入 | 内核日志只读快照、脱敏派生件与 `.archive.json` 元数据 |
| `workspace\audit\reports\<日期>\daily-audit.{json,md}`、`reports\ai-notes\` | 同上 | 当日双格式日报与独立的 AI 附注 |
| `workspace\audit\monitor\<日期>\<小时>.json` | 同上 | 每分钟监测记录 |
| `workspace\audit\state\{monitor,scheduler,alerts}.json`、`audit\runs\` | 同上 | 监测开关、调度与提示状态、每次归档与日报的运行记录 |
| `workspace\exports\` | 页面导出日报 | 与已交付产物逐字节一致的副本 |
| `vault\authorizations.json`、`authorization.key` | 宿主 | 本地授权记录与其 HMAC 密钥；受限原生桥到不了这里 |
| `vault\authorized-roots.json` | 宿主 `roots.rs` | 用户授权扫描的根目录登记 |
| `vault\control-session.json` | 宿主 | 本应用登录会话材料（不进工作区、导出或普通日志） |
| `control\control.sqlite3`、`control\logs\control-*.log` | Rust 控制端（宿主托管的子进程） | 用户、会话、任务、资源、分配、额度快照与最小事件；控制端日志 |
| `network\drafts\*.yaml` | 宿主 | 交给产品网络服务的受管配置草稿（服务按摘要核对后读取） |
| `logs\app-*.log`、`logs\host-control-*.log` | 宿主 | 应用日志（按进程分文件）与控制端托管日志 |
| `logs\exports\diag-*\` | 应用内诊断包 | 用户确认后导出的脱敏日志包 |
| `logs\collected\<case_id>\<时间>-<进程号>\` | `support\collect-logs.cmd` | 统一日志收集的导出包（默认位置） |
| `host-state\background-notice.json` | 宿主 | 第一次关窗进托盘的提示标记 |

浏览器侧只有两个偏好键：`steward-theme`、`steward-lang`。

### 1.2 服务状态根 `%ProgramData%\ai-environmental-steward-service\`

由产品网络服务（Windows 服务 `ai_environmental_steward_service`，LocalSystem）拥有，ACL 只给 SYSTEM 与管理员；批准用户只能读 `link\` 与 `logs\`。

| 路径 | 内容 |
|---|---|
| `install.json` | 安装记录：批准用户 SID、网络状态根、宿主程序路径、服务版本 |
| `link\host-link.key` | 宿主与服务之间的命令签名密钥 |
| `runtime-state.json` | 当前受管配置、last-valid、保护记录（卸载撤保护就按它来）、应急会话、操作回执 |
| `core\configs\` | 按摘要保存的已生效受管配置 |
| `run\` | 服务与内核的运行标记 |
| `logs\service*.log`、`core*.log` | 服务日志与内核日志（内核日志含访问明细） |
| `logs\install-*.log`、`installer-*.log` | 安装助手与安装器钩子日志 |
| `rollback\` | 只在修复或升级的维护阶段存在：`install.json` 与 `runtime-state.json` 的维护前副本，成功或回滚后删除 |

### 1.3 安装目录 `%ProgramFiles%\AI Environmental Steward\`

只有程序与资源（见 [build-packaging.md](build-packaging.md)）。安装目录里没有用户数据。修复或升级的维护阶段，安装器把整个安装目录复制到同级的 `%ProgramFiles%\AI Environmental Steward.rollback\`（桌面程序、页面、控制端、服务、内核、许可与支持脚本），再在旁边写下标记文件 `AI Environmental Steward.rollback.ini`，记下原版本号。标记是独立文件，不随目录交换。提交时先删标记再删副本；回滚时把当前目录改名成同级的 `AI Environmental Steward.failed\` 挪开，再把副本改名放回、删掉换下来的目录，等旧版安装助手复原服务状态并启动服务成功之后才删标记。卸载时标记与两个残留目录都删。

## 2. 记录库里有什么

`native-records.json` 的 `records` 以 `id` 为键，每条带 `type`：`scan`、`classification`、`account_answer`、`problem_decision`、`plan`、`confirmation`、`operation`、`recheck`、`restore`、`restore_preview`、`restore_confirmation`、`report`、网络与诊断的记录，界面自己的 `ui_session`（只存指针），以及待报事件（`outbox:<event_ref>`）。

## 3. 换机或重装时怎么带

| 类别 | 能否带走 | 怎么做 | 注意 |
|---|---|---|---|
| 本地处理历史与备份 | 能 | 整体复制 `workspace\state\native-records.json` 与 `workspace\backups\` | 两者必须一起走：索引在记录库里，字节在文件里 |
| 审计归档、日报与监测记录 | 能 | 复制 `workspace\audit\` 整棵树 | 归档带 SHA-256 与当时的分类口径，拆开搬会让完整性核验失败 |
| 导出的日报与诊断包 | 能 | `workspace\exports\`、`logs\exports\` 可以直接给人 | 诊断包已脱敏 |
| 界面偏好 | 不必带 | 换机后重设 | 只有两个键 |
| 服务端账目与额度 | **不能带** | 留在服务端权威 | 重装、改本机时间、恢复旧配置、换模式都不重置服务端用量 |
| 授权保险库 | **不该带** | 在新机器上重新授权 | 授权记录绑定本机密钥与本机路径 |
| 登录会话 | **不该带** | 重新登录 | 会话材料在 `vault\control-session.json`，由控制端签发 |
| 控制端数据库 | 不跨机迁移 | 同机重装、修复与升级时保留 | 用户与会话属于服务端权威 |
| 网络配置、链接密钥与服务状态 | **不该带** | 由新机器安装与后台分配重新生成 | 按用户与本机隔离 |

## 4. 重装、修复、升级与卸载时的数据

- 修复安装与覆盖升级不删除以上任何数据。桌面程序在运行时，安装器先征得同意关掉它；不同意就在停服务之前退出。维护阶段先备份整个安装目录并写下标记，再由安装助手 `prepare-upgrade` 回读保护、备份服务的 `install.json` 与 `runtime-state.json`、停服务（安装器 `STEWARD_MAINTENANCE_BEGIN`）。服务停不下来时助手把它重新启动再拒绝，安装器中止。
- 服务停下之后到提交之前，任何失败都回到原版本：新版本登记或启动失败（后安装钩子）；文件写不进后选了取消，或模板的应用检查被取消（`.onInstFailed`）；安装中断、断电或进程被结束（下次运行安装包时发现标记还在，先回滚再继续）。回滚时安装助手 `stop-for-rollback` 先停服务，安装器把当前目录整个改名挪开、把副本改名放回，写回卸载项里的旧版本号，再由旧版安装助手 `rollback-upgrade` 放回服务状态并启动旧服务。桌面程序、页面、控制端、服务、内核与安装记录一起回到原版本。
- `rollback-upgrade` 退出码为 0 才删标记、才算恢复。目录已经换回、服务状态还没复原或旧服务没起来时（助手失败，或这一刻断电），标记留着；下次运行安装包发现副本已不在，就只重做这一步，恢复成功之前不开新的维护，也不覆盖原来的服务状态备份。
- 目录里还有文件被占用时，第一次改名整步失败、什么都不动：安装器说明情况，服务保持停止、受保护程序保持阻断，副本与标记保留，重新运行安装包会先放回原版本。副本改名放不回时，把当前目录挪回原位，说明副本位置与手工恢复方法。
- 手动升级时，新安装器的重装页默认选「先卸载旧版本」：这就是一次普通卸载，同样要明确选择停止管理并恢复原网络，保护会被撤掉，之后按新装处理，数据按卸载时的勾选保留。选「不卸载」才走上面的维护流程，保护在维护期间保持。
- 安装与修复登记的批准用户是安装器所在桌面会话的登录用户，不是提权时输入的管理员。安装助手 `--user-from-session` 按会话用户查账号 SID 与配置文件目录，网络状态根取该目录下的 `AppData\Local\local.ai-environmental-steward.desktop\network`。配置文件目录在注册表里通常是 `REG_EXPAND_SZ`（例如 `%SystemDrive%\Users\name`），助手接受 `REG_SZ` 与 `REG_EXPAND_SZ` 两种类型并自己展开。
- 卸载时必须明确选择停止管理并恢复原网络，否则取消卸载。确认之后先关掉正在运行的桌面程序，再由卸载助手证明服务已停止。之后助手不看运行状态记录，直接枚举本产品 WFP 子层：先删放行；放行删除没有报错、重新枚举也只剩阻断，才删阻断；删完重新枚举，为零才往下走。运行状态文件丢了也照样能证明。放行删不掉时一条阻断都不删，受保护程序保持断网。服务停不下来，或枚举、删除、复核任何一步出错，都重启服务并非零退出，安装器中止卸载。
- 子层清干净之后、删服务之前，卸载助手把服务状态里的保护请求作废（`requested=false`、`effective=false`，标记 `UNINSTALL_REVOKED`）。没落盘的保护意图也先对账进待定历史，否则下次启动时会被对账成「已请求」。保留数据时同样要作废，所以重装后服务启动不会按旧请求把阻断装回去，要等用户重新确认「启用监测与保护」。批准程序清单、配置、last-valid 与回执都保留。作废写不进就重启服务并中止卸载，服务按原请求补回保护；状态文件解析不了时，任何服务实例都读不出其中的请求，照常继续。
- 只有勾选「删除应用数据」才删除用户数据根与服务状态根，默认保留报告、恢复材料与日志。项目资料不动。

## 5. 迁移后要验证什么

1. 重开应用后能找回原任务：`ui_session` 指针能解析到 `scan`、`plan`、`operation` 记录。
2. 恢复预览能读到备份字节：任取一条带 `backup_ref` 的回执做预览，不应出现 `BACKUP_NOT_FOUND`。
3. 日报历史条数与 `workspace\audit\reports\` 下的 `daily-audit.json` 数量一致，归档 SHA-256 校验不报 `ARCHIVE_INTEGRITY_HASH_MISMATCH`。

## 6. 不要做的事

- 不要只复制 `native-records.json` 而丢下 `backups\`。
- 不要编辑 `workspace\audit\archive\` 与已交付日报；哈希不符会让快照变成覆盖缺口，再次交付会判冲突。
- 不要把别人的 `vault\`、`control\` 或服务状态根拿来用。

## 7. 未验证

以上落点都来自代码，合成工作区里验证过读写与恢复。真实 Windows 用户目录下的实际落点、`%ProgramData%` 目录的 ACL、跨机复制后的权限与占用、修复与升级前后的数据保留都没有在真机上验证（E55、E56）。
