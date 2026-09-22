# control-rs：本应用控制端（RC1 + RC2）

产品运行路径里唯一的控制端：首启管理员、登录会话、应用用户与会话管理、服务器模型配置与 AI 路由、资源/模板/订阅、候选分配与发布、个人凭据换取、配额适配（Remnawave）与额度操作、最小网络事件，以及本地运行日志。旧 Node 控制端 `services/control/` 只保留为行为基线与离线对照，不随客户端运行。

**状态：源码已写，未编译，未运行。** 本机没有 cargo/rustc，也没有取得依赖；没有 `Cargo.lock`。依赖版本、许可与选型见 [DEPENDENCIES.md](DEPENDENCIES.md)。

## 启动

```text
ai-steward-control --state-dir <绝对路径> [--config <文件>] [--bind 127.0.0.1:<端口>] [--bootstrap-stdin]
```

| 参数 | 说明 |
|---|---|
| `--state-dir` | 必填，绝对路径。数据库 `control.sqlite3`、日志目录 `logs/`、独立运行时的首启凭据文件 `setup-token` 都在这里 |
| `--config` | 可选 JSON 配置。文件缺失、不是 JSON、含未知字段都按配置错误退出 |
| `--bind` | 默认 `127.0.0.1:0`。只接受回环地址 |
| `--bootstrap-stdin` | 宿主托管模式：stdin 首行读宿主生成的首启凭据；之后 stdin 关闭即优雅退出 |

配置文件字段（全部可选）：`bind`、`session_ttl_seconds`（默认 43200）、`password_min_chars`（12）、`login_free_failures`（5）、`login_backoff_base_ms`（1000）、`login_backoff_max_ms`（300000）、`login_failure_window_ms`（900000）、`allowed_origins`。这些是技术默认值，不是 Owner 批准的业务参数。模型、配额权威、资源等业务配置不走配置文件，由管理员在界面里保存到库。

### 就绪握手与退出码

启动成功后 stdout 打一行 `{"event":"ready","service":"ai-steward-control","version":"0.2.0","protocol":"steward-control-1",...}`；协议版本仍是 `steward-control-1`，宿主握手不变。失败先写日志，再打 `{"event":"failed",...}` 退出：

| 退出码 | 阶段 | 典型错误码 |
|---|---|---|
| 2 | 参数、配置、托管首启材料 | `CONTROL_CONFIG_INVALID`、`CONTROL_BOOTSTRAP_INVALID` |
| 3 | 数据库 | `CONTROL_STORE_CORRUPT`、`CONTROL_STORE_UNRECOGNIZED`、`CONTROL_STORE_VERSION_UNSUPPORTED`、`CONTROL_STORE_MIGRATION_FAILED`、`CONTROL_STORE_OPEN_FAILED` |
| 4 | 监听 | `CONTROL_BIND_FAILED`、`CONTROL_BIND_NOT_LOOPBACK` |
| 5 | 其他 | `CONTROL_RANDOM_UNAVAILABLE`、`CONTROL_RUNTIME_FAILED`、`CONTROL_SERVE_FAILED` |

## 数据库版本

`control_meta.schema_version`：RC1 为 1，RC2 为 2，RC4 为 3。

- 新库：一个事务里建 v1 结构、叠加 v2、v3 迁移、写版本 3。与「旧库逐级升级」逐表结构相同（`tests/migration.rs` 核对）。
- v2 库：同一种 IMMEDIATE 事务执行 `MIGRATION_V3`（只建 `control_probe_services`），记 `migrated_v3_at`；v1 库依次执行 v2、v3，两个标记都记。
- v1 库：在原路径用 IMMEDIATE 事务执行 `MIGRATION_V2`，只新建业务表、改版本号、记 `migrated_v2_at`；不动 `control_users`、`control_sessions`、`control_setup`，管理员与有效会话保留。事务内再读一次版本，另一个进程已升级则什么都不做。任一步失败整体回滚，库保持 v1，服务以退出码 3、`CONTROL_STORE_MIGRATION_FAILED` 停止。
- 版本高于 3、归属标记不符、不是 SQLite、损坏：拒绝启动，文件不改。
- 打开后启用 `PRAGMA foreign_keys = ON`。

v2 表：`control_secrets`（密文）、`control_model_policies`、`control_ai_tasks`、`control_ai_turns`、`control_ai_usage_events`、`control_resources`、`control_templates`、`control_template_versions`、`control_subscription_sources`、`control_assignment_candidates`、`control_assignments`、`control_publish_receipts`、`control_apply_receipts`、`control_credentials`、`control_quota_adapter`、`control_provider_bindings`、`control_quota_operations`、`control_quota_snapshots`、`control_pool_snapshots`、`control_network_events`、`control_event_receipts`。用户、会话、唯一键（provider_user_id、username、(credential_ref, user_ref)、(user_ref, operation_id) 等）、状态枚举与幂等键由约束守住；分配快照、额度快照与回执按 Node 基线用 JSON payload 保存。

## 秘密保护

模型 Key、Remnawave 服务地址与管理令牌、订阅链接、个人接入凭据只以密文存入 `control_secrets`，业务表只存 `secret_ref`。

- 产品路径（Windows）：`CryptProtectData` / `CryptUnprotectData`，当前用户范围，`CRYPTPROTECT_UI_FORBIDDEN`，附加熵 `ai-steward-control/secret/<用途>`。密文绑定用途；换用途、换保护方式或篡改都读不出，回 `CONTROL_SECRET_UNREADABLE`，不回显。
- 其他平台：`UnavailableProtector`，写秘密回 `CONTROL_SECRET_PROTECTION_UNAVAILABLE`（503），不退回明文或固定密钥。
- 轮换：同一引用原地更新密文、版本加一。清除：先置空业务表引用，再删密文。
- 任何读取接口只回 `secret_present` / 版本 / 更新时间 / 安全显示（地址只留协议+主机）。
- 测试注入确定性保护器 `tests/common/mod.rs::TestProtector`，它不是产品保护方式。

## 出站调用

模型、Remnawave、订阅拉取都只经 `HttpTransport`。产品实现 `UreqTransport`：每次调用单独的超时，不跟随重定向（鉴权头不外带），响应上限 8 MB。页面断开时 main.rs 置位 `CancelToken`：发送前与收到响应后各检查一次，已经发出的单次调用由超时兜底，不强行中断套接字。不做自动重试。

## 接口

所有错误回 `{code, reason, request_ref}`（部分附 `field` / `path` / `retryable`），响应头带 `X-Request-Ref`。**HTTP 401 只表示本应用会话无效**：上游模型或配额服务的鉴权失败回 502 与各自的错误码，页面据此只在本应用会话失效时退回登录。

未认证可达：`GET /health`、`GET /api/setup/status`、`POST /api/setup/admin`、`POST /api/auth/login`、`GET /api/auth/me`、`POST /api/auth/logout`（与 RC1 相同）。

其余 `/api/*` 先认证（401 `AUTH_SESSION_INVALID`）；`/api/admin/*` 由服务端角色判定（403 `CONTROL_FORBIDDEN`）；不在路由表里的路径回 404 `CONTROL_NOT_FOUND`，已知路径的错误方法回 405。路由表是 `router.rs::ROUTES`。

迁移路由的请求字段沿用 Node 基线的写法（`userRef`、`limitBytes`、`expireAt`、`allowedModes` 等），并接受 `user_ref` 别名；新增路由用 snake_case。请求体里不认识的字段一律 400 并点名字段。

### 用户与会话（管理员）

| 路由 | 请求 | 行为 |
|---|---|---|
| `GET /api/admin/users` | — | `{users: [{user_ref, username, role, status, created_at, updated_at, active_sessions}]}`，不含密码哈希 |
| `POST /api/admin/users` | `{username, password}` | 201 建普通用户；规范化与密码规则同首启；重名 409 `CONTROL_USER_CONFLICT`；带 `role` 等字段 400 |
| `POST /api/admin/users/status` | `{user_ref, status: ACTIVE\|DISABLED}` | 停用时同一事务撤销该用户全部会话，回 `revoked_sessions`；目标是管理员 403 `CONTROL_ADMIN_TARGET_DENIED` |
| `POST /api/admin/users/password-reset` | `{user_ref, password}` | 换 Argon2id 哈希并撤销全部会话 |
| `GET /api/admin/sessions?user_ref=` | — | `{sessions: [{session_ref, status: ACTIVE\|EXPIRED\|REVOKED, created_at, expires_at, revoked_at}]}`，不含令牌或摘要 |
| `POST /api/admin/sessions/revoke` | `{user_ref}` 或 `{session_ref}` | 幂等，回 `revoked` 条数；两个都给或都不给 400 |

### 模型与 AI

| 路由 | 行为 |
|---|---|
| `GET /api/admin/model-config` | 三类任务各自 `{configured, enabled, base_url, model, policy_version, 预算, timeout_ms, secret_present, status, reason, verification, last_error_code, last_call_at, prompt_version, tool_catalog_version}`；不含 Key |
| `PUT /api/admin/model-config` | `{task_type, enabled?, base_url?, model?, policy_version?, max_model_calls?, max_total_tokens?, max_output_tokens?, timeout_ms?, api_key?, clear_api_key?}`；Key 只写；首次保存必须给 `policy_version`；端点必须 https（http 只允许回环）。改端点、模型或 Key 把 `verification` 重置为 `NOT_TESTED`；只有真实调用成功才变 `CALL_SUCCEEDED` |
| `GET /api/ai/capabilities` | 普通用户可读：每个任务 `AVAILABLE {policy_version, catalog_version, verification}` 或 `UNAVAILABLE {reason: MODEL_NOT_CONFIGURED\|MODEL_DISABLED\|MODEL_SECRET_MISSING}`；不含端点、模型或 Key |
| `POST /api/ai/turn` | 只接受 `task_ref, task_type, turn_ref, prompt_version, prompt_body, tool_catalog_version, messages`；版本必须与 `protocol/ai-protocol.json` 一致（400 `CONTROL_PROTOCOL_MISMATCH`）；task 归属首个提交者（403 `CONTROL_TASK_DENIED`）；同 turn 重放原结果，内容不同 409；预算耗尽 429；未配置 503 `AI_UNAVAILABLE`；提供方 401/403 → 502 `AI_AUTH_FAILED`，429 → 429，5xx → 502 `AI_PROVIDER_UNAVAILABLE`，取消 → `AI_ABORTED`，其余 → 502 `AI_TRANSPORT_UNKNOWN` |

`protocol/ai-protocol.json` 由客户端 `src/core/ai/tools.mjs` 与 `services/control/modelPolicy.mjs` 生成，`tests/control-runtime/contract.test.mjs` 核对两边逐项一致。

### 资源、模板、订阅、分配、凭据

| 路由 | 行为 |
|---|---|
| `GET/PUT /api/admin/resources` | `{resource_id, role: front\|A\|B, host, port?, sharing?, status?: ACTIVE\|DISABLED, expires_at?, credential_ref?}`；版本加一；GET 同时回订阅源 |
| `GET/PUT /api/admin/templates` | `{template_id, template, version?, status?, published?}`；结构校验出错回 `TEMPLATE_INVALID` 与 `path`；像秘密的键 `TEMPLATE_SECRET_REJECTED`；每次保存留一份历史 |
| `GET/PUT /api/admin/subscriptions` | `{source_id, format?, status?: PENDING\|DISABLED, url?, clear_url?}`；链接只写，列表只回 `url_present`、`url_display` |
| `POST /api/admin/subscriptions/refresh` | `{source_id, body?, content_type?}`；没给 body 就按保存的链接拉取。只解析 Clash/Mihomo YAML 的 `proxies`；结果 `{ok, source, code?, http_status?, proxies?}`，失败如实落 `FAILED`/`UNSUPPORTED` 并保留上次成功的解析数量 |
| `POST /api/admin/assignments` | `{userRef, allowedModes, resources: [资源编号], roles: {A, B?, front?}, validUntil, templateId?, environmentRef?, accountClass?}`；资源按编号取服务端记录，角色必须对得上；只保存候选（DRAFT），不影响已发布版本；没有模板 409 `TEMPLATE_UNAVAILABLE`，不回退内置样例 |
| `GET /api/admin/assignments?user_ref=&environment_ref=` | `{candidate, published, assignment, validation, ready, last_receipt}` |
| `POST /api/admin/assignments/publish` | `{userRef, confirmation?: {confirmed}, environmentRef?, receiptId?}`；未就绪 `{ok:false, code}`；A 引用、A 主机或受保护进程路径变化需确认，否则 `SENSITIVE_CHANGE_CONFIRMATION_REQUIRED`；发布写回执、清候选 |
| `POST /api/admin/assignments/revoke` | `{userRef}`；已发布记录改 REVOKED，普通用户仍能读到撤销状态 |
| `GET/PUT /api/admin/credentials`、`POST /api/admin/credentials/revoke` | 按 `(user_ref, credential_ref)` 保存个人接入 `{username, password}`；只写；撤销删除密文 |
| `GET /api/network/assignment` | 当前用户的已发布（含撤销）分配与额度快照；候选不下发 |
| `GET /api/network/credentials` | `{status, code, credentials: {credential_ref: {username, password}}, withheld: [{credential_ref, reason}]}`，`Cache-Control: no-store`。只在当前用户已发布分配有效、额度未停用/到期、资源仍可用、凭据属于本人且 ACTIVE 时下发 |
| `POST /api/network/receipts` | 按 (当前用户, operation_id) 幂等；丢弃 yaml、core_secret、password、token 等字段 |

### 配额与事件

| 路由 | 行为 |
|---|---|
| `GET/PUT /api/admin/quota-adapter` | `{kind: remnawave, enabled?, base_url?, token?, timeout_ms?, clear_secrets?}`；地址与令牌只写；读取回 `configured`、`base_url_display`、`token_present`、`verification` 与契约版本 |
| `POST /api/admin/quota/allocate` | `{userRef, operation_id, limitBytes \| limit_value + limit_unit(bytes\|GB\|GiB), period, expireAt, squadUuid?}`；拒绝 0/无限；已有绑定只回读 |
| `POST /api/admin/quota/limit\|suspend\|resume` | `{userRef, operation_id, ...}`；幂等、内容不符 409、调用结果未知时先回读；停用的节点断连效果一律 UNKNOWN；恢复要求已发布分配有效 |
| `GET /api/admin/quota/usage?user_ref=`、`GET /api/network/quota` | 权威可用时写后回读；未配置、超时或不可用回最后快照并标 `stale`/`OFFLINE` 与原因码 |
| `GET /api/admin/quota/pool?pool_id=` | 节点列表与 `exhausted`；共享订阅余额 UNKNOWN；不可用时回最后池快照 |
| `GET/POST /api/network/events`、`GET /api/admin/events?user_ref=` | 最小事件白名单字段；秘密标记整条 400；`event_ref` 去重合并；强制归属 |
| `GET /api/admin/service-state` | 控制端、配额适配、可用模型任务数、秘密保护方式、结构版本、日志状态 |

### 分环境探测服务（RC4）

| 路由 | 行为 |
|---|---|
| `GET/PUT /api/admin/probe-services` | 按 `environment_ref`（小写字母、数字、连字符）登记 `echo_url`、`doh_url`、`probe_base_url`、`intel_url`（至少一个；https，http 只允许回环；不收带账号密码的地址）、`stun_urls`（最多 4 个 `stun:`/`stuns:`）、`client_kind`（webview、wsl-cli、cli）、`webrtc`；版本号递增，带 `expected_version` 时不符回 409 |
| `POST /api/admin/probe-services/remove` | `{environment_ref}`；不存在回 404 |
| `GET /api/network/probe-services` | 已登录用户拿到 `{environments: {<ref>: {地址…}}}`，不含版本与修改人 |

没有登记的环境客户端不建探测端口，诊断按 `ENVIRONMENT_PROBE_UNAVAILABLE` 缺测。探测协议沿用现有回显、DoH 与 Probe 解析。

适配范围：只接 Remnawave 用户额度路径（backend 3.4.3 契约）。不承诺任意机场订阅都能按用户硬限额。

## 日志

`<state-dir>/logs/control-<UTC 时间>-<instance_ref>.log`，每次启动新建文件，每行一条 JSON。认证后的每个业务请求记 `request.completed`：方法、不含查询串的路径、演员引用、HTTP 状态、错误码。管理写操作另记一行（演员、目标引用、版本、是否替换了秘密）。内部故障记 `request.internal_error` 的脱敏细节，对外只回「详见控制端日志」。

不记：Authorization、密码、会话令牌、模型 Key、管理令牌、订阅链接、代理密码、提示词、消息与模型回复、完整请求体。字段名含 password/token/secret/authorization/cookie/api_key/credential 的整体替换，自由文本里的 `Bearer …` 与 32 位以上连续十六进制/Base64 串遮盖。

## 测试（已写未运行）

```powershell
cargo check --manifest-path services/control-rs/Cargo.toml
cargo test  --manifest-path services/control-rs/Cargo.toml
```

| 文件 | 覆盖 |
|---|---|
| `tests/lifecycle.rs` | RC1：首启、登录、过期、注销、重启、坏库与外来库、退避、来源、日志；RC2 调整：业务路由未配置时如实回不可用 |
| `tests/process.rs` | 可执行程序：启动失败现场、托管握手、优雅退出（只绑回环） |
| `tests/migration.rs` | v1 升级保留管理员与有效会话、重复打开、迁移回滚、未来版本与外来归属拒绝、新库与升级库结构一致 |
| `tests/admin_users.rs` | 建用户与唯一性、普通用户访问每条管理路由 403、停用撤销会话、重置密码、会话查看与撤销、未知路径 404 与每条登记路由不落 404/405/501 |
| `tests/network_admin.rs` | 资源版本与重启读回、模板出错位置与历史冻结、订阅链接只写与刷新结果、候选/发布/敏感确认/撤销、个人凭据隔离与失效、应用回执 |
| `tests/quota.rs` | 适配器只写配置与请求形状、身份一对一与操作幂等、写后回读、停用恢复、丢失响应不二次调用、陈旧快照、池耗尽 |
| `tests/ai.rs` | Key 只写与验证状态、客户端夹带模型字段拒绝、请求形状与工具调用解析、重放与归属、预算、提供方错误映射与取消、日志不含提示词和 Key |
| `tests/secrets_events.rs` | 密文篡改/保护方式不符/跨用途读不出且不回显、日志不含管理员录入的任何秘密、最小事件去重合并归属与秘密拒收 |
| `src/*.rs` 单元测试 | 时间解析、规范化 JSON、字段校验、查询串、脱敏规则、YAML 解析、模板校验、Remnawave 用户名与响应投影 |

本机做过的只有 `tools/check-rust-sources.mjs` 的静态检查。它对 `use ai_steward_control::` 报「未声明」是误报（本包 `[lib]` 名）。
