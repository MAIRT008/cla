# control-rs 依赖记录

核对日期 2026-09-16。版本与许可取自 crates.io API（`https://crates.io/api/v1/crates/<name>`），接口签名取自 docs.rs 对应版本页面。只读了公开元数据和文档，没有下载 crate 源码。

**取得状态：全部未取得。** 本机没有 cargo/rustc，也不为装工具改动本机。`Cargo.toml` 里用 `=` 钉死了直接依赖版本；**没有 `Cargo.lock`，不伪造**。异机第一次 `cargo check` 时由 cargo 解析传递依赖并生成锁文件，那份锁文件连同日志一起归档。

## 直接依赖

| crate | 固定版本 | 发布时间（crates.io） | 许可 | 来源 | 本服务用到的接口（docs.rs 核对） |
|---|---|---|---|---|---|
| axum | 0.8.9 | 2026-04-14 | MIT | tokio-rs/axum | `Router::new().fallback(h).with_state(s)`；`axum::serve(listener, router).with_graceful_shutdown(fut)`；需要 `tokio` + `http1` 特性，其余默认特性关闭 |
| tokio | 1.53.1 | 2026-07-20 | MIT | tokio-rs/tokio | 多线程运行时、`net::TcpListener`、`task::spawn_blocking`、`sync::oneshot` |
| rusqlite | 0.40.2 | 2026-08-08 | MIT | rusqlite/rusqlite | `Connection::open`、`busy_timeout`、`transaction_with_behavior(TransactionBehavior::Immediate)`、`execute_batch`、`prepare`/`query_map`/`query_row`、`params!`/`params_from_iter`、`OptionalExtension::optional`、`Vec<u8>` 读写 BLOB、`Error::sqlite_error_code()`；`bundled` 特性随 libsqlite3-sys 编译 SQLite |
| argon2 | 0.6.0 | 2026-08-27 | MIT OR Apache-2.0 | RustCrypto/password-hashes | `PasswordHasher::hash_password_with_salt`、`phc::PasswordHash::new`、`PasswordVerifier::verify_password` |
| getrandom | 0.4.3 | 2026-06-17 | MIT OR Apache-2.0 | rust-random/getrandom | `getrandom::fill(&mut [u8])`；文档写明需要 Rust 1.85 |
| sha2 | 0.11.0 | 2026-03-25 | MIT OR Apache-2.0 | RustCrypto/hashes | `Sha256::digest(data)` |
| serde_json | 1.0.151 | 2026-07-20 | MIT OR Apache-2.0 | serde-rs/json | `Value`、`Map`、`json!`、`from_slice`/`from_str` |
| **ureq**（RC2） | 3.4.2 | 2026-09-13 | MIT OR Apache-2.0 | algesten/ureq | `Agent::config_builder()` → `.timeout_global(Some(Duration))`、`.http_status_as_error(false)`、`.max_redirects(0)`、`.build()`；`Agent::new_with_config`；`agent.get/post/patch/put(uri)`、`.header(k, v)`、`.call()` / `.send(&[u8])` / `.send_empty()`；`response.body_mut().with_config().limit(n).read_to_vec()`；`ureq::Error::{Timeout, HostNotFound, ConnectionFailed, Io, ..}`（枚举 non_exhaustive）。默认特性 `rustls`、`gzip` |
| **regex**（RC2） | 1.13.1 | 2026-07-15 | MIT OR Apache-2.0 | rust-lang/regex | `Regex::new`、`is_match`、`replace_all`；线性时间匹配 |
| **yaml-rust2**（RC2） | 0.13.0 | 2026-09-11 | MIT OR Apache-2.0 | Ethiraric/yaml-rust2 | `YamlLoader::load_from_str(&str) -> Result<Vec<Yaml>, ScanError>`；`Yaml` 的 `Index<&str>`、`as_vec`、`as_str`、`as_i64` |
| **windows-sys**（RC2，仅 `cfg(windows)`） | 0.61.2 | 2025-10-06 | MIT OR Apache-2.0 | microsoft/windows-rs | 特性 `Win32_Foundation`、`Win32_Security`、`Win32_Security_Cryptography`；`CryptProtectData`/`CryptUnprotectData(*const CRYPT_INTEGER_BLOB, …, dwflags: u32, *mut CRYPT_INTEGER_BLOB) -> BOOL`；`CRYPTPROTECT_UI_FORBIDDEN: u32 = 1`；`CRYPT_INTEGER_BLOB { cbData: u32, pbData: *mut u8 }`；`Win32::Foundation::LocalFree(HLOCAL) -> HLOCAL`。文档标注 MSRV 1.71 |

传递依赖（hyper、http、tower、password-hash、libsqlite3-sys、rustls、ring 或 aws-lc-rs、webpki-roots、flate2、hashlink 等）没有逐一核对许可。SQLite 本体为公有领域。异机取得依赖后，用 `cargo tree` 与许可清单工具生成完整清单再补进本文件。

**已知的版本风险**：ureq 3.4.2 与 yaml-rust2 0.13.0 发布距核对日只有 3—5 天。若异机 `cargo check` 发现这两个版本被撤回或接口与上表不符，退到同一主版本上一版（ureq 3.4.1、yaml-rust2 0.12.0）并在交接里记录，不改业务代码的调用方式以外的内容。

`rust-version = "1.85"` 只依据 getrandom 的文档；axum、tokio、argon2、ureq、yaml-rust2 的最低 Rust 版本没有核对。计划中的测试机是 Rust 1.95。

## 选型比较

| 需求 | 选用 | 没选 | 理由 |
|---|---|---|---|
| HTTP 服务 | axum 0.8 + tokio | tiny_http 0.12；直接用 hyper 1 | tiny_http 最近一版是 2022-10-06；hyper 1 需要自己拼连接循环。axum 只用 fallback 一个入口，路由逻辑在 `router.rs`，与框架无关 |
| SQLite | rusqlite（bundled） | sqlx | 同步接口配 `spawn_blocking` 足够本机回环服务；宿主 crate 也用 rusqlite |
| 密码哈希 | argon2（Argon2id） | bcrypt、scrypt、SHA-256 | 施工单禁止用普通 SHA-256 代替密码哈希 |
| 出站 HTTP（模型、Remnawave、订阅拉取） | **ureq 3（阻塞）+ 注入接口 `HttpTransport`** | async-openai 0.42；reqwest；在 tokio 里直接用 hyper 客户端 | 路由跑在 blocking 线程池里，阻塞客户端不必再嵌套运行时。async-openai 基于 reqwest 异步栈，把请求与响应类型固定在它自己的结构体里，测试只能起一个假服务器；本服务要用可注入的传输核对 URL、鉴权头、请求体和各类错误，且本机不许监听端口。reqwest 阻塞模式内部仍起 tokio 运行时。Chat Completions 这里只用非流式请求、工具定义与第一条 choice 的文本/工具调用，`provider.rs` 约 140 行，不是通用 SDK |
| OpenAI 兼容协议 | 自写最小映射（`provider.rs`） | 复用 Node 基线的 openai@7.15.0 | 那是 JavaScript 运行时依赖，Rust 服务不能直接复用；只保留同一组请求字段与错误映射 |
| Remnawave | 自写最小适配（`remnawave.rs`，七条路由） | 社区 Rust SDK | 没找到维护中的 Remnawave Rust 客户端；基线已固定 backend 3.4.3 契约，七条路由直接按契约写，经同一个 `HttpTransport` |
| 订阅 YAML | yaml-rust2 0.13 | serde_yaml 0.9；serde_yml；saphyr 0.0.x | serde_yaml 已归档不再维护；serde_yml 维护状况有争议；saphyr 仍是 0.0.x。只需要读 `proxies[].name/type/server/port`，不需要 serde 反序列化 |
| 脱敏规则 | regex 1 | 手写匹配 | 要与客户端 `evidence.mjs` 的三条正则保持同义，手写容易漏边界；regex 保证线性时间 |
| 秘密保护 | windows-sys DPAPI（当前用户） | keyring、windows-dpapi 等封装；固定密钥 AES；Base64 | 施工单要求当前用户范围的系统保护能力，禁止固定密钥或 Base64。keyring 走凭据管理器，单条大小受限且不适合存大量引用；小封装 crate 维护者少。微软官方绑定只需两次调用与一次 LocalFree。非 Windows 平台直接报不可用，不退回明文 |
| 随机数 | getrandom | rand | 只要系统安全随机字节 |
| 日志 | 自写 `logging.rs` | tracing-appender、flexi_logger | 写入失败要能被读到并回报「日志未成功保存」，每轮新文件不覆盖 |

## 未采用但相关

- 宿主 crate（`apps/desktop-host/src-tauri`）RC2 没有改依赖。控制端的 DPAPI 在控制端进程里完成：宿主托管时控制端以当前 Windows 用户身份运行，保护范围就是这个用户。
- 旧 Node 控制端的 `openai@7.15.0` 与本服务无关，只作为请求形状与错误映射的对照。
