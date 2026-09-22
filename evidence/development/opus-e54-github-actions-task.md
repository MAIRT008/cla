# E54 GitHub Actions 私有构建镜像 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Owner 指定的私有仓库 `https://github.com/MAIRT008/cla.git` 上建立最小、可审计、无秘密的 Windows 构建镜像，首次编译三个 Rust crate、运行 Rust 用例并生成 E54 所需的 NSIS 发布候选和证据。

**Architecture:** 当前项目目录不是 Git 仓库，且包含约 23 万个文件；不得原地 `git init` 后整目录上传。施工方先在独立目录按显式白名单复制构建所需文件，再把 GitHub Actions 工作流和许可生成材料加入镜像。工作流只允许手工触发，使用 GitHub 标准 Windows runner，无仓库写权限、无项目秘密，所有输入均固定版本并留下哈希。

**Tech Stack:** GitHub Actions、Windows Server hosted runner、Windows PowerShell 5.1、Rust 1.95.0 MSVC、Node 22、Tauri CLI 2.10.1、cargo-about 0.8.4、NSIS、项目现有 `tools/release/build-release.ps1`。

**Spec:** `evidence/delivery/build-packaging.md` §4、`evidence/delivery/t10-real-experiments.md` E54、`tools/release/release-inputs.json`。

## 裁决更新（2026-09-22，Codex，经 Owner 同意）

自 Round 1 复核之后的这条裁决起生效，不追溯改变此前的复核记录：

- `MAIRT008/cla` 保持公开。
- 允许上传经过白名单与秘密扫描的源码镜像、工作流，以及 pin 阶段诊断证据。
- 工作流取消“非 private 就失败”，改为只记录仓库可见性；其余边界检查全部保留。
- 仍禁止上传真实配置、账号资料、Token、证书、私钥和个人日志。
- 当前只运行 `mode=pin`。安装包和正式 build 产物的公开上传，要等 pin 复核和 GPL 源码提供方式的裁决之后再放行。
- 不安装 `gh`：工作流在 GitHub 网页上手动运行，产物也从网页下载。

## Global Constraints

- 本轮只做 E54 构建闭环；不启动 Azure，不安装产品，不启停服务，不运行 Mihomo，不改 WFP/TUN/DNS/代理/路由，不做 E53、E55—E58。
- GitHub 仓库必须保持 private；不得为了免额度改成 public。（已被上方 2026-09-22 裁决更新取代：仓库保持公开。）
- 不上传 `fixtures/`、`experiments/`、`dist/`、`build/`、`node_modules/`、真实配置、账号资料、Token、签名证书或签名私钥。
- 不修改当前工作目录的网络、系统服务、Rust/Node 环境；所有下载、编译和打包只发生在 GitHub runner。
- 工作流 `permissions` 固定为 `contents: read`；不得自动 commit、push、创建 release 或写回默认分支。
- Owner 只在自己的 GitHub Desktop、Git Credential Manager 或 `gh auth login` 中交互登录；不得把密码、PAT 或一次性验证码写进聊天、文档、脚本或仓库。
- 远端若非空，必须先克隆并核对现有内容；禁止 force push、覆盖历史或删除远端文件。
- 首次真实构建失败是有效结果；必须保存完整日志，不得用占位二进制、假锁文件、假许可清单或跳过检查换取绿色状态。

## Review Focus

1. 上传白名单遗漏正式编译依赖时必须在预检阶段失败，不得临时把整个工作区加入仓库。
2. 任一禁止目录、重解析点、私钥文件名或高置信秘密模式进入已跟踪文件时，CI 必须在下载依赖前失败。
3. Mihomo 必须来自 MetaCubeX `v1.19.30` 的准确 Windows AMD64 资产；归档摘要、解压后 EXE 摘要和 release commit 都要记录。
4. GitHub runner 只有约 14 GB SSD；磁盘不足必须留下容量与失败日志，不能删除失败证据后假报构建成功。
5. 只有 Rust 测试、发布检查、装配、Tauri/NSIS 构建和包内清单核对全部成功时才上传“candidate”产物；失败运行只上传诊断证据。

---

### Task 1: 建立独立的白名单构建镜像

**Files:**
- Source only: 当前项目目录中的明确白名单文件
- Create in mirror: `.gitignore`
- Create in mirror: `SOURCE-MIRROR.json`
- Do not modify: 当前项目目录的 `.gitignore`

**Interfaces:**
- Consumes: 当前工作目录的 RC6 Round 4 源码状态
- Produces: 一个不含历史大目录和秘密的独立 Git 工作目录；后续任务只在此目录建立 Git 历史

- [ ] **Step 1: 由 Owner 完成交互认证**

在 Windows Credential Manager、GitHub Desktop 或 GitHub CLI 中登录 `MAIRT008`。认证只留在系统凭据存储中。随后运行：

```powershell
$env:GIT_TERMINAL_PROMPT = '0'
git ls-remote 'https://github.com/MAIRT008/cla.git'
```

预期：命令退出 0。无输出表示空仓库；有输出表示非空仓库，必须先克隆并保留其历史。当前未认证会得到 `SEC_E_NO_CREDENTIALS`，不得用明文 PAT 绕过。

- [ ] **Step 2: 创建独立镜像目录**

使用新目录 `D:\AI学习\AI Environmental Steward GitHub Build`。若它已经存在，停止并报告，不删除、不覆盖。不得在当前项目根执行 `git init`。

- [ ] **Step 3: 只复制下列白名单**

```text
根文件：AGENTS.md、README.md、ARCHITECTURE.md、PROJECT_OVERVIEW.md
目录：DOCS/
目录：apps/desktop-ui/
目录：apps/desktop-host/（排除所有 target/）
目录：services/control-rs/（排除所有 target/）
目录：src/
目录：tools/
目录：tests/
目录：vendor/deps/js-yaml-4.3.0/
目录：evidence/delivery/
文件：evidence/development/opus-e54-github-actions-task.md
```

不复制 `services/control/`：它是 Node 行为基线而非 RC6 运行依赖；`release-inputs.json` 已明确排除。也不复制任何 `fixtures/`、`experiments/`、`dist/`、`build/`、`audits/`、`examples/`、`history/` 或其他 `evidence/development/`。

- [ ] **Step 4: 在镜像根创建专用 `.gitignore`**

文件内容固定为：

```gitignore
build/
node_modules/
**/target/
fixtures/
experiments/
dist/
services/control/
*.pfx
*.p12
*.pem
*.key
.env
.env.*
```

- [ ] **Step 5: 生成源镜像清单**

`SOURCE-MIRROR.json` 至少包含：原工作区绝对路径仅写成逻辑名 `AI Environmental Steward`，生成 UTC 时间、白名单版本 `e54-1`、每个被复制文件的仓库相对路径、字节数和 SHA-256。清单不得记录本机用户名或绝对路径。

- [ ] **Step 6: 在初始化 Git 前执行秘密与边界检查**

检查镜像中不存在以下路径和文件：

```text
fixtures/ experiments/ dist/ build/ services/control/ node_modules/
*.pfx *.p12 *.pem *.key .env .env.* auth.json credentials.json
```

再以“只返回文件名、不打印匹配正文”的方式检查：PEM 私钥头、`github_pat_`、`ghp_`、AWS `AKIA`、常见 `sk-` Key。任何命中都停止，逐个证明是合成测试值或从镜像移除；不得把命中正文写进日志。

- [ ] **Step 7: 初始化或接入远端**

空远端：在镜像目录 `git init -b main`，添加远端并建立首个提交。非空远端：先克隆到镜像目录，再把白名单文件复制进克隆，不覆盖未知现有文件。首个提交只包含白名单、镜像清单和后续任务新增的 CI 文件。

预期提交信息：

```text
build: add bounded E54 source mirror
```

### Task 2: 固定许可生成和 NSIS 预热输入

**Files:**
- Create: `tools/release/about.toml`
- Create: `tools/release/about.hbs`
- Create: `tools/release/generate-rust-licenses.ps1`
- Create: `tools/release/nsis-warmup/Cargo.toml`
- Create: `tools/release/nsis-warmup/build.rs`
- Create: `tools/release/nsis-warmup/src/main.rs`
- Create: `tools/release/nsis-warmup/tauri.conf.json`
- Create: `tools/release/nsis-warmup/dist/index.html`

**Interfaces:**
- Consumes: 三个现有 `Cargo.toml`、cargo-about 0.8.4、Tauri CLI 2.10.1
- Produces: 三份真实 `Cargo.lock`、`build/inputs/THIRD-PARTY-RUST.txt`、Tauri 私有 NSIS 缓存

- [ ] **Step 1: 建立显式许可策略**

`about.toml` 只接受当前已知的宽松许可与本项目 GPL：Apache-2.0、MIT、BSD-2-Clause、BSD-3-Clause、ISC、Unicode-3.0、Unicode-DFS-2016、Zlib、MPL-2.0、CC0-1.0、BSL-1.0、OpenSSL、GPL-3.0-only、GPL-3.0-or-later。cargo-about 报出其他许可时保持失败，交 Codex 逐项裁决，不得自动追加通配许可。

- [ ] **Step 2: 建立纯文本 Handlebars 模板**

输出依次包含许可 SPDX 名称、使用该许可的 crate 名称与版本、仓库地址（存在时）和许可正文。文件开头注明：生成工具 `cargo-about 0.8.4`、目标 `x86_64-pc-windows-msvc`、三个 manifest 相对路径。

- [ ] **Step 3: 实现许可生成脚本**

`generate-rust-licenses.ps1` 固定处理以下 manifest：

```text
services/control-rs/Cargo.toml
apps/desktop-host/vendor/service-ipc/Cargo.toml
apps/desktop-host/src-tauri/Cargo.toml
```

对每个 manifest 先运行 `cargo generate-lockfile --manifest-path <path>`，再用仓库内 `about.toml` 和 `about.hbs` 生成独立片段；三个片段按上述顺序合并成 `build/inputs/THIRD-PARTY-RUST.txt`。任何一步非零退出时删除本次未完成的目标文件并非零退出。

- [ ] **Step 4: 建立最小 NSIS 预热工程**

预热工程只用于让 Tauri CLI 2.10.1 下载其固定的 NSIS 与 `nsis_tauri_utils` 到 `%LOCALAPPDATA%\tauri\NSIS\`。依赖固定为 `tauri = 2.11.5`、`tauri-build = 2.6.3`；标识为 `local.ai-environmental-steward.nsis-warmup`，bundle target 仅 `nsis`。页面只含静态 `index.html`。它不进入产品发布清单，构建后删除其 `target/`。

- [ ] **Step 5: 提交构建辅助文件**

```text
build: pin E54 license and NSIS preparation
```

### Task 3: 建立手工触发的 Windows E54 工作流

**Files:**
- Create: `.github/workflows/e54-windows-release.yml`
- Modify: `tools/release/release-inputs.json`（只在官方资产核验后写入 Mihomo 解压后 EXE 的 SHA-256，并清除 `PIN_REQUIRED`）

**Interfaces:**
- Consumes: Task 1 的白名单镜像、Task 2 的许可与预热材料、MetaCubeX v1.19.30 官方 release metadata
- Produces: GitHub Actions 运行记录、三个锁文件、许可汇总、NSIS 安装包、发布清单、哈希表和构建日志

- [ ] **Step 1: 工作流权限和触发器**

工作流只使用 `workflow_dispatch`；顶层：

```yaml
permissions:
  contents: read
```

使用 `windows-2025` 标准 runner，`timeout-minutes: 240`，并设置同一分支仅允许一个 E54 运行。不得接收自由文本 URL、脚本或秘密输入。

- [ ] **Step 2: checkout 后先做镜像边界检查**

通过 `git ls-files` 拒绝 Global Constraints 中的禁止目录与秘密文件名；再次运行高置信秘密模式文件名扫描。检查失败时仍上传 `SOURCE-MIRROR.json` 和边界检查日志，但不安装工具、不下载依赖。

- [ ] **Step 3: 固定工具版本**

```text
Node.js 22.x
Rust 1.95.0-x86_64-pc-windows-msvc
tauri-cli 2.10.1（cargo install --locked）
cargo-about 0.8.4（cargo install --locked --features cli）
```

记录 `node --version`、`rustc --version --verbose`、`cargo --version`、`cargo tauri --version`、`cargo about --version` 和 runner image 信息到 `build/logs/tool-versions.txt`。

- [ ] **Step 4: 预热 NSIS 并执行 PlanOnly 红门**

先在 `tools/release/nsis-warmup/` 执行一次 `cargo tauri build --bundles nsis`，确认 `%LOCALAPPDATA%\tauri\NSIS\makensis.exe` 存在；删除预热工程 `target/`。随后执行项目现有 `build-release.ps1 -PlanOnly`。第一次预期因 Mihomo pin、锁文件或许可汇总缺失得到 `NOT_READY`，该日志必须保留，不能当作 workflow 失败原因被覆盖。

- [ ] **Step 5: 从官方 release metadata 固定 Mihomo**

使用 GitHub REST API读取 `MetaCubeX/mihomo` tag `v1.19.30`，只接受资产名：

```text
mihomo-windows-amd64-v1.19.30.zip
```

要求 release tag 指向提交前缀 `ac017cd`，资产必须带 GitHub 返回的 `sha256:` digest。下载后先核对归档 digest，再解压；要求归档内恰好一个预期 Windows AMD64 EXE。把 EXE 放到 `build/inputs/mihomo-windows-amd64-v1.19.30.exe`，计算 EXE SHA-256，生成 `build/logs/mihomo-pin.json`，内容包括 tag、commit、资产名、资产 URL、归档 digest、EXE digest和文件大小。

首次 pin 运行只生成 `mihomo-pin.json` 与一份把 EXE digest 写入 `tools/release/release-inputs.json` 的补丁，工作流不得自动提交。OPUS 将该单行 pin 变更带回当前项目，经 Codex 核对后再触发正式构建。

- [ ] **Step 6: 生成真实锁文件与许可汇总**

执行 `generate-rust-licenses.ps1`。把三份 `Cargo.lock`、`THIRD-PARTY-RUST.txt` 及各自 SHA-256 写入 `build/logs/generated-inputs.json`。任何未裁决许可导致的 cargo-about 失败保持失败并交回日志。

- [ ] **Step 7: 运行三个 crate 的 Rust 用例**

按顺序执行并分别留日志：

```powershell
cargo test --manifest-path services/control-rs/Cargo.toml
cargo test --features service --manifest-path apps/desktop-host/vendor/service-ipc/Cargo.toml
```

宿主带 Tauri 的测试需要装配目录，放到完整构建后执行。前两项任何失败均停止，不生成候选安装包。

- [ ] **Step 8: 执行现有完整构建入口**

清理本次运行产生的旧 `build/release-staging/` 后，执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\release\build-release.ps1
```

要求 `release.mjs check` 为 `READY`，`assemble` 成功，`cargo tauri build --features tauri` 生成 NSIS 包。

- [ ] **Step 9: 运行宿主 Rust 用例**

```powershell
cargo test --features tauri --manifest-path apps/desktop-host/src-tauri/Cargo.toml
```

失败时整个运行 FAIL，安装包不得标成 candidate。

- [ ] **Step 10: 核对安装包和发布清单**

记录 NSIS 安装包、三个运行时 EXE、Mihomo EXE、`release-manifest.json`、三份 Cargo.lock 和许可汇总的 SHA-256。解开安装包或使用 NSIS 可复核方式列出实际文件，确认与 manifest 一致，且不含 `services/control/`、`fixtures/`、`experiments/`、`dist/`、`tests/`、`evidence/`、秘密或本机绝对路径。

- [ ] **Step 11: 分离成功与失败产物**

所有门通过时上传 artifact `e54-candidate`：安装包、manifest、锁文件、许可汇总、哈希表和完整日志。任何门失败时只上传 `e54-diagnostics`：日志、检查 JSON、工具版本、磁盘容量和生成到失败点的非秘密元数据；不得上传半成品安装包。

- [ ] **Step 12: 提交工作流**

```text
ci: add bounded Windows E54 release build
```

### Task 4: 施工交接与独立复核

**Files:**
- Create: `evidence/development/e54-github-actions-handoff.md`
- Create: `evidence/development/e54-github-actions/` 下的下载证据副本
- Do not modify: RC1—RC6 历史证据和 E01—E53/E55—E58 状态

**Interfaces:**
- Consumes: GitHub Actions run URL、commit SHA、下载 artifacts
- Produces: Codex 可独立复核的 E54 交接；只有复核后才能决定 E54 是否关闭、是否启动 Azure

- [ ] **Step 1: 交回精确来源**

记录私有仓库 URL、分支、commit SHA、workflow run ID、runner image、开始/结束 UTC 时间和 artifact SHA-256。不得把短期下载 URL 或认证信息写进交接。

- [ ] **Step 2: 交回失败也要完整**

如果失败，列出首个真实失败点、退出码、对应日志文件和它属于源码、依赖、工具链还是 runner 环境；不得先自行扩大到 Azure 或实机测试。

- [ ] **Step 3: 停手等待 Codex**

成功时也不得自行把 RC6 标为关闭，不得开始 E53/E55—E58。Codex 将核对源镜像边界、workflow 权限、Mihomo pin、Rust 测试、manifest、安装包内容和证据完整性，再发布下一步。

## Self-Review

- Spec coverage：覆盖 `build-packaging.md` §4 的工具、PlanOnly、Mihomo pin、三份锁文件、许可汇总、完整构建、日志和包内清单；覆盖 E54，但不越到其他 E 编号。
- Placeholder scan：无 TBD/TODO；遇未知许可或远端非空时定义为明确失败/停点，而非自行补全。
- Type consistency：三份 manifest、三个锁文件、Mihomo 输入路径、`THIRD-PARTY-RUST.txt` 和发布清单路径与现有 `release-inputs.json` 一致。
- Review Focus：五项均绑定到 Task 1 或 Task 3 的强制检查。

