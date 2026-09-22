# 使用说明（模拟阶段）

日期：2026-09-14。这份说明描述**当前可运行的东西**：一个用合成资料驱动的四模块应用组合根，加上它的界面与管理后台。它不是安装说明——没有安装包，桌面宿主未接入真实业务会话，见 [构建与打包](build-packaging.md)。

## 1. 前提

- Node v22 或更高（用到 `node:sqlite`，会打印一条实验特性警告）。
- 不需要 `npm install`，没有 `package.json`。
- 工作目录是项目根 `AI Environmental Steward/`。所有命令从这里发。

## 2. 跑一遍

```powershell
node apps/desktop-ui/build-offline-bundle.mjs     # 生成 app.bundle.js
node --check apps/desktop-ui/app.bundle.js        # 语法检查
node tests/ui/run-synthetic.mjs test              # 界面事件级验收 20/20
node tests/delivery/run-acceptance.mjs test       # 跨模块 X01—X20 20/20
node tools/build-traceability.mjs                 # 重建实现映射 352/352
```

原模块回归：

```powershell
node --test tests/ai/*.test.mjs tests/audit/*.test.mjs tests/control/*.test.mjs tests/diagnostics/*.test.mjs
node --test tests/local/*.test.mjs tests/network/*.test.mjs
node --test tests/delivery/gaps.test.mjs
```

每次运行都会在 `fixtures/*/runs/` 下新建一次性工作区，不会碰系统目录、真实浏览器 Profile、代理或网络设置。

## 3. 界面上有什么

页面是 `apps/desktop-ui/index.html`，四个导航：

| 导航 | 能做的事 |
|---|---|
| 环境体检 · 本地 | 深扫/快扫/专项、进度与取消、逐身份回答账号状态、五类结果与问题详情（可选保留或判误报）、可调推荐、固定确认框、批量执行、复查、恢复对象选择与恢复预览、续接执行、脱敏导出 |
| 环境体检 · 网络诊断 | 选环境与 Profile、深扫、接入采样回传、生成修复计划、确认、执行、复查、恢复；AI 模式诊断与"确认 AI 网络建议"两步分开 |
| 网络方案 | 三套方案的预览与应用、常规维护应用、恢复上一配置、白名单增删启停与恢复默认、关闭窗口（不停内核）、触发保护、应急开启/结束（带目标、期限与本次确认勾选） |
| 流量与日报 | 刷新额度与事件、速率与归属（未知按未知显示）、日报与时间线、历史、MD/JSON 导出、生成 AI 附注 |
| 设置 | 当前身份与角色、模型能力（来自服务端能力接口）、界面偏好与重置、管理入口（仅管理员会话可见） |

几个当前行为值得知道：

- **扫描或批量处理进行中**，依赖它们的按钮会置灰；即使绕过置灰把事件送到服务，也会拿到 `SCAN_IN_PROGRESS` 或 `OPERATION_IN_PROGRESS`，并且不会打断正在跑的任务。
- **身份决定一切**。任务恢复、白名单、AI 会话归属都按认证会话的 `user_ref` 隔离。未注册令牌没有身份，看不到任何用户的数据，也拿不到 AI 会话。
- **未接入的能力会写出来**。原生桥接未接入时侧栏直接写明；模型不可用时能力区写明，标准检查、历史与恢复仍可用。

## 4. 页面怎么接到服务

```
index.html
  └─ bridge.js        先加载，决定 __STEWARD__ 从哪来
       ├─ __STEWARD_HOST__（合成宿主 apps/desktop-ui/host.mjs 注入）→ 直接分发到会话
       └─ Tauri invoke('steward_request', {op:'UiAction'}) → 目前返回 UI_BACKEND_NOT_ATTACHED
  └─ app.bundle.js    由 app.js 生成，只做页面与事件
```

会话在 `apps/desktop-ui/session.mjs`，组合根在 `apps/desktop-ui/compose.mjs`。组合根注入 T2 审计产物、T3 本地服务、T4 AI 会话与能力、T5 网络控制器、T6 管理后台、T7 诊断控制器。页面自己不持有任何业务状态。

## 5. 管理后台

管理动作全部经 `services/control/` 的 HTTP handler，路径固定在 `/api/admin/*`，由会话令牌认证并要求 admin 角色。合成环境里的令牌：

| 令牌 | 身份 | 角色 |
|---|---|---|
| `token-max` | user-max | user |
| `token-pro` | user-pro | user |
| `token-free` | user-free | user |
| `token-admin` | admin | admin |

普通用户或未注册令牌调用管理接口会被控制端拒绝，页面上也看不到管理卡片。

## 6. 合成资料在哪

| 用途 | 位置 |
|---|---|
| 本地清理的合成客户端/浏览器/数据库 | `tests/local/demo.mjs` 的 `createSyntheticFixture` + `SYNTHETIC_ENVIRONMENT` |
| 审计日志源与归档/日报产物 | 每次运行时由 `apps/desktop-ui/compose.mjs` 的 `buildAuditArtifacts` 生成到工作区 `audit/` |
| 管理后台三用户资源与额度权威替身 | `fixtures/control/harness.mjs`、`fixtures/control/authoritySim.mjs` |
| 合成模型脚本 | `fixtures/ui/aiModelScript.mjs`、`fixtures/delivery/aiScripts.mjs` |
| 诊断探测替身 | `src/adapters/diagnostics/index.mjs`、`fixtures/diagnostics/harness.mjs` |

## 7. 不要误解的地方

- 这些命令验证的是**业务逻辑与页面接线**。真实 Profile、真实网络、真实模型、OS 保护、安装包都没有验证。
- 界面点击验收跑在 `tests/ui/page.mjs` 的最小 DOM 上，不是 Chrome 实点。
- 审计日报来自项目内合成日志，不是真实路由证据。
- 额度权威是 `authoritySim`，不是真实 Remnawave 后端。
