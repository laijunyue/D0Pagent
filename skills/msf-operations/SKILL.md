---
name: MSF Operations
slug: msf-operations
category: exploitation
stage:
  - exploitation
  - pivot
  - post-exploitation
tags:
  - metasploit
  - msf
  - auxiliary
  - third-zone
  - fourth-zone
priority: 55
summary: 面向本项目已接入 MSF MCP 能力的使用原则与稳定调用方法，强调 MSF 是辅助推进工具，而不是替代分析的黑盒。
when_to_load: 需要检索模块、管理 workspace、统一管理 sessions 或在已有证据下执行明确的 MSF 辅助动作时。
tools:
  - mcp__msf__get_status
  - mcp__msf__search_modules
  - mcp__msf__workspace
  - mcp__msf__db_query
  - mcp__msf__session
  - mcp__msf__module
signals:
  - 需要模块检索
  - 需要会话或路由管理
  - 需要统一记录 MSF 操作
---

# MSF Operations

## 适用场景 / 触发条件

- 当前项目中的 `mcp__msf__*` 工具族已经启用并健康。
- 需要借助 MSF 做模块检索、workspace 管理、session 管理、数据库视图整理。
- 已有比较明确的攻击假设，不想手工重复搭脚手架。

## 何时加载

- 想确认 MSF 是否可用、有哪些模块、当前有哪些 sessions。
- 已经有版本、服务、漏洞信息，准备做针对性 module 检查或执行。
- 需要多会话、多路径管理，但仍希望保持 runtime 主链路不变。

## 输入线索 / 识别信号

- 目标服务类型和版本已知。
- 需要路由、会话、模块、workspace、DB 视图等管理动作。
- 已出现多台主机、多会话、多 exploit 候选。

## 主要目标

- 让 MSF 充当辅助推进和统一管理层，而不是替代前期分析。
- 保持对 workspace、module、session 的可观测和可复现。
- 避免盲打 exploit、盲搜模块、盲执行 payload。

## 推荐工具

- `mcp__msf__get_status`
- `mcp__msf__search_modules`
- `mcp__msf__workspace`
- `mcp__msf__db_query`
- `mcp__msf__session`
- `mcp__msf__module`

## 执行步骤

1. 先用 `mcp__msf__get_status` 确认 sidecar、warmup、service process 都正常。
2. 进入一轮新目标前，先决定 workspace 命名规则，避免多个目标混在一起。
3. 在模块使用前，先准备三个前提：
   - 服务/版本/架构证据
   - 目标可达性
   - 成功后的 session 或 payload 预期
4. 搜索模块时，先用关键词缩小范围，再看 `info`、`options`、`check`，不要一上来就 `run`。
5. 对 exploit 模块优先顺序：
   - 先 `info`
   - 再 `show options`
   - 再补齐明确参数
   - 优先 `check`
   - 最后才 `execute` 或 `run`
6. 对 sessions：
   - 每次都记录 session 来源、目标主机、用途
   - 不要无计划地堆 session
   - 需要稳定保活时联动 `persistence-maintenance`

## 关键检查点 / 决策点

- 现在用 MSF 是否真的比本地终端/手工更高效？
- 模块的利用前提是否已经被事实支撑？
- 当前 workspace 是否干净、目标是否明确、结果是否可追踪？
- 当前 session 是否已经足以推进下一步，而不是继续盲扩？

## 失败时如何切换策略

- 如果模块条件不明，回退到手工验证和本地工具。
- 如果 `check` 结果不稳，优先补服务、版本和网络事实。
- 如果 session 不稳定，切到 `persistence-maintenance` 先保入口。
- 如果已进入域和横向阶段，结合 `ad-internal-ops` 或 `network-oa-pivot`。

## 需要记录的证据 / Notes

- workspace 名称、目标、模块、参数、结果。
- 每个 session 的来源、权限、目标、用途。
- `check` 与 `execute` 的区别、失败原因、环境前提。
- 通过 MSF 得到的新资产、服务、凭据和路径。

## 成功判据 / 退出条件

- MSF 帮你更稳定地完成了模块检索、会话管理或明确利用。
- 没有把分析过程外包给 MSF 黑盒。
- 当前 workspace 与 session 状态清晰可复现。

## 常见误区 / 风险提示

- 看见 MSF 可用就什么都想用它做。
- 先 `run` 后补证据。
- 不分 workspace，多个目标混在一起。
- 不清楚 session 来源和用途，导致后续操作混乱。
