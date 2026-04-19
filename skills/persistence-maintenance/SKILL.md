---
name: Persistence Maintenance
slug: persistence-maintenance
category: post-exploitation
stage:
  - post-exploitation
  - maintenance
tags:
  - shell
  - session
  - token
  - persistence
  - third-zone
  - fourth-zone
priority: 25
summary: 比赛环境中的会话维持与权限保持技能，强调轻维持、低扰动、可回滚和证据保全。
when_to_load: 已获得 shell、webshell、session、token、cookie 或凭据，并且后续任务依赖稳定入口时。
tools:
  - mcp__sandbox__execute_code
  - toolset.terminal
  - toolset.note
signals:
  - 已经有执行面
  - 会话容易断开
  - 后续动作需要稳定身份
---

# Persistence Maintenance

## 适用场景 / 触发条件

- 已经拿到 shell、webshell、session、token、cookie、凭据或管理权限。
- 后续需要多步操作，担心单次入口不稳定。
- 比赛环境中需要保住现有成果，但又不希望过度破坏环境。

## 何时加载

- 首次获得可交互执行面时。
- 发现当前会话容易超时、崩溃、被清理或依赖单次请求。
- 计划进入横向、提权、域渗透、内网代理前。

## 输入线索 / 识别信号

- shell / webshell / RCE / 计划任务 / 定时器 / session / token / JWT / refresh token。
- 管理后台账号、SSH key、浏览器会话、服务账号口令。
- 反弹连接、弱保持、一次性上传入口、临时文件落点。

## 主要目标

- 在不过度扰动环境的前提下，让已有入口尽量稳定、可重复利用。
- 保护已获凭据、token、session 和关键路径不丢失。
- 给后续动作留下回退点和证据链。

## 推荐工具

- `toolset.terminal`：检查会话、环境变量、任务计划、服务状态。
- `toolset.note`：记录凭据、有效期、来源、权限边界、清理点。
- `mcp__sandbox__execute_code`：写小段脚本测试 token、cookie、弱保持接口。

## 执行步骤

1. 先判断当前入口类型：
   - 短生命周期请求型
   - 交互型 shell
   - 浏览器会话 / API token
   - 管理后台凭据
2. 决定采用“轻维持”还是“重持久化”：
   - 比赛场景优先轻维持，例如保存 token、留存凭据、保留可重放请求
   - 只有在后续路径强依赖稳定会话时，才考虑额外的任务计划、反连或多入口备份
3. 对每个入口记录四件事：
   - 来源
   - 权限
   - 失效条件
   - 可替代入口
4. 对 shell 类入口，优先确认：
   - 当前用户
   - 工作目录
   - 可写路径
   - 是否有稳定回显
   - 会话断开后的恢复方式
5. 对 token / session 类入口，优先确认：
   - 有效期
   - 刷新机制
   - 绑定 IP / UA / 设备与否
   - 是否能无交互续期
6. 对后续重要动作，先准备回退方案：备用凭据、备用路由、备用会话。

## 关键检查点 / 决策点

- 当前环境需要“轻维持”就够，还是确实需要额外保活？
- 这项维持动作是否会明显增加被发现或被清理的概率？
- 如果当前入口失效，是否还能从已有证据快速恢复？
- 是否已经出现域环境或多跳场景，应该切到其他技能？

## 失败时如何切换策略

- 如果 shell 不稳定，改保凭据、token、可重放请求。
- 如果 token 生命周期太短，优先找 refresh、SSO 或上游登录链。
- 如果重持久化风险太高，回退到多条轻入口并加强记录。
- 如果已经进入横向和域操作，切到 `ad-internal-ops` 或 `network-oa-pivot`。

## 需要记录的证据 / Notes

- 账号、token、cookie、webshell 路径、计划任务、反连参数。
- 每个入口的有效期、权限、作用域、验证时间。
- 稳定入口的使用方法和恢复步骤。
- 后续利用前后会影响入口稳定性的关键操作。

## 成功判据 / 退出条件

- 已经至少有一条稳定且可重放的入口。
- 已知入口失效后的恢复方法。
- 已把关键身份、凭据和会话证据保存完毕。

## 常见误区 / 风险提示

- 一获得入口就做重持久化，增加环境波动和暴露面。
- 只想着保 shell，不保 token、请求模板和凭据。
- 不记录来源和失效条件，导致后续无法恢复。
- 在比赛环境中忘记回滚意识，造成路径自断。
