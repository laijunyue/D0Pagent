# ctf SKILLS Workflow

本地 `SKILLS` 库的目标不是替代原有 system prompt，也不是替代 `mcp__sandbox__execute_code + toolset` 的实操链路，而是给 Agent 提供一套可按需加载的高质量作战手册。

## 加载原则

1. 先调用 `ListSkills` 观察可用技能摘要、标签、适用阶段。
2. 如场景明确，再调用 `SearchSkills` 缩小到 1 到 3 个候选技能。
3. 只对当前阶段最相关的技能调用 `LoadSkill`，不要一次性把所有技能都读进上下文。
4. 默认先加载 `core-methodology`，再按目标类型补场景技能。
5. 技能加载后，继续通过 `mcp__sandbox__execute_code` 写小段 Python，在代码里 `import toolset` 驱动 browser / proxy / terminal / note。

## 推荐起手式

- Web / SRC / 众测入口不明：先 `core-methodology`，再 `src-web-recon`。
- 已定位到具体 Web 参数点或业务流程：补 `web-vuln-hunting`。
- 题目明显是 N-day / CVE / 云安全 / AI 组件：补 `cve-cloud-aiinfra`。
- 题目出现 OA、多层网络、代理、内网接口：补 `network-oa-pivot`。
- 题目进入 shell、webshell、session、token 阶段：补 `persistence-maintenance`。
- 题目进入域环境或企业内网：补 `ad-internal-ops`。
- 题目要求使用 MSF 或明显适合用 MSF：补 `msf-operations`。
- 零界平台中的社交型、注入型、信息型题目：先 `prompt-injection-defense`，再按情况补 `fragmented-key-exchange`、`content-influence-competition`、`realtime-osint-treasure`。

## 赛区到技能映射

| 赛区 / 场景 | 推荐技能 |
| --- | --- |
| 第一赛区：识器·明理 | `core-methodology`, `src-web-recon`, `web-vuln-hunting`, `realtime-osint-treasure` |
| 第二赛区：洞见·虚实 | `core-methodology`, `cve-cloud-aiinfra`, `web-vuln-hunting`, `msf-operations` |
| 第三赛区：执刃·循迹 | `core-methodology`, `network-oa-pivot`, `persistence-maintenance`, `msf-operations` |
| 第四赛区：铸剑·止戈 | `core-methodology`, `ad-internal-ops`, `persistence-maintenance`, `msf-operations` |
| 平行战场：零界 | `prompt-injection-defense`, `fragmented-key-exchange`, `content-influence-competition`, `realtime-osint-treasure` |

## 技能使用注意事项

- 技能是决策框架，不是“照抄命令清单”。
- 任何自动化扫描都要建立在事实收集之后，先确认边界、入口、版本、身份、流量与功能。
- 任何利用链都要边做边记录事实证据到 `toolset.note` 或 workspace 产物。
- 超时不是放弃信号，而是切小任务、换路径、补证据、再重试。
- 若技能建议与现场证据冲突，以现场证据优先，并及时切换技能。

## 新增技能约定

- 每个技能放在独立目录中，目录名即默认 `slug`。
- 技能正文文件固定为 `SKILL.md`。
- 推荐在 frontmatter 中声明：
  - `name`
  - `slug`
  - `category`
  - `stage`
  - `tags`
  - `priority`
  - `summary`
  - `when_to_load`
  - `tools`
  - `signals`
- `SkillManager` 会自动扫描并重建 `skills/index.yaml`，损坏的技能不会拖垮整个 runtime，只会被记录到 `workspace/logs/skills.jsonl`。
