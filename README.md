# D0Pagent

`D0Pagent` 是一个面向 CTF / 渗透场景的本地化智能体。思考与总结请移步至个人博客https://laijunyue.github.io/2026/04/19/%E7%AC%AC%E4%BA%8C%E5%B1%8A%E8%85%BE%E8%AE%AF%E4%BA%91%E9%BB%91%E5%AE%A2%E6%9D%BE%E6%99%BA%E8%83%BD%E6%B8%97%E9%80%8F%E6%8C%91%E6%88%98%E8%B5%9B%E5%AD%A6%E4%B9%A0%E4%B8%8E%E5%8F%8D%E6%80%9D/

> Agent 意图 -> Metatooling -> PythonExecutor 执行 -> 代码内部 `import toolset` -> Browser / Terminal / Proxy / Note 协作

项目主要支持两种模式：

- 单题模式：传入 `--ctf`，启动一个本地 `Runtime` 解一道题。
- 官方比赛模式：传入 `--auto-hackathon`，启动 `HackathonOrchestrator`，调用官方挑战平台 MCP，按题目编排和隔离运行。

## 核心流程

### 单题模式

```text
main.py
  -> Runtime
      -> 加载 .env / 准备 workspace
      -> 启动 browser service
      -> 初始化 PythonExecutor
      -> 初始化 SkillManager / CVE Knowledge / 可选 MSF / 可选比赛平台工具
      -> CompatibleToolRegistry
      -> LocalCTFSolverAgent (LangGraph + ChatOpenAI-compatible backend)
          -> mcp__sandbox__execute_code
              -> import toolset
              -> toolset.browser / terminal / proxy / note
```

### 自动闯关模式

```text
main.py --auto-hackathon
  -> HackathonOrchestrator
      -> ChallengePlatformClient
      -> 按题目创建独立 Runtime
      -> 每题独立 workspace / browser / PythonExecutor / 日志
      -> EvidenceStore 维护跨 attempt 结构化证据
      -> 平台 submit_flag 结果作为最终权威判定
```

## 运行环境

### 推荐环境

- 操作系统：Linux，推荐 Ubuntu 20.04+ 或等价环境
- Python：`>= 3.11`，实际仓库当前在 `Python 3.12` 环境下也有运行产物
- Shell / 终端能力：需要可用的 `tmux`
- 浏览器能力：需要 Playwright 的 Chromium

Linux / Ubuntu 最小系统依赖可以先准备：

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip tmux
```

### Python 依赖

项目主依赖声明位于：

- `requirements.txt`
- `pyproject.toml`

核心 Python 包包括：

- `langgraph`
- `langchain-core`
- `langchain-openai`
- `python-dotenv`
- `jupyter-client`
- `ipykernel`
- `nbformat`
- `playwright`
- `fastmcp`
- `mcp`
- `gql`
- `libtmux`
- `pyyaml`
- `requests`

### 可选增强工具

下面这些不是运行主链路的硬性前置，但如果希望启用对应能力，建议提前安装并加入 `PATH`：

- Web 扫描封装：`httpx`、`katana`、`ffuf`、`nuclei`、`sqlmap`
- 终端里常见渗透工具：`dirsearch`、`nmap`、`masscan` 等
- 流量平台：Caido
- Metasploit：`msfconsole`，`msfrpcd` 可选
- 可视终端：`xfce4-terminal`，仅在 `NO_VISION=0` 时有意义

说明：

- `run_httpx_scan` / `run_katana_crawl` / `run_ffuf_scan` / `run_nuclei_scan` / `run_sqlmap_scan` 本质上都是通过 `toolset.terminal` 包装本机命令，所以对应命令必须真实存在。
- `ffuf` 的默认字典路径写死为 `/home/ubuntu/Public/dicc.txt`。如果你的环境没有这个文件，使用时请显式传 `wordlist`。

## 安装

### 1. 创建虚拟环境并安装依赖

```bash
cd /home/Pentest_Agent/D0Pagent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

如果你希望把项目本身也按 editable 方式安装，可以再执行：

```bash
pip install -e .
```

### 2. 准备配置文件

程序启动时会优先读取项目根目录下的 `.env`。可以直接参考 `.env.example`：

```bash
cp .env.example .env
```

### 3. 配置模型后端

代码当前通过 `langchain_openai.ChatOpenAI` 初始化模型，因此推荐提供一组兼容 `base_url + api_key + model` 的配置。运行时同时接受三套变量命名：

- 通用前缀：`LLM_*`
- 兼容别名：`ANTHROPIC_*`
- 兼容别名：`OPENAI_*`

最推荐直接使用：

```bash
LLM_BASE_URL="https://your-endpoint"
LLM_AUTH_TOKEN="your-token"
LLM_MODEL="your-model-name"
```

也可以使用兼容别名，例如：

```bash
ANTHROPIC_BASE_URL="https://your-endpoint"
ANTHROPIC_AUTH_TOKEN="your-token"
ANTHROPIC_MODEL="your-model-name"
```

运行时代码还支持以下回退取值：

- 认证：`DASHSCOPE_API_KEY`、`OPENAI_API_KEY`
- 地址：`OPENAI_BASE_URL`
- 模型：`OPENAI_MODEL`

## 关键配置项

### 常用环境变量

| 变量 | 作用 | 默认行为 |
| --- | --- | --- |
| `LLM_BASE_URL` / `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` | 模型接口地址 | 必填 |
| `LLM_AUTH_TOKEN` / `ANTHROPIC_AUTH_TOKEN` / `DASHSCOPE_API_KEY` / `OPENAI_API_KEY` | 模型认证 | 必填 |
| `LLM_MODEL` / `ANTHROPIC_MODEL` / `OPENAI_MODEL` | 模型名 | 必填 |
| `CTF_MAX_STEPS` | LangGraph 最大步数 | 默认 `96` |
| `CTF_MAX_TOKENS` | 单次模型最大输出 token | 默认 `4096` |
| `CTF_TEMPERATURE` | 模型温度 | 不设置则交给 SDK 默认值 |
| `NO_VISION` | 是否 headless 启动浏览器 | 默认 `1` |
| `BROWSER_PORT` / `CTF_BROWSER_PORT` | 本地浏览器 CDP 端口 | 优先尝试 `9222`，占用时自动换端口 |
| `ENABLE_MSF_MCP` | 是否启用本地 MSF 集成 | 默认开启，但环境不满足时会自动降级 |
| `CAIDO_PORT` / `CAIDO_TOKEN` | 启用 `toolset.proxy` 所需配置 | 不配置则代理工具返回清晰错误 |
| `PENTEST_MCP_URL` / `PENTEST_MCP_SERVER_HOST` | 官方比赛 MCP 地址 | 仅 `--auto-hackathon` 必需 |
| `PENTEST_AGENT_TOKEN` | 官方比赛平台 Token | 仅 `--auto-hackathon` 必需 |

### 官方比赛模式相关变量

官方平台接入由 [第二届腾讯云黑客松智能渗透挑战赛MCP接入文档.md](./第二届腾讯云黑客松智能渗透挑战赛MCP接入文档.md) 和 `runtime/challenge_platform.py` 实现。至少需要：

```bash
# 二选一，PENTEST_MCP_URL 优先级更高
PENTEST_MCP_SERVER_HOST="127.0.0.1:8080"
PENTEST_MCP_URL="http://127.0.0.1:8080/mcp"

# 比赛环境页面提供
PENTEST_AGENT_TOKEN="your-agent-token"
```

官方挑战平台工具包括：

- `mcp__challenge__list_challenges`
- `mcp__challenge__start_challenge`
- `mcp__challenge__stop_challenge`
- `mcp__challenge__submit_flag`
- `mcp__challenge__view_hint`

注意：

- 在 `--auto-hackathon` 的单个 attempt 内，运行时默认会禁用 `start_challenge` / `stop_challenge` / `view_hint` 这类生命周期工具，由 orchestrator 统一管理，避免实例抖动。
- 官方模式下，是否“真正解出”以平台 `submit_flag` 返回和 `flag_got_count / flag_count` 为准，不是本地看到 `flag{...}` 就算完成。

### MSF 集成相关变量

MSF 集成由 `meta-tooling/service/msfconsole_mcp.py` 和 `runtime/msf_client.py` 提供，当前是可选增强能力：

```bash
ENABLE_MSF_MCP="1"
MSF_MCP_PORT="28765"
MSFCONSOLE_MCP_DIR="/home/Pentest_Agent/D0Pagent/meta-tooling/service/vendors/msfconsole_mcp"
MSFCONSOLE_PATH="/usr/bin/msfconsole"
MSFRPCD_PATH="/usr/bin/msfrpcd"
MSF_DEFAULT_WORKSPACE="default"
```

行为说明：

- 如果 `ENABLE_MSF_MCP=0`，运行时不启动 MSF 集成。
- 如果 `msfconsole` 不存在、vendor 目录缺失、依赖不满足或 warmup 失败，主流程不会中断，只是不会向 Agent 注册 `mcp__msf__*` 工具。

## 运行命令

先查看帮助：

```bash
python main.py -h
```

### 单题模式

最小启动方式：

```bash
python main.py --ctf "http://example.com" --workspace workspace
```

也可以传入文字描述而不只是 URL：

```bash
python main.py --ctf "Target: http://example.com, focus on web login and flag retrieval" --workspace workspace
```

如果不传 `--workspace`，默认目录为 `workspace`。  
如果不传 `--max-steps`，优先读取 `CTF_MAX_STEPS`，否则默认 `96`。

示例：

```bash
python main.py --ctf "http://example.com" --workspace workspace --max-steps 64
```

### 官方自动闯关模式

最小启动方式：

```bash
python main.py --auto-hackathon --workspace workspace
```

只跑指定题目：

```bash
python main.py --auto-hackathon --workspace workspace --only-codes AAA,BBB
```

跳过部分题目：

```bash
python main.py --auto-hackathon --workspace workspace --skip-codes AAA,BBB
```

限制步数与并发：

```bash
python main.py --auto-hackathon --workspace workspace --max-steps 40 --max-concurrent-challenges 2
```

控制提示词策略：

```bash
python main.py --auto-hackathon --workspace workspace --hint-policy-mode conservative
```

当前代码中 `--hint-policy-mode` 支持的主要模式有：

- `default`
- `conservative`
- `aggressive`
- `never`

并发上限在代码里会被限制到 `3`。

## 当前运行时能力

### 1. Agent 主工具

- `mcp__sandbox__execute_code`
- `mcp__sandbox__list_sessions`
- `mcp__sandbox__close_session`

这三者由 `meta-tooling/service/python_executor_mcp.py` 中的 `PythonExecutor` 支撑，底层是状态化 Jupyter Kernel，会把执行过程持久化为 `python_sessions/*.ipynb`。

### 2. Claude Code 兼容工具

`runtime/tools.py` 里实现了本地兼容 shim：

- `Task`
- `EnterPlanMode`
- `ExitPlanMode`
- `TodoWrite`

### 3. toolset 元工具

通过 `import toolset` 使用，核心包括：

- `toolset.browser`
- `toolset.terminal`
- `toolset.proxy`
- `toolset.note`

对应实现位置：

- `meta-tooling/toolset/src/toolset/browser/`
- `meta-tooling/toolset/src/toolset/terminal/`
- `meta-tooling/toolset/src/toolset/proxy/`
- `meta-tooling/toolset/src/toolset/note/`

### 4. 本地增强工具

由 `CompatibleToolRegistry` 暴露给 Agent：

- `run_httpx_scan`
- `run_katana_crawl`
- `run_ffuf_scan`
- `run_nuclei_scan`
- `run_sqlmap_scan`
- `extract_secrets_and_flags`
- `build_target_profile`
- `SearchCVEKnowledge`
- `LoadCVEKnowledge`
- `ListSkills`
- `SearchSkills`
- `LoadSkill`

### 5. 可选 MSF 工具

当本地环境健康时，会额外注册：

- `mcp__msf__get_status`
- `mcp__msf__execute_command`
- `mcp__msf__search_modules`
- `mcp__msf__workspace`
- `mcp__msf__db_query`
- `mcp__msf__session`
- `mcp__msf__module`

## 架构说明

### 运行时主模块

| 模块 / 文件 | 作用 |
| --- | --- |
| `main.py` | 命令行入口，负责加载 `.env`、解析参数、切换单题模式或自动闯关模式，并把控制台输出写入项目根目录 `log/*.log` |
| `runtime/runtime.py` | 本地运行时核心，负责准备 workspace、启动浏览器服务、创建 PythonExecutor、拼装工具和 Agent、写最终结果 |
| `runtime/agent.py` | `LocalCTFSolverAgent` 实现，基于 LangGraph 驱动单 Agent 循环，模型调用使用 `ChatOpenAI` |
| `runtime/tools.py` | `CompatibleToolRegistry`，统一暴露主工具、兼容工具、toolset 包装器、技能、CVE、MSF、比赛平台工具 |
| `runtime/hackathon.py` | `HackathonOrchestrator`，负责官方比赛模式的题目编排、隔离运行、并发控制、hint 策略和总结输出 |
| `runtime/challenge_platform.py` | 官方比赛平台 `streamable-http` MCP 客户端，封装 challenge 列表、启动、停止、交 flag、查看 hint |
| `runtime/evidence_store.py` | 自动闯关模式下的跨 attempt 证据存储，聚合 hosts / services / creds / pivots / flags / loot 等信息 |
| `runtime/skills.py` | 本地技能索引、搜索、加载与推荐逻辑，自动维护 `skills/index.yaml` |
| `runtime/cve_knowledge.py` | 本地结构化 CVE / POC 知识库的搜索与加载逻辑 |
| `runtime/prompt_loader.py` | 加载提示词文件 `claude_code/.claude/agents/security-ctf-agent.md` |
| `runtime/pentest_helpers.py` | 文本信息抽取和轻量画像工具函数 |
| `runtime/msf_client.py` | 运行时侧对本地 MSF 服务的封装代理 |

### 元工具与本地服务

| 路径 | 作用 |
| --- | --- |
| `meta-tooling/service/python_executor_mcp.py` | 状态化 Jupyter `PythonExecutor`，是 `mcp__sandbox__execute_code` 的核心执行器 |
| `meta-tooling/service/browser.py` | Playwright Chromium 本地服务，默认 headless，通过 CDP 暴露给 `toolset.browser` |
| `meta-tooling/service/msfconsole_mcp.py` | 本地 MSF 适配层 |
| `meta-tooling/service/vendors/msfconsole_mcp/` | vendored 的上游 MSF MCP 实现 |
| `meta-tooling/toolset/src/toolset/browser/` | 浏览器上下文获取与页面交互 |
| `meta-tooling/toolset/src/toolset/terminal/` | 基于 `tmux` 的终端会话管理 |
| `meta-tooling/toolset/src/toolset/proxy/` | 对接 Caido GraphQL 的代理流量读取 |
| `meta-tooling/toolset/src/toolset/note/` | 持久化笔记 |

### Prompt、技能和知识库

| 路径 | 作用 |
| --- | --- |
| `claude_code/.claude/agents/security-ctf-agent.md` | 主 system prompt 真源 |
| `skills/` | 本地技能库，每个技能一个目录，文件名固定为 `SKILL.md` |
| `skills/index.yaml` | 技能索引文件，运行时自动重建 |
| `skills/WORKFLOW.md` | 技能使用约定和推荐加载策略 |
| `knowledge/cves/` | 本地 CVE / POC 结构化知识库 |

## 目录结构与文件功能

当前仓库的核心目录可以按下面理解：

```text
D0Pagent/
├── main.py
├── README.md
├── .env.example
├── claude_code/
│   └── .claude/agents/security-ctf-agent.md
├── runtime/
│   ├── runtime.py
│   ├── agent.py
│   ├── tools.py
│   ├── hackathon.py
│   ├── challenge_platform.py
│   ├── evidence_store.py
│   ├── skills.py
│   ├── cve_knowledge.py
│   ├── msf_client.py
│   ├── prompt_loader.py
│   └── pentest_helpers.py
├── meta-tooling/
│   ├── service/
│   │   ├── browser.py
│   │   ├── python_executor_mcp.py
│   │   ├── msfconsole_mcp.py
│   │   └── vendors/msfconsole_mcp/
│   └── toolset/
│       └── src/toolset/
│           ├── browser/
│           ├── terminal/
│           ├── proxy/
│           └── note/
├── skills/
│   ├── WORKFLOW.md
│   ├── index.yaml
│   ├── core-methodology/
│   ├── src-web-recon/
│   ├── web-vuln-hunting/
│   ├── cve-cloud-aiinfra/
│   ├── network-oa-pivot/
│   ├── persistence-maintenance/
│   ├── ad-internal-ops/
│   ├── msf-operations/
│   ├── prompt-injection-defense/
│   ├── fragmented-key-exchange/
│   ├── content-influence-competition/
│   └── realtime-osint-treasure/
├── knowledge/
│   └── cves/
│       ├── index.json
│       ├── thinkphp/
│       ├── spring/
│       ├── struts/
│       ├── fastjson/
│       ├── weblogic/
│       ├── oa/
│       ├── jboss/
│       └── nextjs/
├── README/
│   └── 文档图片与徽章资源
├── images/
│   └── 其他图片资源
└── log/
    └── 运行时控制台输出日志
```

## Skills 体系

本地 `skills/` 不是把所有经验一次性塞进 system prompt，而是做按需加载：

1. 先 `ListSkills`
2. 再按场景 `SearchSkills`
3. 只对当前阶段需要的技能 `LoadSkill`
4. 加载后继续用 `mcp__sandbox__execute_code` + `import toolset` 执行

当前内置技能包括：

- `core-methodology`
- `src-web-recon`
- `web-vuln-hunting`
- `cve-cloud-aiinfra`
- `network-oa-pivot`
- `persistence-maintenance`
- `ad-internal-ops`
- `msf-operations`
- `prompt-injection-defense`
- `fragmented-key-exchange`
- `content-influence-competition`
- `realtime-osint-treasure`

`runtime/skills.py` 会根据题目元数据、赛区和关键词动态推荐优先加载的技能。

## 本地 CVE 知识库

`knowledge/cves/` 是一套本地 JSON 结构化知识库，当前仓库已经包含多个产品族：

- `thinkphp`
- `spring`
- `struts`
- `fastjson`
- `weblogic`
- `oa`
- `jboss`
- `nextjs`

使用方式：

- 先用 `SearchCVEKnowledge`
- 确认结果后再 `LoadCVEKnowledge`

设计目标是“按需加载高价值本地知识”，而不是把整库一次性塞进上下文。

## Workspace 与日志产物

### 单题模式产物

默认 `workspace/` 下会生成：

- `logs/agent.jsonl`：Agent 每一步消息、工具调用、错误日志
- `logs/browser-service.log`：本地浏览器服务日志
- `logs/skills.jsonl`：技能索引、搜索、加载日志
- `logs/msfconsole-mcp.log`：MSF sidecar 日志，只有启用且启动后才有
- `python_sessions/*.ipynb`：PythonExecutor 会话 Notebook
- `executions/*.json`：每次 `execute_code` 的代码和输出记录
- `notes/*.md`：`toolset.note` 写入的笔记
- `todo.md`：兼容 `TodoWrite` 的待办文件
- `agent_state.json`：本地运行状态
- `subtasks.jsonl`：兼容 `Task` 工具记录
- `final_answer.txt`：最终答案
- `skills_loaded.jsonl`：技能加载记录

此外，项目根目录还会写入：

- `log/YYYYMMDD_HHMMSS_xxx.log`：主进程控制台 stdout / stderr 汇总日志

### 自动闯关模式产物

`workspace/hackathon/` 下会额外生成：

- `orchestrator.jsonl`：编排器日志
- `summary.json`：全局汇总
- `0001_<code>/`、`0002_<code>/` ...：每道题的独立目录
- `evidence_store.json`：题级证据记忆

题目的 attempt 子目录按模式不同会有两类：

- 单 flag 题：`attempt1_no_hint/`、`attempt2_with_hint/`
- 多 flag / campaign 题：`attempt1_campaign/`、`attempt2_campaign/` 等

每个 attempt 目录内部仍然是完整独立的 `workspace` 结构，互不污染。

## 自动闯关模式行为说明

基于当前 `runtime/hackathon.py` 的实现，自动闯关模式具备这些特点：

- 每道题在独立运行时中执行，互相隔离
- challenge 并发默认最多 `3`
- `single_flag` 题目默认第一轮不用 hint，第二轮可带 hint 重试
- `multi_flag_campaign` 题目会按 campaign 方式连续推进，允许多轮 attempt
- `EvidenceStore` 会跨 attempt 汇总 hosts / services / credentials / pivots / flags / loot / notes
- 平台状态才是最终判定标准，不是本地文本匹配

## 常见注意事项

- `--ctf` 在非自动闯关模式下是必填参数。
- 浏览器默认 headless。只有在你明确需要可视窗口时，才考虑设置 `NO_VISION=0`。
- `toolset.proxy` 依赖 Caido；不配置 `CAIDO_PORT` / `CAIDO_TOKEN` 时不会拖垮主流程，只是代理能力不可用。
- MSF 集成默认是“能用就启用，不能用就降级”，不会阻塞主链路。
- 如果你需要把提示词、技能或 CVE 知识库扩展到自己的题型，优先复用 `skills/` 和 `knowledge/cves/` 的现有组织方式。

## 参考资料

- 文章：https://mp.weixin.qq.com/s/jT4poWZ4Gfu3faXvul07HA
- 原项目地址：https://github.com/chainreactors/tinyctfer
