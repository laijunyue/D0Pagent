# ThinkPHP Local CVE Knowledge

这个目录用于存放 ThinkPHP 相关的本地结构化 CVE / N-day / POC JSON 条目。

维护约定：

- 每条知识使用单独 JSON 文件，字段遵循 `runtime/cve_knowledge.py` 的统一归一化结构。
- `index.json` 只保存搜索摘要和相对路径，方便 agent 先检索、再按需加载详情。
- `verification` 优先放低破坏、可重复、易匹配的 harmless probe。
- `exploitation` 只保留少量高价值链路，不把整篇外部文章全文塞进 JSON。
- `post_exploitation` 和 `stability` 要强调环境探针、稳定化、凭据复用和低噪声推进。

适用范围：

- ThinkPHP 5.0.x / 5.1.x 常见 `invokeFunction`、`Request/input` 一类公开链路。
- 更高版本或修复后的目标，不应机械复刻 payload；应先基于指纹、版本和响应差异做验证。
