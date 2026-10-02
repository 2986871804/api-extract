# api-extract

授权范围内 Web API 接口提取、敏感信息挖掘与只读接口验证的 agent 技能（ZCode / Claude Code 通用）。

- **SKILL.md** — 技能入口：触发条件、硬性规则、两段流水线（阶段 2 提取 / 阶段 3 验证）
- **references/** — 分阶段细节：`delivery.md`（产物契约与词表）、`phase2-fingerprint-js.md`（提取）、`phase3-api-verification.md`（验证）、`environment-and-pitfalls.md`（排错）
- **scripts/** — 离线工具，Python 3.8+ 仅标准库；`evals/run_regression.py` 为回归自检
- **安装**：把本目录复制到 `~/.agents/skills/`（或 `.claude/skills/`）即可
- **更新已安装副本后必须验证**：`diff -rq -x .git -x __pycache__ <本仓库> ~/.agents/skills/api-extract` 应零输出——既查缺失也查**多余文件**（曾因复制层级写错在安装目录留下根目录游离副本，成为分叉种子）；复制层级错误不会报错，只有 diff 能抓到
- **自检**：`python evals/run_regression.py`（离线、零网络；改动脚本后先跑）

仅用于已获书面授权的目标。验证只发 GET/HEAD/OPTIONS，不做越权/写入/注入测试。
