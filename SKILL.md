---
name: api-extract
description: 授权范围内 Web API 接口提取、敏感信息挖掘与接口验证。两阶段：①从前端资源（JS/SPA/Webpack/apk/ipa）提取接口、硬编码密钥、注释线索、组件指纹（离线分析或仅下载静态资源）；②对提取的接口做低频只读验证——存在性确认与鉴权判定（GET/HEAD/OPTIONS，三态判定表，响应体递归挖掘）。用户给出 JS 目录/URL/apk 要求提取接口/挖密钥/分析前端时触发阶段①；用户说验证接口/测哪些不要 token/批量确认接口时触发阶段②。输入可以是 asset-recon 技能的 subdomains.csv、直接 URL、本地文件目录或移动端安装包。
---

# API 提取与接口验证

两阶段流水线：**提取**（离线分析，零业务请求）→ **验证**（低频只读，GET/HEAD/OPTIONS）。

## 输入（三种，任选其一）

| 输入 | 行为 |
|---|---|
| 本地文件目录 / subdomains.csv | 直接进入提取（零网络请求） |
| 在线 URL | `safe_fetch.py` 下载静态资源后提取 |
| apk / ipa | 解包 + strings grep（零网络请求） |

## 硬性规则

1. **提取阶段零业务请求**——只分析文件，不发请求到目标接口。
2. **验证阶段只发 GET/HEAD/OPTIONS**——不发 POST/PUT/DELETE，不上传，不注入。
3. **只加不减**：全部记录，分级/置信度/三态是标注不是过滤。
4. **下载完整性**：`实收字节 == Content-Length`，chunked → CHUNKED。

## 阶段 A：提取（零业务请求）

1. **获取文件**：本地直接用 / URL 用 `safe_fetch.py` / apk 解包。
2. **指纹**：响应集与 GitHub 指纹规则库（Wappalyzer / FingerprintHub / EHole）离线比对。
3. **双路线提取**：
   - 静态：`extract_apis.py` 粗筛 → `extract_endpoints.py --hidden --site <站点>` 精提 → 通道直方图 + 对账
   - 运行时（有浏览器）：`hook_inject.js` 钩 fetch/XHR → SPA 路由表 diff
4. **敏感信息三层**：
   - 全文 grep：硬编码 AK/SK、JWT、内网 IP、签名函数
   - 注释扫描（`scan_comments.py`）：凭据/内网/旧接口（独立通道，置信分级）
   - 源码与文档侦察：GitHub org / 协作文档（零目标流量）
5. **移动端**：apk 解包三阶梯 / ipa 解压。

**产出**：入口清单.csv（全部状态=未验证）+ leaks.csv + clues.csv + fingerprints.csv

## 阶段 B：验证（低频只读）

目的：确认接口存在性与鉴权状况。越权/写入/注入不做。

1. **选候选**（≤10 条）：路径含 public/anonymous/noLogin 的、启动期调用的、空参数列表类。
2. **逐条请求**，每条保存响应头与正文（间隔 ≥3 秒、单会话 ≤50 发）。
3. **三态判定**（看业务码不只看 HTTP 状态码，完整表见 references/phase3-api-verification.md）：

| 响应 | 结论 |
|---|---|
| 200 + 业务成功码 + 数据 | 未鉴权可读 |
| 401/403 + 鉴权提示 | 需凭据（基线） |
| 404 + 框架错误体 | 不在此前缀 ≠ 不存在 |

4. **响应体挖掘**（`mine_responses.py`，零请求）：从验证响应中发现新接口 → 全部标**待批准** → 用户点名后方可继续验证（递归，深度 ≤3 层）。

**产出**：入口清单的状态与验证结果列更新。

## 自带防线

| 防线 | 机制 |
|---|---|
| 通道直方图 | 各通道命中数，零也是信号 |
| 粗筛/精提对账 | `extract_apis.py --reconcile-fine`——盲区候选点名 |
| 判定联动 | `_fetch_report.json` 非 OK 不进入提取 |
| .hdr 侧车 | 报告损坏时降级复核 |
| 响应体待批准 | 挖掘产物不自动进入验证，须用户点名 |

## 脚本

| 脚本 | 用途 |
|---|---|
| `scripts/safe_fetch.py` | 下载器（完整性校验+退避重试） |
| `scripts/extract_apis.py` | 粗筛 + 对账 |
| `scripts/extract_endpoints.py` | 精提（`--hidden` `--site`） |
| `scripts/scan_comments.py` | 注释线索（置信分级） |
| `scripts/mine_responses.py` | 响应体挖掘（零请求，待批准） |
| `scripts/hook_inject.js` | 浏览器 fetch/XHR 捕获 |

依赖：Python 3.8+（仅标准库）。
