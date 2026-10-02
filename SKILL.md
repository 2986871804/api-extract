---
name: api-extract
description: 授权范围内从前端资源中提取 API 接口与敏感信息（零目标流量或仅下载静态资源）：JS/SPA/Webpack 打包产物逆向、apk/ipa 移动端静态解包、接口与隐藏端点提取、硬编码密钥/凭据/内网地址发现、注释线索挖掘、指纹识别。用户给出 JS 目录、URL、apk 文件要求提取接口/挖密钥/分析前端时使用。支持多种输入：本地文件目录、在线 URL（仅下载静态资源）、移动端安装包。自带盲区防线（通道直方图 + 粗筛/精提对账）与判定联动（非 OK 下载文件不进入提取）。
---

# API 提取与敏感信息挖掘

从前端资源中提取接口清单、敏感信息、组件指纹。核心原则：**只分析、不验证**——产出是嫌疑名单，不是定罪；接口验证属 web-recon 阶段 3。

## 输入（三种，任选其一）

| 输入 | 行为 |
|---|---|
| 本地文件目录 | 直接进入提取（零网络请求） |
| 在线 URL | `safe_fetch.py` 下载静态资源（仅 GET，等价浏览）后提取 |
| apk / ipa | 解包 + strings grep（零网络请求） |

## 硬性规则

1. **不向目标业务接口发请求**——本技能只做提取，不做验证。
2. **不删改目标数据**：仅 GET 静态资源。
3. **只加不减**：全部记录，分级/置信度是标注不是过滤。
4. **下载完整性**：`实收字节 == Content-Length`，chunked → CHUNKED（可提取，标注不可校验）。

## 步骤

1. **获取文件**：本地目录直接用 / URL 用 `scripts/safe_fetch.py` 下载 / apk 解包。
2. **指纹**：响应集与 GitHub 指纹规则库（Wappalyzer / FingerprintHub / EHole）离线比对 → 组件名+版本串。
3. **双路线提取**（必跑静态，可选运行时）：
   - 静态：`extract_apis.py` 粗筛 → `extract_endpoints.py --hidden --site <站点>` 精提 → 通道直方图 + 粗筛/精提对账
   - 运行时（有浏览器）：`hook_inject.js` 钩住 fetch/XHR → SPA 路由表 diff 找隐藏页
4. **敏感信息三层**：
   - §6 全文 grep：硬编码 AK/SK、JWT、内网 IP、签名函数、DB 连接串
   - §6.1 注释扫描（`scan_comments.py --dir <目录> --site <站点>`）：中文/英文凭据、内网裸地址、注释旧接口（独立通道，核验后才升级）
   - §7 源码与文档侦察：GitHub org 仓库、协作文档（零目标流量）
5. **移动端**（§8）：apk 解包三阶梯（unzip→apktool→strings）/ ipa 解压 → 产出并入入口清单。

## 自带防线

| 防线 | 机制 |
|---|---|
| 通道直方图 | 各通道命中数，零也是信号（前端形态变迁最先在这里显形） |
| 粗筛/精提对账 | `extract_apis.py --reconcile-fine <精提CSV>`——粗筛有/精提无 = 盲区候选 |
| 判定联动 | `_fetch_report.json` 非 OK 文件不进入提取（下载完整性→提取安全性的机械闭环） |
| .hdr 侧车重建 | 判定报告损坏时降级复核（Status+Content-Length 重建 verdict） |

## 产出

| 文件 | 内容 |
|---|---|
| `入口清单.csv` | URL、方法、参数、基址、来源、站点、状态=未验证 |
| `leaks.csv` | 级别、类别、内容（按长度打码）、上下文、来源文件、站点 |
| `clues.csv` | 注释线索：凭据/内网/旧接口（独立通道，置信分级） |
| `fingerprints.csv` | 组件名+版本串、判定来源、证据 |

## 脚本

| 脚本 | 用途 |
|---|---|
| `scripts/safe_fetch.py` | 下载器（完整性校验+退避重试，预算守卫内建） |
| `scripts/extract_apis.py` | 粗筛：路径分级 + 调用点分类 + 对账 |
| `scripts/extract_endpoints.py` | 精提：占位符保留，`--hidden` 隐藏形态，`--site` 打标 |
| `scripts/scan_comments.py` | 注释线索：凭据/内网/旧接口（license 滤除，⏎ 证据格式） |
| `scripts/mine_responses.py` | 响应体挖掘（零请求，高危标记，待批准门控） |
| `scripts/hook_inject.js` | 浏览器 fetch/XHR 请求+响应捕获 |

依赖：Python 3.8+（仅标准库）；`hook_inject.js` 无依赖。

自检：`python evals/run_regression.py`（同 web-recon 共用回归套件，详见 web-recon/evals/）。
