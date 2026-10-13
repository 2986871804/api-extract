#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
mine_responses.py —— 从阶段 2 已落盘的响应体中挖掘新接口（递归发现通道）

什么是它：对 .body 文件执行六种模式提取（五种 JSON 形态 + 一种 HTML 链接形态），
发现代码里没写死、由服务端下发的动态接口与页面路由。
什么不是它：不发任何请求（纯本地 grep），不验证任何接口，不修改入口清单。

安全设计（三道闸）：
  ① 脚本本身零网络——只读 .body 文件，不存在"误跑危险接口"的网络行为
  ② 危险路径标记——输出中每个条目带「风险」列，匹配危险词的标「⚠高危」并单独汇总
  ③ 消费侧防线——高危条目的备注写明"验证前须人工确认"，agent 不应对高危条目
     自动发起验证（这是技能层纪律，脚本靠标记提醒）

用法：
  python scripts/mine_responses.py --dir <body文件目录> [--entry-list 入口清单.csv]
                                    [--site <站点>] [--csv out.csv] [--out report.txt] [--log log.txt]
  --entry-list 传入时与已有条目去重（占位符归一化），只输出新发现
退出码：0 = 正常；1 = 有致命错误
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_endpoints import API_PREFIX, TEXT_EXTS  # noqa: E402
from reconcile_list import url_to_path               # noqa: E402
# 入口清单 URL 列是完整绝对地址（基址+路径）——去重基线必须先剥 scheme://host 再归一化，
# 否则清单侧键折成 /https://host/… 与挖掘侧相对路径永不相等（v2.39 实测：30 条发现里
# 26 条是已有条目却全部漏网通过）。url_to_path 与终清单对账（reconcile_list）同源同口径——
# 「两侧归一化不对称」是同类事故第三案（v2.36 wss 假阳性、本案挖掘去重），不再自造第三份实现。

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------- 提取模式
# 五种 JSON 模式按特异性排序，同一路径命中多模式时取首个（计数仍全记）
PATTERNS = [
    ("error_echo", re.compile(
        r'"path"\s*:\s*"(/[^"]{2,200})"')),
    ("hateoas", re.compile(
        r'"(?:next|prev|self|related|first|last|href|link)"\s*:\s*"(/[^"]{2,200})"')),
    ("url_field", re.compile(
        r'"[a-z_]*(?:url|uri|link|href|endpoint|callback)"\s*:\s*"(/[^"]{2,200})"')),
    ("path_value", re.compile(
        r'"(/(?:' + API_PREFIX + r')/[^"]{2,200})"')),
    ("nested_uri", re.compile(
        r'"(/[a-z]+/\d+/[a-z]+(?:/[^"]{0,100})?)"')),
]

# HTML 链接形态（第六模式，独立函数不走 PATTERNS——过滤规则不同）：
# 多页站（WebForms/传统企业站）的验证/探测响应是整页 HTML，JSON 五模式对它产出恒 0
# （实测 1.15MB 搜索页里有大量链接，五模式零命中）。链接语义 = 页面路由线索，
# 回流待批准清单后由人决定要不要抓页面提取其 JS——不是直接当接口。
# 与 extract_endpoints html 通道同构：href/src/action/data-url、无引号形态也收；
# 资产扩展名剔除；页面型后缀（.aspx/.ashx/.jsp/.php/.html…）保留。
# 正则与提取器同坑同修（v2.40 #5，两轮迭代）：① 锚定标签内拦查询串 action=list；
# ② 懒惰量词 + (?<![\w.]) 拦 onclick="this.src=…" 的伪属性——贪婪版在此处比提取器
# 更惨：垃圾值 this.src+ 的伪后缀被本侧过滤静默拒收，真链接又被吞，整条零产出。
HTML_LINK_RE = re.compile(
    r'<[a-zA-Z][^<>]*?(?<![\w.])(?:href|src|action|data-url)\s*=\s*[\'"]?([^\'"\s>]{2,200})[\'"]?', re.I)
# 页面型后缀（路由/处理器面），区别于 JS/CSS/图片资产——资产由 ASSET_RE 剔除
PAGE_EXTS = ("aspx", "ashx", "asmx", "asp", "jsp", "php", "html", "htm", "do")

# ---------------------------------------------------------------- 危险词
# 这些词出现在路径中时标记「⚠高危」——不是因为脚本会触发它们（脚本零请求），
# 而是因为后续如果有人/agent 对它们发 GET，可能触发服务端副作用（如 export 生成大文件、
# logout 使会话失效、callback 触发下游动作）。只标记不丢弃（只加不减）。
# 按路径段精确匹配：/orders 不再误中 /order（旧版整串子串匹配，全部 /orders/* 都在稀释信号）；
# camel 组合段（exportFile / resetPassword）仍命中。
DANGER_SEGMENTS = frozenset(
    "logout signout export download delete remove destroy reset flush clear "
    "callback webhook notify admin upload import create update edit modify "
    "write send pay order submit password token secret key credential".split())


def danger_hit(norm):
    """危险词按路径段判定：整段命中，或小写前缀命中且原段续大写（camel 组合）。"""
    for seg in norm.strip("/").split("/"):
        s = seg.lower()
        for w in DANGER_SEGMENTS:
            if s == w or (s.startswith(w) and seg[len(w):len(w) + 1].isupper()):
                return True
    return False

ASSET_RE = re.compile(
    r'\.(js|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|json|xml|pdf)(\?|$)', re.I)


def normalize_path(p):
    """归一化：数字段→{id}，去 query，补前导斜杠"""
    p = p.split("?")[0].split("#")[0]
    if not p.startswith("/"):
        p = "/" + p
    segs = []
    for s in p.strip("/").split("/"):
        if re.fullmatch(r"\d+", s):
            segs.append("{id}")
        elif re.fullmatch(r"[0-9a-f-]{8,}", s):
            segs.append("{uuid}")
        else:
            segs.append(s)
    return "/" + "/".join(segs)


def is_valid_path(p):
    """过滤明显不是接口的路径"""
    if not p or len(p) < 4 or len(p) > 300:
        return False
    if ASSET_RE.search(p):
        return False
    if p.startswith(("//", "javascript:", "data:", "#")):
        return False
    if " " in p:
        return False
    if not re.match(r"^/[a-zA-Z0-9_{\-]+(/[a-zA-Z0-9_{}\-]+){0,8}$", p):
        return False
    return True


def is_valid_html_path(p):
    """HTML 链接形态的过滤：末段允许一个页面型后缀（.aspx/.ashx/…）——is_valid_path
    的字符集不含点，WebForms 处理器路径（label/ajax/x.aspx）会被整族拒掉。
    末段无点号时回落 is_valid_path 同一判据（纯段页面路由）。"""
    if not p or len(p) > 300 or " " in p:
        return False
    last = p.strip("/").rsplit("/", 1)[-1]
    if "." in last:
        stem, _, ext = last.rpartition(".")
        if ext.lower() not in PAGE_EXTS or not stem:
            return False                  # 资产或非法后缀（ASSET_RE 已挡常见资产，这里挡其余点号串）
        head = p[:p.rfind("/")]           # 末段之前的全部路径段（单段页面为空串）
        if head and not re.fullmatch(r"(/[a-zA-Z0-9_{}\-]+)+", head):
            return False
        return not ASSET_RE.search(p)
    return is_valid_path(p)


def _mine_html(text):
    """HTML 响应的链接提取：返回 [(norm, raw, "html_link", line)]。
    剔除：协议绝对/协议相对（挖掘产物只有路径列，绝对地址记录语义在提取侧不在挖掘侧）、
    片段/脚本伪协议、资产扩展名、模板占位符（{xxx} 是 WebForms 模板语法不是路径）。"""
    out = []
    for m in HTML_LINK_RE.finditer(text):
        raw = m.group(1).split("#")[0]
        if not raw or raw.startswith(("http", "//", "javascript:", "mailto:",
                                      "tel:", "data:", "{", "<", "?")):
            continue
        if "%" in raw[:2] or raw.startswith("./") or raw.startswith("../"):
            continue                      # 相对寻址在无基址语境下不可解析，不猜
        norm = normalize_path(raw)
        if not is_valid_html_path(norm):
            continue
        line = text.count("\n", 0, m.start()) + 1
        out.append((norm, raw, "html_link", line))
    return out


def mine_file(path):
    """对一个 .body 文件执行六模式提取（五 JSON + html 链接），返回 [(norm_path, raw_path, pattern, line_no)]"""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out = []
    for pat_name, pat in PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1)
            norm = normalize_path(raw)   # 先归一（去 query/数字段）再校验——旧序先校验，带 query 的 HATEOAS 分页链接被静默过滤
            if not is_valid_path(norm):
                continue
            line = text.count("\n", 0, m.start()) + 1
            out.append((norm, raw, pat_name, line))
    # HTML 链接形态：JSON 模式零命中且文本是 HTML（含链接属性）时的自然数据源。
    # 判据用「内容含链接属性」而非扩展名/内容嗅探——.body 文件没有扩展名语境，
    # 服务端下发的 HTML 片段（表格/列表局部）同样该收。三个属性都查（v2.40 #5
    # 复现时发现）：只认 href= 会漏纯 <img src=…> 片段——验证码处理器响应的典型形态。
    low_text = text.lower()
    if "href=" in low_text or "src=" in low_text or "action=" in low_text:
        out += _mine_html(text)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="响应体挖掘：从已落盘的 .body 文件中发现新接口（零请求，离线）")
    ap.add_argument("--dir", required=True, help="阶段 2 落盘的 .body 文件目录")
    ap.add_argument("--entry-list", help="已有入口清单 CSV——传入时与已有条目去重")
    ap.add_argument("--site", default="-", help="站点归属")
    ap.add_argument("--csv", help="新发现 CSV（UTF-8 BOM）")
    ap.add_argument("--out", help="报告文件（UTF-8）")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8）")
    args = ap.parse_args()

    # 已有条目（去重用）——URL 列先过 url_to_path 剥 scheme://host/query，再与挖掘侧同规归一化
    existing = set()
    if args.entry_list and os.path.isfile(args.entry_list):
        try:
            for r in csv.DictReader(open(args.entry_list, encoding="utf-8-sig")):
                u = (r.get("URL") or r.get("接口路径") or "").strip()
                if u:
                    existing.add(normalize_path(url_to_path(u)))
        except Exception:
            pass

    # 挖掘
    all_finds = {}          # norm_path → {raw, pattern, files, danger}
    body_files = 0
    for root, _, fs in os.walk(args.dir):
        for f in sorted(fs):
            if not f.endswith(".body"):
                continue
            body_files += 1
            fp = os.path.join(root, f)
            for norm, raw, pat, line in mine_file(fp):
                if norm in existing:
                    continue
                if norm not in all_finds:
                    all_finds[norm] = {
                        "raw": raw, "pattern": pat, "files": set(),
                        "danger": danger_hit(norm)
                    }
                all_finds[norm]["files"].add(f)

    # 分类
    danger_items = {k: v for k, v in all_finds.items() if v["danger"]}
    safe_items = {k: v for k, v in all_finds.items() if not v["danger"]}
    pat_counts = collections.Counter(v["pattern"] for v in all_finds.values())

    # 输出
    L = []
    L.append("=== 响应体挖掘 ===")
    L.append("扫描 %d 个 .body 文件｜新发现 %d 条（去重后）｜其中 ⚠高危 %d 条｜已有 %d 条不重复计入"
             % (body_files, len(all_finds), len(danger_items), len(existing)))
    L.append("模式命中：%s" % " · ".join("%s %d" % kv for kv in pat_counts.most_common()))
    L.append("")

    if danger_items:
        L.append("⚠⚠ 高危条目（路径含危险词，验证前须人工确认——GET 也可能触发副作用）：")
        for k, v in sorted(danger_items.items()):
            L.append("  ⚠ %s  (%s, 来自 %s)" % (k, v["pattern"], ",".join(sorted(v["files"])[:3])))
        L.append("")

    L.append("⚠ 全部条目状态=待批准：响应体挖掘产物不自动进入验证，须用户点名后方可验证。")
    L.append("")

    if safe_items:
        L.append("常规条目（无危险词，用户批准后可验证）：")
        for k, v in sorted(safe_items.items()):
            L.append("  %s  (%s, 来自 %s)" % (k, v["pattern"], ",".join(sorted(v["files"])[:3])))
    else:
        L.append("（无新发现——响应体中的路径全部已在入口清单中）")

    L.append("")
    L.append("⚠ 本脚本零网络请求，只发现不验证。全部产出状态=待批准——")
    L.append("  agent 须将此清单呈报用户，用户点名后方可进入阶段 2 验证。")
    L.append("  高危标记（export/delete/callback 等）是额外参考信息，不替用户做决定。")

    out_text = "\n".join(L)

    if args.csv:
        with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "接口路径", "原始值", "模式", "来源文件", "状态", "风险", "站点"])
            w.writeheader()
            for k, v in sorted(all_finds.items()):
                w.writerow({
                    "接口路径": k, "原始值": v["raw"], "模式": v["pattern"],
                    "来源文件": ",".join(sorted(v["files"])),
                    "状态": "待批准",       # 响应体挖掘产物一律待用户批准，不自动验证
                    "风险": "⚠高危" if v["danger"] else "", "站点": args.site})

    if args.out:
        open(args.out, "w", encoding="utf-8").write(out_text + "\n")
    if args.log:
        open(args.log, "w", encoding="utf-8").write(out_text + "\n")
    else:
        print(out_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
