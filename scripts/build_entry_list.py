#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_entry_list.py —— 入口清单官方汇编器（delivery §1 合并规则的代码化）

两轮实弹评测中，合并规则一直靠执行者现写胶水脚本（第二轮还出过 _fetch_report.json
相对路径双重替换事故，当场发现重跑）——本脚本把规则固化，消灭 env 文档批评过的
「靠自觉」模式。规则权威仍是 delivery §1/§1.5/§0，本脚本是其机械执行：

  · 形态→来源映射（delivery §1 写死规则）：html→页面引用；hidden:*→JS提取；
    url/tpl/concat/json/css/fetch/call/ws/sse/wss-url/graphql-op/absolute→JS提取；
    apk/ipa 形态→移动端提取
  · URL 列 = 基址+路径（绝对形态行用精提「基路径」列作基址；动态段保留 {param}）；
    query 串拆参数名并入「参数」列（与精提「参数名」列合并）
  · 备注列保留具体形态字样（delivery §1）；精提「可疑」列内容并入备注
  · 去重键 = (URL, 方法)；同键合并：状态取信息更全者（已验证>待批准>未验证>未确认），
    首行站点保留、备注记「亦见于 <站点>」；两条已验证且验证结果冲突 → 状态已验证、
    验证结果取首个、备注标「跨站结果不一致，疑构建漂移」（delivery §1）
  · PROBE 行（probe_verify --csv）：来源=PROBE、不与真实接口混排；状态=未验证、
    验证结果留空（判定表落位是执行者动作，脚本不代落），探测响应证据进备注
  · 页面路由升级（--fetch-report，可选）：形态=页面引用 且其路径在 safe_fetch
    _fetch_report.json 中判定 OK → 状态=已验证、验证结果留空、备注按词表例外记
    「下载 200 OK 即存在性证据」（delivery §0）。路径匹配用报告行的 url 字段做
    精确归一化对比，不按落盘文件名猜（文件名含父目录前缀变换，猜必错）

用法：
  python scripts/build_entry_list.py --fine 站A/fine.csv 站B/fine.csv \
      [--probe 站A/probe-results.csv ...] [--fetch-report 站A/dl/_fetch_report.json ...] \
      --out 入口清单.csv [--log 汇编.log]

  退出码：0 = 成功；1 = 参数/IO 错误
多站点：每站精提 CSV 分次传入（各站 extract_endpoints --site 已打标）；PROBE 与
fetch-report 同理按站传。产物列契约见 delivery §1（URL/方法/参数/来源/站点/状态/验证结果/备注）。
"""
import argparse
import csv
import json
import os
import re
import sys
from urllib.parse import urlparse, parse_qsl, unquote

STATUS_PRECEDENCE = {"已验证": 3, "待批准": 2, "未验证": 1, "未确认": 0}
HTML_SOURCE_FORMS_PREFIX = ("hidden:",)
JS_SOURCE_FORMS = {"url", "tpl", "concat", "json", "css", "fetch", "call", "ws",
                   "sse", "wss-url", "graphql-op", "absolute"}


def source_of(form):
    """形态→来源列映射（delivery §1 写死规则，不靠语义对号）。"""
    if form == "html":
        return "页面引用"
    if form.startswith(HTML_SOURCE_FORMS_PREFIX):
        return "JS提取"
    if form in JS_SOURCE_FORMS:
        return "JS提取"
    if form.startswith(("apk", "ipa")):
        return "移动端提取"
    return "JS提取"          # 未知形态按 JS提取 兜底并如实标注，不静默丢行


def qnames(q):
    """query 串 → 参数名（占位符 {} 剥除后保留核；与精提 参数名 列合并）。"""
    if not q:
        return ""
    names = []
    for k, _ in parse_qsl(q.lstrip("?"), keep_blank_values=True):
        k = unquote(k)
        k = re.sub(r"\{.*?\}", "", k).strip()
        if k:
            names.append(k)
    return ",".join(dict.fromkeys(names))


def base_of(row, site):
    """行基址：绝对形态行用精提「基路径」（域外域名）；否则 https://站点。"""
    bp = (row.get("基路径") or "").strip()
    if bp.startswith(("http://", "https://")):
        return bp.rstrip("/")
    return "https://" + site


def norm_path(p):
    try:
        return urlparse(p).path or p
    except Exception:
        return p


def load_fine(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_ok_paths(fetch_report_path):
    """safe_fetch _fetch_report.json → 判定 OK 的请求路径集合（小写归一化）。"""
    with open(fetch_report_path, encoding="utf-8-sig") as f:
        rep = json.load(f)
    items = rep if isinstance(rep, list) else rep.get("items", rep.get("files", []))
    ok = set()
    for it in items:
        if isinstance(it, dict) and it.get("verdict") == "OK" and it.get("url"):
            ok.add(norm_path(it["url"]).rstrip("/").lower())
    return ok


def probe_rows(path):
    """probe_verify --csv → 入口清单行（来源=PROBE；判定表落位留给执行者）。"""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            url = r.get("URL") or r.get("url") or ""
            if not url:
                continue
            note = "PROBE 响应：%s %sB（证据 %s）" % (r.get("状态") or "?",
                                                     r.get("字节") or "?", r.get("编号/文件") or "-")
            hint = (r.get("提示") or "").strip()
            if hint:
                note += "｜" + hint
            out.append({"URL": url, "方法": (r.get("方法") or "GET").strip(),
                        "参数": "", "来源": "PROBE", "站点": r.get("站点") or "-",
                        "状态": "未验证", "验证结果": "", "备注": note})
    return out


def build(fine_paths, probe_paths=(), fetch_reports=()):
    """合并规则主体。返回 (rows, stats)。"""
    ok_paths = set()
    for fp in fetch_reports:
        ok_paths |= load_ok_paths(fp)

    merged = {}          # (URL, 方法) → row
    stats = {"精提行": 0, "PROBE行": 0, "去重合并": 0, "页面路由升级": 0, "跨站冲突": 0}

    def put(row):
        key = (row["URL"], row["方法"])
        if key not in merged:
            merged[key] = row
            return
        old = merged[key]
        stats["去重合并"] += 1
        if STATUS_PRECEDENCE[row["状态"]] > STATUS_PRECEDENCE[old["状态"]]:
            old.update({"状态": row["状态"], "验证结果": row["验证结果"] or old["验证结果"],
                        "来源": row["来源"] if old["来源"] == "-" else old["来源"]})
        if old["状态"] == "已验证" and row["验证结果"] and row["验证结果"] != old["验证结果"]:
            old["备注"] += "｜跨站结果不一致，疑构建漂移（另一值：%s）" % row["验证结果"]
            stats["跨站冲突"] += 1
        elif row["站点"] and row["站点"] != old["站点"]:
            old["备注"] += "｜亦见于 %s" % row["站点"]

    for fp in fine_paths:
        for r in load_fine(fp):
            stats["精提行"] += 1
            path = (r.get("接口路径") or "").strip()
            if not path:
                continue
            form = r.get("形态") or ""
            site = (r.get("站点") or "-").strip() or "-"
            url = path if path.startswith(("http://", "https://")) else base_of(r, site) + path
            note = "形态=" + form
            if r.get("可疑"):
                note += "｜" + r["可疑"]
            if r.get("来源文件"):
                note += "｜来源文件:" + r["来源文件"]
            params = ",".join(x for x in (qnames(r.get("query")), r.get("参数名") or "") if x)
            row = {"URL": url, "方法": (r.get("请求方式") or "?").strip() or "?",
                   "参数": params, "来源": source_of(form), "站点": site,
                   "状态": (r.get("状态") or "未验证").strip() or "未验证",
                   "验证结果": (r.get("验证结果") or "").strip(),
                   "备注": note}
            if (row["URL"], row["方法"]) not in merged \
                    and row["状态"] == "未验证" and row["来源"] == "页面引用" \
                    and norm_path(url).rstrip("/").lower() in ok_paths:
                row["状态"] = "已验证"
                row["备注"] += "｜页面路由/静态资源下载 200 OK 即存在性证据（词表例外，delivery §0；验证结果留空）"
                stats["页面路由升级"] += 1
            put(row)

    for pp in probe_paths:
        for row in probe_rows(pp):
            stats["PROBE行"] += 1
            put(row)

    return list(merged.values()), stats


COLS = ["URL", "方法", "参数", "来源", "站点", "状态", "验证结果", "备注"]


def main():
    ap = argparse.ArgumentParser(description="入口清单官方汇编器（delivery §1 规则代码化）")
    ap.add_argument("--fine", nargs="+", required=True, help="各站精提 CSV（extract_endpoints --csv 产物）")
    ap.add_argument("--probe", nargs="*", default=[], help="probe_verify --csv 产物（可多份）")
    ap.add_argument("--fetch-report", dest="fetch_report", nargs="*", default=[],
                    help="safe_fetch _fetch_report.json（可多份；用于页面路由存在性升级）")
    ap.add_argument("--out", required=True, help="入口清单.csv 输出路径（UTF-8 BOM）")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8），不再打印")
    args = ap.parse_args()

    for p in list(args.fine) + list(args.probe) + list(args.fetch_report):
        if not os.path.isfile(p):
            print("✗ 输入不存在：%s" % p)
            sys.exit(1)

    rows, stats = build(args.fine, args.probe, args.fetch_report)
    rows.sort(key=lambda r: (r["来源"] == "PROBE", r["URL"]))   # PROBE 不与真实接口混排（排尾）
    with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)

    lines = ["=== 入口清单汇编（build_entry_list） ===",
             "精提行 %d ｜ PROBE 行 %d ｜ 去重合并 %d ｜ 页面路由升级 %d ｜ 跨站冲突 %d"
             % (stats["精提行"], stats["PROBE行"], stats["去重合并"],
                stats["页面路由升级"], stats["跨站冲突"]),
             "合计 %d 行 → %s" % (len(rows), args.out),
             "判定表落位/验证结果由执行者按 phase3 判定表填——脚本不代落结论。"]
    text = "\n".join(lines)
    if args.log:
        with open(args.log, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    sys.exit(0)


if __name__ == "__main__":
    main()
