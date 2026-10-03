#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""终清单对账：精提 CSV → 最终入口清单 的最后一环。

为什么要有它：粗筛/精提对账（extract_apis.py --reconcile-fine）只管提取器之间；
「各站精提 CSV → 人工汇编最终入口清单」这一步此前无网——实测发生过丢行事故
（清单少行、报告反查索引仍在引用该行）。断言满分 ≠ 交付无缺陷。

机械规则（正向断言、可拦截）：
  精提 CSV 的每条路径必须在入口清单在场——缺失即交付缺陷，退出码 1。
  段级归一化后比对：{占位符}→{}、纯数字段→{}、8+ 位 hex 段→{}（两侧同规），
  大小写不敏感；入口 URL 先剥 scheme://host 与 query/fragment 再取路径。
  反向（清单有、精提无）只提示不判缺陷——PROBE/运行时捕获/响应体提取/
  历史归档/移动端提取本是精提之外的合法来源，逐行带来源列出供人工扫一眼。

用法：
  python scripts/reconcile_list.py --fine <精提CSV>... --entry 入口清单.csv \
      [--out report.txt] [--log log.txt]
（--out 报告文件仍打印；--log 控制台输出改写文件不打印——与其他脚本语义一致）
"""
import argparse
import csv
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HEX_SEG = re.compile(r"^[0-9a-f]{8,}$")


def _norm_path(p):
    """段级归一化：{xx}→{}、纯数字段→{}、hex 段→{}、小写化；剥 query/fragment。"""
    p = str(p).split("?", 1)[0].split("#", 1)[0]
    segs = []
    for s in p.strip("/").split("/"):
        if not s:
            continue
        if s.startswith("{"):
            segs.append("{}")
        elif s.isdigit() or HEX_SEG.match(s):
            segs.append("{}")
        else:
            segs.append(s.lower())
    return "/" + "/".join(segs)


def url_to_path(u):
    """入口清单 URL → 路径部分：剥 scheme://host 与 query/fragment（wss/http 绝对地址同规）。"""
    u = str(u).strip().split("?", 1)[0].split("#", 1)[0]
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+(/.*)?$", u)
    if m:
        return m.group(1) or "/"
    return u if u.startswith("/") else "/" + u


def load_fine(paths):
    """精提 CSV（可多个，多站点）→ 归一化路径集合。要求列名含「接口路径」。
    同样过 url_to_path——wss-url 通道行的「接口路径」本身是 wss:// 绝对地址，
    不剥 scheme 会折成 /wss:/… 与清单侧不对称（v2.36 实测假阳性：CLI 误报 wss 行缺失）。"""
    out = set()
    for fp in paths:
        with open(fp, encoding="utf-8-sig", newline="") as f:
            for r in csv.DictReader(f):
                p = (r.get("接口路径") or "").strip()
                if p:
                    out.add(_norm_path(url_to_path(p)))
    return out


def load_entry(fp):
    """入口清单 → [(来源, 归一化路径)]。要求列名含 URL（容错认接口路径）。"""
    rows = []
    with open(fp, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            u = (r.get("URL") or r.get("接口路径") or "").strip()
            if u:
                rows.append(((r.get("来源") or "?").strip(), _norm_path(url_to_path(u))))
    return rows


def reconcile(fine_paths, entry_rows):
    """→ (缺失路径列表, 精提之外的多余 [(来源, 路径)])。缺失 = 交付缺陷。
    两侧入参内部归一化（幂等）——load_* 已归一化过再进也安全，直接传原始路径/URL 同样成立。"""
    rows = [((src or "?"), _norm_path(url_to_path(p))) for src, p in entry_rows]
    entry_set = {p for _, p in rows}
    fine_set = {_norm_path(url_to_path(p)) for p in fine_paths}
    missing = sorted(p for p in fine_set if p not in entry_set)
    extra = sorted({(src, p) for src, p in rows if p not in fine_set})
    return missing, extra


def main():
    ap = argparse.ArgumentParser(
        description="终清单对账：精提 CSV 的每条路径必须在最终入口清单在场（汇编丢行=交付缺陷）")
    ap.add_argument("--fine", nargs="+", required=True, help="精提 CSV（extract_endpoints --csv，可多个）")
    ap.add_argument("--entry", required=True, help="最终入口清单.csv")
    ap.add_argument("--out", help="报告文件（UTF-8 带 BOM；仍打印）")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8，不打印）")
    args = ap.parse_args()

    fine = load_fine(args.fine)
    entry = load_entry(args.entry)
    missing, extra = reconcile(fine, entry)

    L = ["=== 终清单对账 ===",
         "精提 CSV 路径 %d 条｜入口清单 %d 行｜缺失 %d 条" % (len(fine), len(entry), len(missing))]
    if missing:
        L.append("❌ 精提有、清单无（交付缺陷——人工汇编丢行；报告反查索引会引用到不存在的行）：")
        L += ["  - %s" % p for p in missing]
    else:
        L.append("OK 精提路径全部在清单在场")
    if extra:
        L.append("提示（清单有、精提无——PROBE/运行时捕获/响应体提取/历史归档/移动端为合法来源，人工扫一眼）：")
        L += ["  - %s  [%s]" % (p, s) for s, p in extra]
    text = "\n".join(L) + "\n"

    if args.out:
        with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
            f.write(text)
    if args.log:
        with open(args.log, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    else:
        print(text, end="")

    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
