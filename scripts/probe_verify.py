#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
probe_verify.py —— 白名单探测 / 验证请求执行器（把两类纪律最重的目标请求机械化）

为什么要有它：safe_fetch 把下载的完整性、判定、侧车全包了，但白名单探测（phase1 §1.2）
与验证请求（phase2）——证据规范要求最严的两类——长期靠每次现场手搓 curl 循环。
实测事故形态：状态码从响应文本里 grep（把 Date 头里的年份当状态码）、间隔靠 sleep 手写、
三件套编号靠自觉复刻、24h 跨会话窗口护栏靠人脑合计。本脚本把这四类失误整类消除。

两种模式（间隔/预算/重试/落盘规则全部对齐 SKILL.md「速率与预算总表」）：

  --mode probe   阶段 1 白名单探测
      · 间隔 ≥2 秒（默认 2）；不重试；额度 ≤30 发/站点——按 24h 滚动窗口跨会话合计
        口径执行（含 catch-all 基线）：护栏机械化，按落盘目录既有 .headers 首行时间戳
        合计，本会话可用额度 = 预算 − 窗口既有，触线即停（时间戳不可读按窗口内计，
        宁拦勿漏；台账 = --out 目录，跨会话核对须复用同一落盘目录）
      · 自动先打 catch-all 基线 GET /<随机串>-check-xyz（phase1 §1.4 第 1 步机械化），
        200+HTML+>500B+无敏感关键词 ⇒ 判 catch-all 并在摘要中作废所有「200=命中」判定
      · 落盘 <out>/<路径名>.body + .headers（命名 = 探测路径去前导斜杠、/ 转 _，
        点开头路径折 _dot_ 前缀，撞名加 __2 序号——phase1 §1.2 规则）；
        得响应的路径当场写入口清单（来源=PROBE）
  --mode verify  阶段 2 验证请求
      · 间隔 ≥3 秒（默认 3，条目间与同条重试间同距）；网络层失败 ≤2 次重试；
        业务响应（任意 HTTP 状态码，含 4xx/5xx）绝不重试（429 例外见判定表，脚本不代重试）
      · 会话 ≤50 发 + 跨会话滚动 24h 窗口合计 ≤100 发——护栏机械化：按落盘目录既有
        .headers 首行时间戳合计，触线即停（时间戳不可读按窗口内计，宁拦勿漏）
      · 落盘三件套 NNN.body / NNN.headers / NNN.sha256（编号从落盘目录既有最大编号续起，
        跨会话不重置——delivery §3）；.headers 首行 = 请求时间戳，次行 = Status

两种模式共同的硬约束：
  · 只发 GET / HEAD / OPTIONS（--method 三选一）；禁跟随重定向（env #8——3xx 原样带回，
    Location 打进摘要，由判定表 3xx 行落位）
  · 状态码来自 HTTP 客户端返回值，绝不做响应文本解析（实测事故：手搓脚本把 Date 里的
    年份当状态码）
  · 范围硬边界机械化（硬性规则 6）：路径清单里的完整 URL 若 host 不属于 --base 的
    host 或其子域，跳过并出声——兄弟域/第三方域不请求
  · 脚本不改入口清单、不落判定结论；摘要中的「判定提示」只是 phase2 判定表的行定位
    提示，结论由执行者按判定表落

用法：
  python scripts/probe_verify.py --mode probe  --base https://<host> --paths probes.txt --out <站点>/probe
  python scripts/probe_verify.py --mode verify --base https://<host> --paths batch1.txt --out <站点>/verify --method GET
  python scripts/probe_verify.py --out <站点>/verify --register-manual curl_dump.txt [--timestamp ISO] [--note 说明]
  probes.txt 每行一个路径（/actuator/env）或完整 URL；# 注释与空行跳过；
  --register-manual = 手工证据折编（零请求）：完整 HTTP 响应原文自动剥头解析状态码/响应头/Date，
  纯 body 文件状态记 0；时间戳回退链 --timestamp > Date 头 > 文件 mtime > now，写入三件套。

退出码：0 = 全部发完；1 = 护栏触发未跑完（预算/窗口/范围跳过）或致命错误——链式调用据此判断
"""
import argparse
import csv
import datetime
import email.utils
import hashlib
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

MODE_GAP_MIN = {"probe": 2.0, "verify": 3.0}          # 「速率与预算总表」：探测 ≥2s / 验证 ≥3s
MODE_BUDGET = {"probe": 30, "verify": 50}             # 探测 ≤30/站点；验证单会话 ≤50
VERIFY_WINDOW_HOURS = 24
VERIFY_WINDOW_MAX = 100                               # 跨会话滚动窗口合计上限

# catch-all 判据的敏感关键词（phase1 §1.4：命中任一 ⇒ 不是 catch-all 的通用页）
CATCHALL_SENSITIVE = ("登录", "密码", "token", "error", "异常", "login", "password")

VERIFY_NUM_RE = re.compile(r"^(\d{3,})\.body$")


# ---------------------------------------------------------------- 基础件

def build_opener(proxy):
    """与 safe_fetch 同构：走代理才关证书校验（自签 CA）；直连显式弃用环境代理 + 默认校验。
    另加 NoRedirect——探测/验证禁跟随重定向（env #8），3xx 原样返回给判定表。"""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    handlers = [NoRedirect()]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def request_once(opener, url, method, ua, timeout, extra_headers):
    """单发。返回 (status, body_bytes, headers_dict)；网络层异常返回 (None, None, err_str)。
    3xx 因 NoRedirect 以 HTTPError 形态返回——同 safe_fetch.fetch_once 的处理，存在性不丢。"""
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        **dict(extra_headers),
    })
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return e.code, body, dict(e.headers or {})
    except Exception as e:
        return None, None, "%s: %s" % (type(e).__name__, e)


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def host_of(url):
    m = re.match(r"^https?://([^/:?#]+)", url, re.I)
    return (m.group(1) or "").lower() if m else ""


def host_in_scope(url_host, base_host):
    """硬性规则 6：请求 host 必须是输入站点 host 本身或其子域（*.base）。
    兄弟域（同注册域平行主机）不算——由调用侧拿原始输入判定，脚本只看 --base。"""
    if not url_host or not base_host:
        return False
    return url_host == base_host or url_host.endswith("." + base_host)


def probe_filename(path, used):
    """phase1 §1.2 命名：去前导斜杠、/ 转 _，非 [A-Za-z0-9._-] 字符折成 _；撞名加 __2 序号。
    点开头路径折 _dot_ 前缀（/.env → _dot_env）——否则落盘成隐藏文件，ls 默认不显示，
    证据文件会被数漏（真目标实测：/.well-known/security.txt → .well-known_security.txt.*）。"""
    name = path.split("?")[0].lstrip("/").replace("/", "_")
    name = "".join(c if (c.isalnum() or c in "-._") else "_" for c in name) or "root"
    if name.startswith("."):
        name = "_dot_" + name[1:]
    if name in used:
        k = 2
        while "%s__%d" % (name, k) in used:
            k += 1
        name = "%s__%d" % (name, k)
    used.add(name)
    return name


def write_headers_file(path, ts, status, headers):
    """delivery §3：请求时间戳记于 .headers 首行（跨会话窗口合计按时间戳），
    次行 Status（与 safe_fetch .hdr 侧车同字段名，方便工具链统一解析）。"""
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write("Timestamp: %s\n" % ts)
        f.write("Status: %d\n" % status)
        for k, v in headers.items():
            f.write("%s: %s\n" % (k, v))


def next_verify_number(out_dir):
    """编号续起：落盘目录既有 NNN.body 的最大编号 +1（跨会话不重置——delivery §3）。"""
    mx = 0
    try:
        for f in os.listdir(out_dir):
            m = VERIFY_NUM_RE.match(f)
            if m:
                mx = max(mx, int(m.group(1)))
    except OSError:
        pass
    return mx + 1


def window_count(out_dir, now):
    """跨会话窗口合计：既有 .headers 首行 Timestamp 在 24h 内的条数。
    时间戳不可读按窗口内计（宁拦勿漏）并出声——静默放过等于护栏停摆。"""
    n = unreadable = 0
    try:
        names = [f[:-len(".headers")] for f in os.listdir(out_dir) if f.endswith(".headers")]
    except OSError:
        return 0, 0
    for stem in names:
        ts = None
        try:
            with open(os.path.join(out_dir, stem + ".headers"), encoding="utf-8-sig",
                      errors="replace") as f:
                first = f.readline().strip()
            if first.lower().startswith("timestamp:"):
                ts = datetime.datetime.fromisoformat(first.split(":", 1)[1].strip())
        except Exception:
            ts = None
        if ts is None:
            unreadable += 1
            n += 1
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)   # 无时区按 UTC，宁可算进窗口
        if now - ts <= datetime.timedelta(hours=VERIFY_WINDOW_HOURS):
            n += 1
    return n, unreadable


def probe_effective_budget(out_dir, budget, now):
    """探测跨会话窗口护栏：预算 30 发/站点按「24h 滚动窗口跨会话合计」口径执行——
    台账 = probe 落盘目录既有 .headers 首行时间戳（与 verify 同一 window_count），
    本会话可用额度 = 预算 − 窗口既有。时间戳不可读按窗口内计（宁拦勿漏）。
    台账在 --out 目录：换目录 = 换台账，跨会话核对以复用同一 --out 为前提。"""
    used, unreadable = window_count(out_dir, now)
    return budget - used, used, unreadable


def is_catchall(status, headers, body):
    """phase1 §1.4 第 1 步：200 + HTML + >500B + 无敏感关键词 ⇒ catch-all。"""
    if status != 200 or body is None or len(body) <= 500:
        return False
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "html" not in ctype:
        return False
    text = body.decode("utf-8", errors="replace").lower()
    return not any(k in text for k in CATCHALL_SENSITIVE)


def verdict_hint(status, headers, size, catchall):
    """phase2 判定表的行定位提示（只是提示——结论由执行者按判定表落，脚本不落结论）。"""
    if status is None:
        return "网络层失败 ≠ 判定结论：状态改未确认、验证结果留空"
    loc = headers.get("Location") or headers.get("location")
    allow = headers.get("Allow") or headers.get("allow")
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if 300 <= status < 400:
        return "3xx：有 Location 按「不在此前缀」落位（备注必填 Location 目标）；无 Location 留空保持未验证" \
            if loc else "3xx 无 Location：验证结果留空、状态保持未验证"
    if status in (401, 403):
        return "401/403：需凭据（正常态）；裸 403 先排除全站一律拦截"
    if status == 405:
        return "405：方法不符——在 GET/HEAD/OPTIONS ∩ Allow 交集内换方法再请求" \
            if allow else "405 无 Allow 头：按词表例外处理"
    if status == 429:
        return "429：限速非结论——等窗口后重试（唯一可重试的 4xx，计入预算）"
    if status == 500:
        return "500：已抵达后端触发异常——状态记已验证、验证结果留空、备注必填"
    if 400 <= status < 500:
        return "%d：按判定表兜底落位（400/422=参数不符已到业务层）" % status
    if status == 200 and catchall:
        return "catch-all 站：200 无判定意义，只能靠内容特征判"
    if status == 200:
        return "200：必须打开响应体看业务码（200 包络业务错误常见）"
    return "%d：有响应即证明存在，三值不适用按词表例外" % status


# ---------------------------------------------------------------- 主流程

def parse_http_dump(data):
    """完整 HTTP 响应原文 → (status, headers_dict, body_bytes, Date头时间戳|None)。
    首行 HTTP/x.y NNN 形态才算 dump（头体以空行分界）；否则返回 None（按纯 body 处理）。"""
    head, sep, rest = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, rest = data.partition(b"\n\n")
        if not sep:
            return None
    first = head.split(b"\n", 1)[0].strip()
    m = re.match(rb"HTTP/[\d.]+\s+(\d{3})", first)
    if not m:
        return None
    status = int(m.group(1))
    headers, date_ts = {}, None
    for line in head.split(b"\n")[1:]:
        k, _, v = line.partition(b":")
        if not _:
            continue
        try:
            ks, vs = k.strip().decode("latin-1"), v.strip().decode("latin-1")
        except Exception:
            continue
        headers.setdefault(ks, vs)
        if ks.lower() == "date":
            try:
                date_ts = email.utils.parsedate_to_datetime(vs)
            except Exception:
                date_ts = None
    return status, headers, rest, date_ts


def register_manual_flow(args):
    """手工证据折编（零请求）：把 curl/代理导出的证据折进 verify 编号体系。
    两种输入：完整 HTTP 响应原文（自动剥头、解析状态码与响应头、取 Date 头时间戳）；
    纯 body 文件（状态记 0，无头）。时间戳回退链 --timestamp > 响应 Date 头 > 文件
    mtime > 当前时刻，来源注明在 .headers 尾部 X-Register-Note——手工文件不折编则
    不满足首行格式，每轮都触发窗口护栏「时间戳不可读按窗口内计」的保守计数（实测）。"""
    src = args.register_manual
    if not os.path.isfile(src):
        print("✗ 证据文件不存在：%s" % src)
        return 1
    data = open(src, "rb").read()
    dump = parse_http_dump(data)
    if dump:
        status, headers, body, ts = dump
        src_note = "完整响应原文剥头"
    else:
        status, headers, body, ts = 0, {}, data, None
        src_note = "纯 body（无 HTTP 头，状态记 0）"
    if args.timestamp:
        ts_use, ts_src = datetime.datetime.fromisoformat(args.timestamp), "--timestamp"
    elif ts is not None:
        ts_use, ts_src = ts, "响应 Date 头"
    else:
        try:
            ts_use = datetime.datetime.fromtimestamp(os.path.getmtime(src)).astimezone()
            ts_src = "文件 mtime"
        except Exception:
            ts_use, ts_src = datetime.datetime.now().astimezone(), "当前时刻"
    if ts_use.tzinfo is None:
        ts_use = ts_use.replace(tzinfo=datetime.timezone.utc)
    os.makedirs(args.out, exist_ok=True)
    name = "%03d" % next_verify_number(args.out)
    with open(os.path.join(args.out, name + ".body"), "wb") as f:
        f.write(body)
    with open(os.path.join(args.out, name + ".headers"), "w", encoding="utf-8", errors="replace") as f:
        f.write("Timestamp: %s\n" % ts_use.astimezone().isoformat(timespec="seconds"))
        f.write("Status: %d\n" % status)
        for k, v in headers.items():
            f.write("%s: %s\n" % (k, v))
        f.write("X-Register-Note: 手工证据折编：%s；时间戳来源=%s%s\n"
                % (src_note, ts_src, ("；" + args.note) if args.note else ""))
    digest = hashlib.sha256(body).hexdigest()
    with open(os.path.join(args.out, name + ".sha256"), "w", encoding="utf-8") as f:
        f.write("%s  %s.body\n" % (digest, name))
    print("已折编 %s → %s/%s.{body,headers,sha256}（状态 %s，时间戳来源 %s）——原文件未动"
          % (src, args.out, name, status, ts_src))
    n, bad = window_count(args.out, datetime.datetime.now().astimezone())
    print("折编后 24h 窗口合计：%d 发（时间戳不可读 %d）——手工证据自此计入护栏" % (n, bad))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="白名单探测 / 验证请求执行器（间隔、落盘、编号、窗口护栏全部机械化；"
                    "只发 GET/HEAD/OPTIONS，禁跟随重定向）")
    ap.add_argument("--mode", default=None, choices=["probe", "verify"],
                    help="probe=阶段1白名单探测；verify=阶段2验证请求（--register-manual 流程下可省）")
    ap.add_argument("--base", default="", help="站点基址，如 https://www.example.com")
    ap.add_argument("--paths", default=None, help="路径清单文件：每行 /路径 或完整 URL")
    ap.add_argument("--out", required=True,
                    help="落盘目录：probe→<站点>/probe；verify→<站点>/verify（三件套编号续起）")
    ap.add_argument("--register-manual", dest="register_manual", default="",
                    metavar="FILE", help="手工证据折编（零请求）：完整 HTTP 响应原文或纯 body 文件"
                                         "→ 三件套编号落盘（时间戳回退链 --timestamp > Date 头 > mtime > now）")
    ap.add_argument("--timestamp", default="", metavar="ISO8601",
                    help="折编时间戳显式指定（优先级最高，授权扩展请求的场景用它登记实际请求时刻）")
    ap.add_argument("--note", default="", help="折编备注（写入 .headers 尾部 X-Register-Note）")
    ap.add_argument("--method", default="GET", choices=["GET", "HEAD", "OPTIONS"],
                    help="请求方法（405 方法轮换=换方法再跑一次本脚本，各计 1 发）")
    ap.add_argument("--gap", type=float, default=None,
                    help="条目间隔秒（缺省按模式：probe=2 / verify=3；低于下限会被抬到下限）")
    ap.add_argument("--budget", type=int, default=None,
                    help="本发可用数上限（缺省按模式：probe=30 / verify=50；两模式均受 24h 滚动窗口跨会话合计约束：probe ≤30、verify ≤100，按 --out 目录既有 .headers 时间戳核对")
    ap.add_argument("--proxy", default="", help="代理，如 http://127.0.0.1:8080")
    ap.add_argument("--ua", default="chrome", choices=["chrome", "raw"],
                    help="raw 暴露非浏览器 UA，部分 WAF 全拦，慎用")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--header", action="append", default=[],
                    metavar="NAME:VALUE", help="附加请求头（可重复，如 Origin: https://x —— CORS 实测用）")
    ap.add_argument("--site", default="-", help="站点归属（进摘要与 CSV，口径同其它脚本 --site）")
    ap.add_argument("--csv", help="逐发结果 CSV（UTF-8 BOM）")
    ap.add_argument("--out-report", dest="out_report", help="摘要报告文件（UTF-8）")
    ap.add_argument("--log", help="控制台输出改写入该文件（UTF-8），不再打印")
    args = ap.parse_args()

    # 手工证据折编流程：零请求，mode/base/paths 全部不需要
    if args.register_manual:
        return register_manual_flow(args)
    for _req in ("mode", "base", "paths"):
        if not getattr(args, _req):
            ap.error("--%s 为必填（或改用 --register-manual 手工证据折编流程）" % _req)

    gap = args.gap if args.gap is not None else MODE_GAP_MIN[args.mode]
    if gap < MODE_GAP_MIN[args.mode]:
        print("⚠ --gap %s 低于「速率与预算总表」下限（%s 模式 ≥%s 秒），已抬到下限"
              % (args.gap, args.mode, MODE_GAP_MIN[args.mode]))
        gap = MODE_GAP_MIN[args.mode]
    budget = args.budget if args.budget is not None else MODE_BUDGET[args.mode]
    extra_headers = []
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers.append((k.strip(), v.strip()))

    base_host = host_of(args.base)
    if not base_host:
        print("✗ --base 不是合法 http(s) 地址：%s" % args.base)
        return 1

    # 路径清单：# 注释 / 空行跳过；范围硬边界（硬性规则 6）在清单装载时就拦
    entries, skipped_scope = [], []
    try:
        for line in open(args.paths, encoding="utf-8-sig"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("http://", "https://")):
                if not host_in_scope(host_of(line), base_host):
                    skipped_scope.append(line)
                    continue
                entries.append(line)
            else:
                entries.append(args.base.rstrip("/") + "/" + line.lstrip("/"))
    except OSError as e:
        print("✗ 路径清单读不了：%s" % e)
        return 1

    os.makedirs(args.out, exist_ok=True)
    ua = UA_CHROME if args.ua == "chrome" else "python-urllib/probe_verify"
    opener = build_opener(args.proxy or None)

    L = []
    stopped_early = False

    # ---- verify 模式：编号续起 + 跨会话窗口护栏（先核后发） ----
    num = 0
    window_used = window_unreadable = 0
    if args.mode == "verify":
        num = next_verify_number(args.out)
        now = datetime.datetime.now().astimezone()
        window_used, window_unreadable = window_count(args.out, now)
        if window_unreadable:
            print("⚠ %d 个既有 .headers 首行时间戳不可读，已按窗口内计入（宁拦勿漏）" % window_unreadable)
        if window_used >= VERIFY_WINDOW_MAX:
            print("✗ 跨会话窗口护栏触线：落盘目录既有 24h 内 %d 发 ≥ 上限 %d——本会话不发，收工留待下窗口"
                  % (window_used, VERIFY_WINDOW_MAX))
            return 1

    # ---- probe 模式：跨会话窗口护栏（预算 30 按 24h 滚动窗口合计口径，先核后发） ----
    if args.mode == "probe":
        now = datetime.datetime.now().astimezone()
        budget, window_used, window_unreadable = probe_effective_budget(args.out, budget, now)
        if window_unreadable:
            print("⚠ %d 个既有 .headers 首行时间戳不可读，已按窗口内计入（宁拦勿漏）" % window_unreadable)
        if budget <= 0:
            print("✗ 探测跨会话窗口护栏触线：probe/ 目录 24h 内既有 %d 发 ≥ 预算 %d——本会话不发，收工留待下窗口"
                  % (window_used, MODE_BUDGET["probe"] if args.budget is None else args.budget))
            return 1

    # ---- probe 模式：catch-all 基线先行（占 1 发额度） ----
    sent = 0
    results = []
    catchall = False
    if args.mode == "probe" and (entries or budget >= 1):
        import random
        base_path = "/%08d-check-xyz" % random.randint(10 ** 7, 10 ** 8 - 1)
        url = args.base.rstrip("/") + base_path
        print("[基线] %s" % url)
        st, body, hdrs = request_once(opener, url, "GET", ua, args.timeout, extra_headers)
        sent += 1
        if st is None:
            ts = now_iso()
            write_headers_file(os.path.join(args.out, "_catchall_baseline.headers"), ts, 0, {})
            results.append({"目标": base_path, "编号/文件": "_catchall_baseline",
                            "方法": "GET", "URL": url, "状态": "—", "字节": 0,
                            "提示": "基线网络层失败——先查自己链路（env 排错手册）"})
            L.append("基线请求网络层失败：%s（环境假象先查自己链路，见 env 排错手册）" % hdrs)
        else:
            ts = now_iso()
            name = "_catchall_baseline"
            with open(os.path.join(args.out, name + ".body"), "wb") as f:
                f.write(body or b"")
            write_headers_file(os.path.join(args.out, name + ".headers"), ts, st, hdrs)
            catchall = is_catchall(st, hdrs, body or b"")
            results.append({"目标": base_path, "编号/文件": name, "方法": "GET", "URL": url,
                            "状态": st, "字节": len(body or b""), "提示": "catch-all 基线"})
            if catchall:
                print("⚠⚠ 本站是 catch-all（任意路径 200+HTML）——本站所有「200=命中」判定作废，"
                      "只能靠内容特征判（phase1 §1.4）")
            else:
                print("基线非 catch-all（状态 %s）——200 判定可用" % st)
        time.sleep(gap)

    def budget_left():
        if args.mode == "verify":
            return (sent < budget) and (window_used + sent < VERIFY_WINDOW_MAX)
        return sent < budget

    # ---- 逐条发 ----
    for i, url in enumerate(entries):
        if not budget_left():
            L.append("护栏触线停发（%s 模式上限 %s%s）——剩余 %d 条未发，记入未闭环清单：\n  %s"
                     % (args.mode, budget,
                        "" if args.mode == "probe" else " 或 24h 窗口 ≤%d" % VERIFY_WINDOW_MAX,
                        len(entries) - i, "\n  ".join(entries[i:])))
            stopped_early = True
            break
        path_disp = url[len(args.base.rstrip("/")):] or "/"
        print("[%s] %s" % (args.mode, url))
        tries = 1
        while True:
            st, body, hdrs = request_once(opener, url, args.method, ua, args.timeout, extra_headers)
            if st is not None:
                break                      # 任意 HTTP 响应（含 4xx/5xx）= 业务响应，绝不重试
            # 网络层失败：verify ≤2 次重试（与首发同距 ≥gap）；probe 不重试
            max_tries = 3 if args.mode == "verify" else 1
            if tries >= max_tries:
                break
            print("    网络层失败（%s），%.0f 秒后重试 %d/%d" % (hdrs, gap, tries, max_tries - 1))
            time.sleep(gap)
            tries += 1
        sent += 1
        ts = now_iso()
        if st is None:
            hint = verdict_hint(None, {}, 0, False)
            name = "未落盘（网络层失败）"
            L.append("网络层失败×%d：%s —— %s" % (tries, url, hint))
            results.append({"目标": path_disp, "编号/文件": name, "方法": args.method, "URL": url,
                            "状态": "—", "字节": 0, "提示": hint})
            time.sleep(gap)
            continue
        if args.mode == "verify":
            name = "%03d" % num
            num += 1
            with open(os.path.join(args.out, name + ".body"), "wb") as f:
                f.write(body or b"")
            write_headers_file(os.path.join(args.out, name + ".headers"), ts, st, hdrs)
            digest = hashlib.sha256(body or b"").hexdigest()
            with open(os.path.join(args.out, name + ".sha256"), "w", encoding="utf-8") as f:
                f.write("%s  %s.body\n" % (digest, name))
        else:
            used_names = {f[:-len(".body")] for f in os.listdir(args.out) if f.endswith(".body")}
            name = probe_filename(path_disp, used_names)
            with open(os.path.join(args.out, name + ".body"), "wb") as f:
                f.write(body or b"")
            write_headers_file(os.path.join(args.out, name + ".headers"), ts, st, hdrs)
        ctype = (hdrs.get("Content-Type") or hdrs.get("content-type") or "")
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        allow = hdrs.get("Allow") or hdrs.get("allow") or ""
        hint = verdict_hint(st, hdrs, len(body or b""), catchall)
        results.append({"目标": path_disp, "编号/文件": name, "方法": args.method, "URL": url,
                        "状态": st, "字节": len(body or b""), "提示": hint})
        print("    → %s %sB %s%s%s  %s" % (st, len(body or b""), ctype,
                                           ("  Location=" + loc) if loc else "",
                                           ("  Allow=" + allow) if allow else "", name))
        if i < len(entries) - 1:
            time.sleep(gap)

    # ---- 摘要 ----
    L.insert(0, "=== probe_verify 摘要（%s / %s / %s）===" % (args.mode, args.method, args.site))
    L.append("")
    L.append("请求 %d 发｜清单 %d 条｜间隔 %.0f 秒（%s 模式下限 %.0f）"
             % (sent, len(entries), gap, args.mode, MODE_GAP_MIN[args.mode]))
    if skipped_scope:
        L.append("⚠ 范围硬边界跳过 %d 条（host 不属于 --base 站点或其子域，硬性规则 6——只记录不请求）：%s"
                 % (len(skipped_scope), ", ".join(skipped_scope[:5])
                    + ("…" if len(skipped_scope) > 5 else "")))
        stopped_early = True
    if args.mode == "probe":
        L.append("catch-all 判定：%s（基线响应见 _catchall_baseline.*）" % ("是——200 判定作废" if catchall else "否"))
        L.append("额度：本发 %d / 上限 %d（含基线与存活确认 GET，速率与预算总表）" % (sent, budget))
        L.append("探测得响应的路径当场写入口清单（来源=PROBE、不与真实接口混排）——脚本不改清单，由执行者落表。")
    else:
        L.append("会话额度：本发 %d / 上限 %d；24h 窗口合计：既有 %d（时间戳不可读 %d 已按窗口内计）+ 本发 %d，上限 %d"
                 % (sent, budget, window_used, window_unreadable, sent, VERIFY_WINDOW_MAX))
        L.append("三件套落盘于 %s（编号自既有最大续起，跨会话不重置）；.headers 首行时间戳供窗口核对。" % args.out)
    L.append("「提示」列只是 phase2 判定表的行定位——结论必须打开响应体按判定表落，脚本不代落。")
    L.append("")
    L.append("%-6s %-40s %-8s %-8s %-9s %s" % ("状态", "目标", "方法", "字节", "编号/文件", "提示"))
    for r in results:
        L.append("%-6s %-40s %-8s %-8s %-9s %s" % (str(r["状态"]), r["目标"][:40], r["方法"],
                                                   r["字节"], r["编号/文件"], r["提示"]))

    out_text = "\n".join(L)
    if args.out_report:
        open(args.out_report, "w", encoding="utf-8").write(out_text + "\n")
    if args.log:
        open(args.log, "w", encoding="utf-8").write(out_text + "\n")
    else:
        print("\n" + out_text)
    if args.csv:
        with open(args.csv, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["模式", "站点", "编号/文件", "方法", "URL", "目标",
                                              "状态", "字节", "提示"])
            w.writeheader()
            for r in results:
                w.writerow({"模式": args.mode, "站点": args.site, **r})
    return 1 if stopped_early else 0


if __name__ == "__main__":
    sys.exit(main())
