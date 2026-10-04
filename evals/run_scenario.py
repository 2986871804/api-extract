#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""场景回归（第二道网，离线零网络）：planted 站点端到端召回。

与 run_regression（单元层）互补——整目录多文件、全通道合流、跨文件去重后按
planted 清单点验召回与缺席：sourcemap sourcesContent、.vue 脚本区、语言包、
CSS url()、HTML href、压缩写法（concat 链）、二进制伪装 .js、绝对第三方域、
别名实例双漏（诚实边界）。这些组合层是单用例不碰的；断言数以运行输出为准。

用法：python evals/run_scenario.py   （退出码 0=全过，1=有失败）
"""
import collections
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import extract_endpoints as ee          # noqa: E402

PASS = FAIL = 0


def chk(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok    %s" % name)
    else:
        FAIL += 1
        print("  FAIL  %s" % name)


def w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    return path


tmp = tempfile.mkdtemp(prefix="apix-scen-")
site = os.path.join(tmp, "demo-site")

# ---------------------------------------------------------------- planted fixture
# 预期去重总数 25 = 23 个 planted（含 2 条 jQuery 裸 $ 字面量 + 1 条表达式首参——
# _siteAppPath 运行时变量基址打占位符、静态后缀保留，真目标实测形态；+ 2 条服务端
# 页面 .aspx 产出行——页面路由与内联 AJAX，v2.40 前整页被当非文本跳过）+ WS_HOST 常量
# 裸 wss:// 字面量（wss-url 通道对源码字面量照收）+ concat 双通道行（url: 键读到
# method:post、补充扫 concat 通道方法列 ?——方法不同，按交付去重键 (URL, 方法) 契约
# 是两行，delivery §1）。sourcemap 的 sourcesContent 用单引号内嵌源码——JSON 转义
# 不动单引号，url: 通道可直接吃。
w(os.path.join(site, "dl", "app.js"),
  'const WS_HOST="wss://h.io";\n'
  'const c1={url:"/api/v1/users/list",method:"get"};\n'
  'const c2={url:"".concat("/a/",t,"/b"),method:"post"};\n'
  'fetch("/api/plain/literal");\n'
  'axios.get("https://cdn.partner-ext.com/v9/partner/data");\n'
  'uploadDhFileUrl = "/dh/uploadDhFile";\n'
  'new WebSocket(WS_HOST+"/api/ws");\n'
  'new EventSource("/api/stream/sse");\n'
  'const live="wss://x.io/live";\n'
  'nav(`/api/v2/goods/${t.id}/comments`);\n'
  '$.get("label/ajax/getAreaParentPath.aspx");\n'
  '$.post("label/ajax/saveForm.aspx");\n'
  '$.get(_siteAppPath + "label/ajax/exprForm.aspx?formid=" + nid);\n'
  'client = axios.create(); client.get("/api/alias/miss");\n')
w(os.path.join(site, "dl", "packed.bin.js"),
  "PK\x03\x04" + "\x00" * 200 + 'fetch("/api/bin/leak");\n')
w(os.path.join(site, "page.vue"),
  '<template><!-- 旧接口 /api/legacy/removed -->\n'
  '<div>u</div></template>\n'
  '<script>\n'
  'const v1={url:"/vue/url/form"};\n'
  'fetch("/vue/fetch/form");\n'
  'action: "/vue/action/form",\n'
  'axios.get("/vue/call/form");\n'
  '</script>\n')
w(os.path.join(site, "assets", "app.js.map"),
  '{"version":3,"sources":["app.js"],'
  '"sourcesContent":["const a={url:\'/api/from/sourcemap/one\'}; const b={url:\'/api/from/sourcemap/two\'};"]}')
w(os.path.join(site, "lang", "zh-CN.json"),
  '{"menu":{"export":"api/i18n/export"}}')
w(os.path.join(site, "style.css"),
  'body{background:url(/gateway/live/push)}')
w(os.path.join(site, "index.html"),
  '<a href="/admin/user/list">u</a>')
# v2.40 真目标形态（ezEIP 站真目标实测）：补爬落盘的 .aspx 页面带 <%@ 指令头、
# 业务 AJAX 内联在页面 <script> 里——此前整页被当非文本跳过
w(os.path.join(site, "dl", "list.aspx"),
  '<%@ Page Language="C#" %>\n'
  '<!doctype html><html><body>\n'
  '<a href="/news/detail.aspx">n</a>\n'
  '<script>$.get("/Ajax/AjaxData.ashx?action=list");</script>\n'
  # evals #6 真目标形态（真目标 submitform_validator.js:164 实录）：裸 url 赋值 +
  # 函数调用基址——旧 HIDDEN_NAME 前缀段必选字符类打头，裸 url/Url 永远匹配不上
  '<script>var url = whir.site.getAppPath() + "label/ajax/formsubmit.aspx?formid=" '
  '+ formid + "&submitid=" + sid; $.post(url, data, cb);</script>\n'
  '</body></html>\n')

PLANTED = [
    "/api/v1/users/list", "/a/{t}/b", "/api/plain/literal", "/v9/partner/data",
    "/dh/uploadDhFile", "/api/ws", "/api/stream/sse", "wss://x.io/live",
    "/vue/url/form", "/vue/fetch/form", "/vue/action/form", "/vue/call/form",
    "/api/from/sourcemap/one", "/api/from/sourcemap/two",
    "/api/i18n/export", "/gateway/live/push", "/admin/user/list",
    "/api/v2/goods/{id}/comments",
    # jQuery 裸 $（2026-10 真目标驱动：国内 WebForms/建站站型的业务 AJAX 主流写法，
    # 与 axios 风格夹具互补——评测此前从未覆盖；第三条是表达式首参形态：
    # v2.38 只收字面量、真目标 $.get(_siteAppPath + "…") 恒 0 命中而回归全绿的钉子）
    "/label/ajax/getAreaParentPath.aspx", "/label/ajax/saveForm.aspx",
    "/{_siteAppPath}label/ajax/exprForm.aspx",
    # 服务端页面（v2.40：.aspx 此前被当非文本整页跳过，内联 AJAX 与页面路由全漏）
    "/news/detail.aspx", "/Ajax/AjaxData.ashx",
    # evals #6：裸 url 赋值 + 函数调用基址（hidden:url 通道；v2.40 前整段零产出）
    "/{expr}label/ajax/formsubmit.aspx",
]

# ---------------------------------------------------------------- 跑提取管线（多文件合流）
files = [
    os.path.join(site, "dl", "app.js"),
    os.path.join(site, "dl", "packed.bin.js"),
    os.path.join(site, "dl", "list.aspx"),
    os.path.join(site, "page.vue"),
    os.path.join(site, "assets", "app.js.map"),
    os.path.join(site, "lang", "zh-CN.json"),
    os.path.join(site, "style.css"),
    os.path.join(site, "index.html"),
]
consts = ee.build_consts(files)
stats = collections.Counter()
all_recs = []
for f in files:
    recs, _, _, err = ee.extract_file(f, hidden=True, stats=stats, consts=consts)
    assert err == "", err
    all_recs += recs

dedup = {}
for r in all_recs:                      # 与交付去重同键：（路径, 基路径, 方法）——形态不进键，跨通道同名并一行
    dedup.setdefault((r["接口路径"], r["基路径"], r["请求方式"]), r)
paths = {r["接口路径"] for r in dedup.values()}

print("== S 场景层（planted 站点端到端）==")
chk("S1 planted 召回 %d/%d" % (len([p for p in PLANTED if p in paths]), len(PLANTED)),
    all(p in paths for p in PLANTED))
chk("S2 去重总数恰为 %d（23 planted + WS_HOST 裸字面量 + concat 双通道行），无额外垃圾行" % (len(PLANTED) + 2),
    len(dedup) == len(PLANTED) + 2)
chk("S3 二进制边界：伪装 .js 被嗅探跳过，埋点接口缺席",
    "/api/bin/leak" not in paths and stats.get("二进制跳过") == 1)
chk("S4 别名实例双漏在场（与 phase2 §3 诚实边界一致）", "/api/alias/miss" not in paths)
chk("S5 无协议折叠垃圾行（/wss:/ /https:/ /http:/ 前缀零出现）",
    not any(p.startswith(("/wss:/", "/https:/", "/http:/")) for p in paths))
_abs = [r for r in dedup.values() if r["接口路径"] == "/v9/partner/data"]
chk("S6 绝对第三方域拆基址 + 「需另行授权」标注",
    _abs and _abs[0]["基路径"] == "https://cdn.partner-ext.com" and "另行授权" in _abs[0]["可疑"])
chk("S7 sourcemap sourcesContent 两条入清单",
    "/api/from/sourcemap/one" in paths and "/api/from/sourcemap/two" in paths)
chk("S8 .vue 脚本区四形态全收（url/fetch/hidden:action/call）",
    all(p in paths for p in ("/vue/url/form", "/vue/fetch/form", "/vue/action/form", "/vue/call/form")))
_expr = [r for r in dedup.values() if r["接口路径"] == "/{_siteAppPath}label/ajax/exprForm.aspx"]
chk("S9 jQuery 表达式首参：运行时变量基址占位符 + 静态后缀 + query 还原（v2.38 字面量版恒漏的真目标形态）",
    _expr and _expr[0]["含占位符"] == "是" and _expr[0]["query"] == "?formid={nid}"
    and "运行时变量" in _expr[0]["可疑"])
_aspx = [r for r in dedup.values() if r["接口路径"] == "/Ajax/AjaxData.ashx"]
chk("S10 服务端页面 .aspx：<%@ 指令头不挡内联 AJAX（call）与页面路由（html）双通道（v2.40 前整页跳过）",
    _aspx and _aspx[0]["形态"] == "call" and _aspx[0]["query"] == "?action=list"
    and any(r["接口路径"] == "/news/detail.aspx" and r["形态"] == "html" for r in dedup.values()))
_fs = [r for r in dedup.values() if r["接口路径"] == "/{expr}label/ajax/formsubmit.aspx"]
chk("S11 裸 url 赋值 + 函数调用基址（evals #6：真目标 submitform_validator.js:164 实录，旧版整段零产出）",
    _fs and _fs[0]["形态"] == "hidden:url" and _fs[0]["含占位符"] == "是"
    and "formid" in _fs[0]["query"] and "submitid" in _fs[0]["query"])

print()
print("===== %d 通过 / %d 失败 =====" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
