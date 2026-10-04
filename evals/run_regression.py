#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归自检（离线，零网络，零目标请求）。

分组覆盖面（断言数以运行输出为准，数字不复制进文档防漂移）：
  A 判定联动   _fetch_report 排除键、.hdr 侧车重建（Status+CL+chunked、旧侧车退化、报告缺失时侧车兜底）
  B 路径重建   concat/模板串占位符、无前导斜杠归一化、绝对URL拆基址、前缀常量回填、参数名
  C 通道覆盖   hidden/concat/json/css/html/fetch/框架调用点(call, 含 jQuery 裸 $ 与表达式首参、第二参参数名)/
              ws/sse/wss-url/graphql 各通道有产出；服务端页面（.aspx 指令前缀+内联 AJAX）与 css 噪声过滤、
              裸 url/Url 赋值（HIDDEN_NAME 可行前缀）
  D 注释扫描   .vue 双区切分（模板 // 不误切）、.aspx 双区（<%-- --%> + 内嵌 script）、凭据触发词、
              内网置信二道判据、license 抑制
  E 响应体挖掘 五 JSON 模式 + html_link 模式、数字段/uuid 归一化、危险词标记、去重基线两侧同口径
  F 粗筛分级   grade A/B/C 路径分级
  G 终清单对账 汇编丢行、占位符/数字段归一化匹配、精提之外只提示
  H probe_verify 离线件  probe 文件命名/撞名（含点开头 _dot_）、verify 编号续起、24h 窗口合计
                  （含不可读时间戳宁拦勿漏）与 probe 有效额度、catch-all 判据、范围硬边界、
                  判定表行定位提示、手工折编解析（parse_http_dump）
  I 入口清单汇编器（build_entry_list）
未覆盖：safe_fetch / probe_verify 的网络路径（重试/退避/CL 判定/落盘三件套需真连接）；
        改动脚本后先跑本脚本。

用法：python evals/run_regression.py   （退出码 0=全过，1=有失败）
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import extract_endpoints as ee          # noqa: E402
import extract_apis as ea               # noqa: E402
import scan_comments as sc              # noqa: E402
import mine_responses as mr             # noqa: E402
import reconcile_list as rl             # noqa: E402
import probe_verify as pv               # noqa: E402

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


tmp = tempfile.mkdtemp(prefix="apix-reg-")

# ---------------------------------------------------------------- A 判定联动
print("== A 判定联动 ==")
dl = os.path.join(tmp, "dl")
w(os.path.join(dl, ee.FETCH_REPORT), json.dumps([
    {"file": "a.js", "url": "https://h/a.js", "verdict": "OK"},
    {"file": "b.js", "url": "https://h/b.js", "verdict": "CHUNKED"},
    {"file": "c.js", "url": "https://h/c.js", "verdict": "TRUNCATED"},
    {"file": "d.js", "url": "https://h/d.js", "verdict": "HTTP_403"},
]))
excl, errs = ee.load_fetch_exclusions([os.path.join(dl, ee.FETCH_REPORT)])
chk("A1 报告解析零错误", errs == [])
chk("A2 OK/CHUNKED 不排除", (os.path.abspath(dl), "a.js") not in excl
    and (os.path.abspath(dl), "b.js") not in excl)
chk("A3 TRUNCATED/HTTP_4xx 排除", excl.get((os.path.abspath(dl), "c.js")) == "TRUNCATED"
    and excl.get((os.path.abspath(dl), "d.js")) == "HTTP_403")

w(os.path.join(dl, "x.js"), "abc")                                     # 3 字节
w(os.path.join(dl, "x.js.hdr"), "Status: 200\nContent-Length: 100\n")
chk("A4 侧车重建 TRUNCATED（CL 不符）", ee.hdr_verdict(os.path.join(dl, "x.js")) == "TRUNCATED")
w(os.path.join(dl, "y.js"), "hi")
w(os.path.join(dl, "y.js.hdr"), "Status: 403\n")
chk("A5 侧车重建 HTTP_403", ee.hdr_verdict(os.path.join(dl, "y.js")) == "HTTP_403")
w(os.path.join(dl, "z.js"), "data")
w(os.path.join(dl, "z.js.hdr"), "Status: 200\nTransfer-Encoding: chunked\n")
chk("A6 侧车重建 CHUNKED（可提取）", ee.hdr_verdict(os.path.join(dl, "z.js")) == "CHUNKED"
    and not ee.hdr_bad(os.path.join(dl, "z.js")))
w(os.path.join(dl, "old.js"), "ab")
w(os.path.join(dl, "old.js.hdr"), "Content-Length: 5\n")                # 旧侧车无 Status
chk("A7 旧侧车退化为截断校验", ee.hdr_verdict(os.path.join(dl, "old.js")) == "TRUNCATED")
chk("A8 无侧车不排除", ee.hdr_verdict(os.path.join(dl, "不存在.js")) is None)

# A9 报告缺失但侧车在场：侧车即权威，4xx 错误体不得混进提取（实测缝隙的钉子）
dl2 = os.path.join(tmp, "dl2")
w(os.path.join(dl2, "gone.js"), '{"code":404}')
w(os.path.join(dl2, "gone.js.hdr"), "Status: 404\nContent-Length: 11\n")
w(os.path.join(dl2, "fine.js"), 'fetch("/api/ok/one");\n')
kept, dl_exc, _errs = ee.apply_fetch_filter(
    [os.path.join(dl2, "gone.js"), os.path.join(dl2, "fine.js")], [])
chk("A9 报告缺失时侧车仍拦 4xx", kept == [os.path.join(dl2, "fine.js")]
    and dl_exc.get("HTTP_404(hdr回退)") == 1)

# ---------------------------------------------------------------- B/C 提取（同文件驱动）
print("== B 路径重建 ==")
js = os.path.join(tmp, "app.js")
w(js, (
    'const WS_HOST="wss://h.io";\n'
    'var liveUrl="wss://x.io/live";\n'
    'const c1={url:"".concat("/a/",t,"/b"),method:"post"};\n'
    'const c2={url:`web/user/${uid}/list`};\n'
    'const c3={url:"face/batchImport"};\n'
    'const c4={url:"https://api.other.com/v1/data"};\n'
    'const c5={url:"/api/with/params",params:{pageNum:1,pageSize:10}};\n'
    'fetch("/api/plain/literal");\n'
    'new WebSocket(WS_HOST+"/api/ws");\n'
    'new EventSource("/api/stream/sse");\n'
    'var operationName="ListUsers";\n'
    'uploadDhFileUrl = "/dh/uploadDhFile";\n'
    'fn("".concat("/api/v2/",id,"/orders"));\n'
    'axios.get("api/orders/list");\n'
    'request.post("/submit/order");\n'
    'this.$http.get("user/profile");\n'
    'axios.delete("goods/remove");\n'
    'this.http.get<Resp>("/angular/typed");\n'
    'axios.get("just plain text");\n'
    'fetch(`/api/tpl1`);\n'
    'axios.get(`/api/items/${id}`);\n'
    'myrequest.get("/api/wp");\n'
    'fetch("https://api.demo.local/api/v2/stats/overview");\n'
    'axios.get("https://cdn.other.net/v9/abs/call");\n'
    'var statUrl = "https://api.demo.local/api/v2/stats/hidden";\n'
    'var dupWsUrl = "wss://dup.io/ws";\n'
    'new WebSocket("wss://dup2.io/rt");\n'
    'new EventSource("https://cdn.other.net/v9/sse/stream");\n'
    'nav(`/api/v2/goods/${t.id}/comments`);\n'
    '$.get("label/ajax/getAreaParentPath.aspx");\n'
    '$.post("label/ajax/saveForm.aspx");\n'
    '$.getJSON("/api/menu/tree");\n'
    '$.ajax("label/getList.aspx");\n'
    '$.get("just plain text");\n'
    'my$.get("/api/jqprefix");\n'
    'const BASE2="/api";\n'
    '$.get(_siteAppPath + "label/ajax/only.aspx?formid=" + fid);\n'
    'axios.get(BASE2 + "/v9/expr/form");\n'
    'fetch(BASE2 + "/expr/fetch/path");\n'
    '$.ajax({url:"/jq/objform", method:"POST"});\n'
    '$.get(someVar);\n'
    'fetch(buildUrl(a, b));\n'
    # evals #6 真目标形态（真目标 submitform_validator.js:164 实录）：裸 url 赋值 +
    # 函数调用基址——旧 HIDDEN_NAME 前缀段必选字符类打头，裸 url/Url 永远匹配不上
    'var url = whir.site.getAppPath() + "label/ajax/formsubmit.aspx?formid=" + formid + "&columnid=" + columnid;\n'
    '$.post(url, data, cb);\n'
    'var Url = "/api/bare/upper/x";\n'
    'cfg = {url: "/onlyurlkey/x"};\n'
))
import collections                                                    # noqa: E402
consts = ee.build_consts([js])
chk("B1 常量表收录 wss 前缀", consts.get("WS_HOST") == "wss://h.io")
cstats = collections.Counter()
recs, url_total, hit, err = ee.extract_file(js, hidden=True,
                                            stats=cstats, consts=consts)
chk("B2 提取零错误", err == "")
idx = {(r["接口路径"], r["基路径"], r["请求方式"], r["形态"]): r for r in recs}
p1 = idx.get(("/a/{t}/b", ee.base_of("/a/{t}/b"), "POST", "url"))
chk("B3 concat 占位符保留（/a/{t}/b）", p1 is not None and p1["含占位符"] == "是")
chk("B4 无拼接伪路径 /a/b 不存在", ("/a/b", ee.base_of("/a/b"), "POST", "url") not in idx)
chk("B5 模板串占位符 + 无前导斜杠补齐",
    ("/web/user/{uid}/list", ee.base_of("/web/user/{uid}/list"), "?", "url") in idx)
chk("B6 相对路径 face/ 归一化", ("/face/batchImport", ee.base_of("/face/batchImport"), "?", "url") in idx)
absr = idx.get(("/v1/data", "https://api.other.com", "?", "absolute"))
chk("B7 绝对 URL 拆基址+路径", absr is not None and "另行授权" in absr["可疑"])
c5 = idx.get(("/api/with/params", ee.base_of("/api/with/params"), "?", "url"))
chk("B8 参数名提取", c5 is not None and c5["参数名"] == "pageNum,pageSize")
wsr = idx.get(("/api/ws", "wss://h.io", "WSS", "ws"))
chk("B9 ws 前缀常量回填", wsr is not None)

print("== C 通道覆盖 ==")
chk("C1 hidden 形态（= 赋值）", ("/dh/uploadDhFile", ee.base_of("/dh/uploadDhFile"), "?", "hidden:uploadDhFileUrl") in idx)
chk("C2 concat 链首参", ("/api/v2/{id}/orders", ee.base_of("/api/v2/{id}/orders"), "?", "concat") in idx)
chk("C3 裸 fetch 字面量", ("/api/plain/literal", ee.base_of("/api/plain/literal"), "?", "fetch") in idx)
chk("C4 SSE 通道", ("/api/stream/sse", "", "SSE", "sse") in idx)
chk("C5 wss 字面量", ("wss://x.io/live", "", "WSS", "wss-url") in idx)
chk("C6 graphql operationName", ("ListUsers", "", "?", "graphql-op") in idx)
chk("C10 axios 调用点（api/ 前缀）", ("/api/orders/list", ee.base_of("/api/orders/list"), "GET", "call") in idx)
chk("C11 request 调用点（/ 前缀）", ("/submit/order", ee.base_of("/submit/order"), "POST", "call") in idx)
chk("C12 双漏场景：this.$http 无前缀相对路径", ("/user/profile", ee.base_of("/user/profile"), "GET", "call") in idx)
chk("C13 双漏场景：axios.delete + 方法动词", ("/goods/remove", ee.base_of("/goods/remove"), "DELETE", "call") in idx)
chk("C14 Angular 泛型调用点", ("/angular/typed", ee.base_of("/angular/typed"), "GET", "call") in idx)
chk("C15 call 通道噪声过滤（无斜杠文案参数）", not any(r["形态"] == "call" and "plain" in r["接口路径"] for r in recs))
chk("C16 fetch 模板串字面量", ("/api/tpl1", ee.base_of("/api/tpl1"), "?", "fetch") in idx)
_tpl = idx.get(("/api/items/{id}", ee.base_of("/api/items/{id}"), "GET", "call"))
chk("C17 call 模板串插值 → 占位符", _tpl is not None and _tpl["含占位符"] == "是")
chk("C18 call 词边界（myrequest 不命中）", not any(r["形态"] == "call" and r["接口路径"] == "/api/wp" for r in recs))
chk("C19 粗筛正则吃模板串", bool(ea.STR_RE.search("`/api/tpl2`")) and bool(ea.REL_RE.search("`api/coarse/tpl`")))
chk("C20 fetch 绝对 URL 拆基址（旧版产 /https:/ 垃圾路径）",
    ("/api/v2/stats/overview", "https://api.demo.local", "?", "absolute") in idx)
chk("C21 call 绝对 URL 拆基址", ("/v9/abs/call", "https://cdn.other.net", "GET", "absolute") in idx)
_hs = idx.get(("/api/v2/stats/hidden", "https://api.demo.local", "?", "hidden:statUrl"))
chk("C22 hidden 绝对 URL 拆基址+域外标注", _hs is not None and "另行授权" in _hs["可疑"])
chk("C23 协议 URL 不再产折叠垃圾行（hidden 的 wss 值去重给 wss-url 通道）",
    not any(r["接口路径"].startswith(("/wss:/", "/https:/", "/http:/")) for r in recs)
    and ("wss://dup.io/ws", "", "WSS", "wss-url") in idx)
chk("C24 ws 构造器字面量去重给 wss-url（v2.32 漏掉的同类分支）",
    not any(r["接口路径"] == "/wss:/dup2.io/rt" for r in recs)
    and ("wss://dup2.io/rt", "", "WSS", "wss-url") in idx)
chk("C25 sse 绝对 URL 拆基址", ("/v9/sse/stream", "https://cdn.other.net", "SSE", "absolute") in idx)
# C28-C32 jQuery 裸 $ 调用点（2026-10 真目标驱动：label/ajax/*.aspx 三闸全漏的钉子；
# 夹具此前全 axios 风格——this.$http 有覆盖、裸 $ 没有，评测与真实站型脱节）
chk("C28 $.get 无前导斜杠 aspx 路径（实测事故形态）",
    ("/label/ajax/getAreaParentPath.aspx", ee.base_of("/label/ajax/getAreaParentPath.aspx"), "GET", "call") in idx)
chk("C29 $.post 方法动词入方法列",
    ("/label/ajax/saveForm.aspx", ee.base_of("/label/ajax/saveForm.aspx"), "POST", "call") in idx)
chk("C30 $.getJSON 映射 GET", ("/api/menu/tree", ee.base_of("/api/menu/tree"), "GET", "call") in idx)
chk("C31 $.ajax 首参形态方法记 ?", ("/label/getList.aspx", ee.base_of("/label/getList.aspx"), "?", "call") in idx)
chk("C32 jQuery 噪声与前缀：无斜杠文案不进 call、my$ 不命中",
    not any(r["形态"] == "call" and ("plain" in r["接口路径"] or r["接口路径"] == "/api/jqprefix") for r in recs))
# C33-C37 表达式首参（v2.39 真目标驱动：$.get(_siteAppPath + "label/ajax/only.aspx?formid=" + …)
# 标识符开头首参——字面量版正则恒 0 命中，回归却全绿，夹具与真实代码再脱节一次的钉子）
_jq = idx.get(("/{_siteAppPath}label/ajax/only.aspx",
               ee.base_of("/{_siteAppPath}label/ajax/only.aspx"), "GET", "call"))
chk("C33 jQuery 表达式首参：运行时变量基址打占位符、静态后缀保留、query 还原",
    _jq is not None and _jq["含占位符"] == "是" and _jq["query"] == "?formid={fid}"
    and "运行时变量" in _jq["可疑"])
_ax = idx.get(("/v9/expr/form", "/api", "GET", "call"))
chk("C34 axios 表达式首参：大写常量前缀回填（基路径=/api）",
    _ax is not None and "前缀已解析" in _ax["可疑"])
chk("C35 fetch 表达式首参：常量回填同规",
    idx.get(("/expr/fetch/path", "/api", "?", "fetch")) is not None)
chk("C36 纯动态首参不产垃圾行（$.get(someVar)/fetch(buildUrl())）",
    not any(re.fullmatch(r"/\{[^}]*\}", r["接口路径"]) for r in recs)
    and cstats.get("纯动态路径", 0) >= 2)
chk("C37 对象首参归 url: 通道不双计（$.ajax({url:…}) 无 call 行）",
    ("/jq/objform", ee.base_of("/jq/objform"), "POST", "url") in idx
    and not any(r["形态"] == "call" and "objform" in r["接口路径"] for r in recs))
# C38-C39 v2.40 真目标驱动（ezEIP 站真目标实测）：25 个补爬 .aspx 被当非文本跳过、
# 内联 AJAX /Ajax/AjaxData.ashx 漏提；css 通道 /ant; 噪声行与 @import url() 垃圾前缀
af = os.path.join(tmp, "news.aspx")
w(af, '<%@ Page Language="C#" %>\n<!doctype html><html><body>\n'
      '<a href="/news/detail.aspx">n</a>\n'
      '<script>$.get("/Ajax/AjaxData.ashx?action=list");</script>\n'
      '</body></html>\n')
astats = collections.Counter()
arecs, _, _, _ = ee.extract_file(af, hidden=True, stats=astats, consts={})
chk("C38 .aspx 进扫描面：TEXT_EXTS 含服务端页面族 + <%@ 指令前缀不挡 href/内联 AJAX 双通道；查询串 action= 不被当标签属性",
    ".aspx" in ee.TEXT_EXTS and ".php" in ee.TEXT_EXTS
    and any(r["形态"] == "html" and r["接口路径"] == "/news/detail.aspx" for r in arecs)
    and any(r["形态"] == "call" and r["接口路径"] == "/Ajax/AjaxData.ashx"
            and r["query"] == "?action=list" for r in arecs)
    and not any(r["接口路径"] == "/list" for r in arecs))
nf = os.path.join(tmp, "noise.css")
w(nf, 'div{filter:url(/ant;)}\n@import url(/ok/import);\nbody{background:url(/gateway/live/push)}\n')
nstats = collections.Counter()
nrecs, _, _, _ = ee.extract_file(nf, stats=nstats, consts={})
chk("C39 css 通道：语句标点噪声拒收（/ant;）+ @import url() 剥 url( 前缀（不再产 /url(/ 垃圾）",
    not any("ant" in r["接口路径"] or r["接口路径"].startswith("/url(") for r in nrecs)
    and any(r["接口路径"] == "/ok/import" and r["形态"] == "css" for r in nrecs)
    and any(r["接口路径"] == "/gateway/live/push" for r in nrecs)
    and nstats.get("css噪声") == 1)
# C40 v2.40 #5（真目标实测）：锚定标签内的贪婪 [^<>]* 回溯落到 onclick 里 this.src=
# （. 与 s 之间是词边界）——真 src 被吞、/this.src+ 垃圾残留的双重损失；懒回溯+
# (?<![\w.]) 前置断言让匹配落回真属性。就是报告给的最小复现 img 标签本体。
imgf = os.path.join(tmp, "code.aspx")
w(imgf, '<img src="checkcode.ashx" onclick="this.src=this.src+\'?r=\'+Math.random()">\n')
irecs, _, _, _ = ee.extract_file(imgf, hidden=True, stats=collections.Counter(), consts={})
chk("C40 img 真属性不被 onclick this.src 吞：/checkcode.ashx 在场、/this.src+ 消失",
    any(r["形态"] == "html" and r["接口路径"] == "/checkcode.ashx" for r in irecs)
    and not any("this.src" in r["接口路径"] for r in irecs))
# C41-C44 evals #6（真目标 submitform_validator.js:164 实录）：裸 url/Url 赋值曾被
# HIDDEN_NAME 前缀段必选字符类打头而永远匹配不上（uploadUrl/URL 反而都中）——tokenizer
# 本身无恙（call 通道同表达式正常），修的是候选名正则的可行前缀
_fs = idx.get(("/{expr}label/ajax/formsubmit.aspx",
               ee.base_of("/{expr}label/ajax/formsubmit.aspx"), "?", "hidden:url"))
chk("C41 裸 url 赋值 + 函数调用基址（formsubmit 形态入清单）", _fs is not None)
chk("C42 formsubmit query 参数占位符还原", _fs is not None
    and "formid={formid}" in _fs["query"] and "columnid={columnid}" in _fs["query"])
chk("C43 裸 Url 大小写变体同收",
    ("/api/bare/upper/x", ee.base_of("/api/bare/upper/x"), "?", "hidden:Url") in idx)
chk("C44 url: 冒号键仍归 url: 通道，hidden 不双计",
    ("/onlyurlkey/x", ee.base_of("/onlyurlkey/x"), "?", "url") in idx
    and not any(r["形态"] == "hidden:url" and "onlyurlkey" in r["值表达式"] for r in recs))
# C45 调用第二参参数名（真目标反判事故的机械化防线：分页真名只在 $.post 第二参里，
# page/rows 试探得出「参数被忽略」假阴性、可枚举库差点标安全——phase3 判定表
# 「差分对照无差异」行的上游数据源）
pf = os.path.join(tmp, "params.js")
w(pf, '$.post("/label/ajax/paged.aspx", {pageIndex: p, pageSize: s, columnId: c});\n'
      'this.$http.post("/cfg/save", {data:{kw: q, rows: 20}, success: function(){}});\n'
      '$.get("/plain2.aspx", function(d){});\n')
prec, _, _, _ = ee.extract_file(pf, hidden=True, stats=collections.Counter(), consts={})
pidx = {r["接口路径"]: r["参数名"] for r in prec}
chk("C45 调用第二参对象键入「参数名」列（配置键跳过、data 子键展开、回调第二参为空）",
    pidx.get("/label/ajax/paged.aspx") == "pageIndex,pageSize,columnId"
    and pidx.get("/cfg/save") == "kw,rows"
    and pidx.get("/plain2.aspx") == "")
binf = os.path.join(tmp, "packed.bin.js")
w(binf, "PK\x03\x04" + "\x00" * 200 + 'fetch("/api/bin/leak");')
bstats = collections.Counter()
brecs, _, _, _ = ee.extract_file(binf, stats=bstats)
chk("C26 二进制嗅探：前 8KB 含 NUL 即跳过，不产垃圾端点", not brecs and bstats.get("二进制跳过") == 1)
chk("C27 裸模板串通道（tpl，无调用上下文，${t.id} 还原占位符）",
    any(r["形态"] == "tpl" and r["接口路径"] == "/api/v2/goods/{id}/comments"
        and r["含占位符"] == "是" for r in recs))
jf = os.path.join(tmp, "zh-CN.json")
w(jf, '{"menu":{"export":"api/i18n/export"}}')
jrecs, _, _, _ = ee.extract_file(jf)
chk("C7 JSON 语言包通道", any(r["接口路径"] == "/api/i18n/export" and r["形态"] == "json" for r in jrecs))
cf = os.path.join(tmp, "style.css")
w(cf, "body{background:url(/gateway/live/push)}")
crecs, _, _, _ = ee.extract_file(cf)
chk("C8 CSS url() 通道", any(r["接口路径"] == "/gateway/live/push" and r["形态"] == "css" for r in crecs))
hf = os.path.join(tmp, "page.html")
w(hf, '<a href="/admin/user/list">u</a> <a href="/static/app.js">s</a>')
hrecs, _, _, _ = ee.extract_file(hf)
chk("C9 HTML href 通道收路由、剔除静态资产",
    any(r["接口路径"] == "/admin/user/list" and r["形态"] == "html" for r in hrecs)
    and not any(r["接口路径"] == "/static/app.js" for r in hrecs))

# ---------------------------------------------------------------- D 注释扫描
print("== D 注释扫描 ==")
vue = os.path.join(tmp, "page.vue")
w(vue, ('<template><a href="//cdn.x/lib.js"></a>'
        '<!-- 网关直连 192.168.1.10 备用 --></template>\n'
        '<script>// 密码：Admin@123\nvar x=1;</script>\n'))
hits, stats, seen = {}, collections.Counter(), {}
sc.scan_file(vue, hits, stats, seen)
cred = [v for k, v in hits.items() if k[0] == "中文/英文凭据"]
chk("D1 .vue 脚本区凭据命中", any("Admin@123" in k[1] for k in hits) and cred != [])
chk("D2 模板 // 不误切（无 cdn 假线索）", not any("cdn" in k[1] for k in hits))
chk("D3 内网 IP 高置信（网关语境）", any(k == ("内网裸地址", "192.168.1.10") and hits[k]["conf"] == "高"
                                    for k in hits))
chk("D4 内网置信二道判据", sc.ip_confidence("10.0.0.1", "版本 version 1.2.3") == "低"
    and sc.ip_confidence("10.0.0.1", "backend 直连") == "高")
lic = os.path.join(tmp, "lib.js")
w(lic, "/*! @license MIT */\nvar a=1;\n")
hits2, stats2, seen2 = {}, collections.Counter(), {}
sc.scan_file(lic, hits2, stats2, seen2)
chk("D5 license 横幅整块滤除", stats2["license块滤除"] == 1 and hits2 == {})
# D6 v2.40：服务端页面注释（<%-- --%> 与内嵌 <script> JS 注释）——.aspx 此前不进扫描面
asx = os.path.join(tmp, "page2.aspx")
w(asx, '<%-- 旧接口注释：密码：Svr@2024 --%>\n'
       '<script>// 内网直连 192.168.8.10 备用\nvar b=1;</script>\n')
hits3, stats3, seen3 = {}, collections.Counter(), {}
sc.scan_file(asx, hits3, stats3, seen3)
chk("D6 .aspx 双区注释：<%-- --%> 服务端注释 + 内嵌 script JS 注释都扫",
    any("Svr@2024" in k[1] for k in hits3)
    and any(k == ("内网裸地址", "192.168.8.10") for k in hits3))

# ---------------------------------------------------------------- E 响应体挖掘
print("== E 响应体挖掘 ==")
body = os.path.join(tmp, "001.body")
w(body, ('{"path": "/api/v2/echo", "links": {"next": "/api/page/list?page=2&size=50"},'
         '"upload_url": "/api/up/file", "nested": "/users/123/orders",'
         '"d": "/api/export/all"}\n'))
found = mr.mine_file(body)
paths = {}
for norm, raw, pat, _ in found:
    paths.setdefault(norm, (raw, pat))       # 同路径多模式命中取首个（特异性序）
chk("E1 error_echo", paths.get("/api/v2/echo", ("", ""))[1] == "error_echo")
chk("E2 hateoas（带 query 的分页链接不再被静默过滤）", "/api/page/list" in paths)
chk("E3 url_field", "/api/up/file" in paths)
chk("E4 嵌套资源数字段归一化", "/users/{id}/orders" in paths)
chk("E5 危险词标记（路径段精确）", mr.danger_hit("/api/export/all"))
chk("E6 危险词段边界：/orders 不误中 /order", not mr.danger_hit("/api/v1/orders/history"))
chk("E7 危险词 camel 组合段仍命中", mr.danger_hit("/api/resetPassword"))

# E8-E10 HTML 链接模式（2026-10 真目标驱动：1.15MB 搜索页五 JSON 模式零命中——
# 多页站验证响应里最自然的数据源此前不存在回路）
html_body = os.path.join(tmp, "003.body")
w(html_body, '<a href="/news/list.aspx?type=1">n</a><a href="label/ajax/getArea.aspx">a</a>'
             '<a href="/admin/login.aspx">adm</a><a href="/static/app.js">j</a>'
             '<a href="https://other.com/x">e</a><a href="mailto:a@b.c">m</a>'
             '<a href="javascript:void(0)">js</a><a href="/user/center">c</a>'
             '<script>$.get("/Ajax/AjaxData.ashx?action=list");</script>'
             "<img src=\"/captcha/code.ashx\" onclick=\"this.src=this.src+'?r='+1\">")
hfound = mr.mine_file(html_body)
hpaths = {norm: pat for norm, _raw, pat, _ in hfound}
chk("E8 html_link 模式：aspx 处理器路径入发现",
    hpaths.get("/news/list.aspx") == "html_link" and hpaths.get("/label/ajax/getArea.aspx") == "html_link")
chk("E9 html_link 资产/外链/伪协议剔除",
    not any(p.startswith(("/static/", "https:", "mailto", "javascript")) for p in hpaths))
chk("E10 html_link 纯段路由也收（无后缀不拒）", hpaths.get("/user/center") == "html_link")
chk("E10a html_link 查询串 action= 不被当标签属性（无 /list 垃圾行，与 C38 同坑）",
    "/list" not in hpaths and "/Ajax/AjaxData.ashx" not in hpaths)
chk("E10b html_link img 真属性不被 onclick this.src 吞（贪婪版此处整条零产出，与 C40 同坑同修）",
    hpaths.get("/captcha/code.ashx") == "html_link"
    and not any("this.src" in p for p in hpaths))
imgbody = os.path.join(tmp, "004.body")
w(imgbody, "<img src=\"/captcha/only.ashx\" onclick=\"this.src=this.src+'?r='+1\">\n")
ifound = mr.mine_file(imgbody)
chk("E10c 纯 img 片段进 HTML 挖掘（闸门三属性同查——验证码处理器响应典型形态，只认 href= 会整条漏）",
    any(n == "/captcha/only.ashx" and p == "html_link" for n, _r, p, _l in ifound))

# E11 去重基线两侧同口径（v2.39 真目标驱动：入口清单绝对 URL 不剥 scheme/host 时，
# 清单侧键折成 /https://host/… 与挖掘侧相对路径永不相等——30 条里 26 条已有条目漏网通过）
import csv                                                     # noqa: E402
_ent = os.path.join(tmp, "entry-mine.csv")
w(_ent, "URL,方法,来源\n"
       "https://demo.x.com/CaseDismantling/list.aspx,GET,JS提取\n"
       "https://demo.x.com/user/123/orders,GET,JS提取\n"
       "wss://ws.demo-app.cn/realtime,WSS,JS提取\n")
_existing = set()
for _r in csv.DictReader(open(_ent, encoding="utf-8-sig")):
    _existing.add(mr.normalize_path(mr.url_to_path((_r.get("URL") or "").strip())))
chk("E11 入口清单绝对 URL 剥 scheme/host 后与挖掘相对路径同键（含数字段归一化）",
    mr.normalize_path("/CaseDismantling/list.aspx") in _existing
    and mr.normalize_path("/user/{id}/orders") in _existing
    and "/https://" not in "".join(_existing))

# ---------------------------------------------------------------- F 粗筛分级
print("== F 粗筛分级 ==")
chk("F1 grade A/B/C", ea.grade("/api/user") == "A" and ea.grade("/get/list") == "B"
    and ea.grade("/static/img") == "C")

# ---------------------------------------------------------------- G 终清单对账
print("== G 终清单对账 ==")
_fine = {"/api/v1/users/list", "/user/profile", "/notice/detail",
         "/users/{id}/orders", "/dh/uploadDhFile"}
_entry = [("JS提取", "/api/v1/users/list"), ("JS提取", "/user/profile"),
          ("JS提取", "/users/123/orders"),          # 数字段归一化后与 {id} 同键
          ("JS提取", "/dh/uploadDhFile"),
          ("PROBE", "/actuator/mappings")]          # 精提之外——只提示不判缺陷
_missing, _extra = rl.reconcile(_fine, _entry)
chk("G1 汇编丢行被抓（/notice/detail 缺失即交付缺陷）", _missing == ["/notice/detail"])
chk("G2 占位符/数字段归一化匹配（{id} 对 123 不误报缺失）", "/users/{}/orders" not in _missing)
chk("G3 精提之外只提示不判缺陷（PROBE 行入 extra）",
    any(p == "/actuator/mappings" for _, p in _extra))
_m2, _ = rl.reconcile(_fine, _entry + [("JS提取", "/notice/detail")])
chk("G4 补齐后零缺失", _m2 == [])
chk("G5 URL 剥 scheme/host/query 取路径",
    rl.url_to_path("https://api.x.com/v9/data?a=1") == "/v9/data"
    and rl.url_to_path("wss://h.io/api/ws") == "/api/ws")
_f2 = os.path.join(tmp, "fine-wss.csv")
w(_f2, "接口路径,基路径,请求方式,形态\n"
       "wss://ws.demo-app.cn/realtime,,WSS,wss-url\n"
       "/user/profile,,?,url\n")
_e2 = os.path.join(tmp, "entry-wss.csv")
w(_e2, "URL,方法,来源\n"
       "wss://ws.demo-app.cn/realtime,WSS,JS提取\n"
       "/user/profile,?,JS提取\n")
_m3, _ = rl.reconcile(rl.load_fine([_f2]), rl.load_entry(_e2))
chk("G6 CLI 同口径：精提侧 wss 绝对地址不再误报缺失（load_fine 补剥 scheme）", _m3 == [])

# ---------------------------------------------------------------- H probe_verify 离线件
print("== H probe_verify 离线件 ==")
import datetime                                                # noqa: E402
used = set()
chk("H1 probe 文件命名：去斜杠转下划线", pv.probe_filename("/actuator/env", used) == "actuator_env")
chk("H2 probe 撞名加 __2 序号", pv.probe_filename("/actuator/env", used) == "actuator_env__2")
pvdir = os.path.join(tmp, "verify-h")
os.makedirs(pvdir, exist_ok=True)
for n in ("001", "003", "010"):
    w(os.path.join(pvdir, n + ".body"), "x")
chk("H3 verify 编号续起（既有最大 010 → 011，不重置）", pv.next_verify_number(pvdir) == 11)
now = datetime.datetime.now().astimezone()
w(os.path.join(pvdir, "900.headers"),
  "Timestamp: %s\nStatus: 200\n" % now.isoformat(timespec="seconds"))          # 24h 内
w(os.path.join(pvdir, "901.headers"),
  "Timestamp: %s\nStatus: 200\n"
  % (now - datetime.timedelta(hours=25)).isoformat(timespec="seconds"))       # 窗口外
w(os.path.join(pvdir, "902.headers"), "不是时间戳文件\n")                      # 不可读
n_in, n_bad = pv.window_count(pvdir, now)
chk("H4 24h 窗口合计：窗口内 1 + 不可读 1（宁拦勿漏），窗口外不计", n_in == 2 and n_bad == 1)
big_html = {"Content-Type": "text/html; charset=utf-8"}
chk("H5 catch-all 判据：200+HTML+>500B+无敏感词",
    pv.is_catchall(200, big_html, b"<html>" + b"x" * 600 + b"</html>")
    and not pv.is_catchall(200, big_html, "<html>请登录 login</html>".encode("utf-8") + b"x" * 600)
    and not pv.is_catchall(404, big_html, b"<html>" + b"x" * 600 + b"</html>"))
chk("H6 范围硬边界：子域放行、兄弟域拦",
    pv.host_in_scope("sub.www.example.com", "www.example.com")
    and pv.host_in_scope("www.example.com", "www.example.com")
    and not pv.host_in_scope("api.example.com", "www.example.com")
    and not pv.host_in_scope("evil.com", "www.example.com"))
chk("H7 判定表行定位提示：3xx/网络层失败/500",
    "不在此前缀" in pv.verdict_hint(302, {"Location": "/login"}, 0, False)
    and "未确认" in pv.verdict_hint(None, {}, 0, False)
    and "500" in pv.verdict_hint(500, {}, 4, False))
_du = set()
chk("H8 点开头路径 _dot_ 前缀（.env 曾落成隐藏文件、证据被数漏）",
    pv.probe_filename("/.env", _du) == "_dot_env"
    and pv.probe_filename("/.well-known/security.txt", set()) == "_dot_well-known_security.txt"
    and pv.probe_filename("/.env", _du) == "_dot_env__2")            # 撞名序号在改名后仍生效
chk("H9 probe 跨会话窗口护栏：本会话可用额度 = 预算 − 窗口既有（evals #2）",
    pv.probe_effective_budget(pvdir, 30, now) == (28, 2, 1)
    and pv.probe_effective_budget(pvdir, 2, now) == (0, 2, 1))
# H10/H11 手工证据折编解析（--register-manual 的离线件：实测手工 curl 证据无 Timestamp
# 首行，每轮触发「时间戳不可读按窗口内计」保守计数——折编把这类证据纳入编号与护栏）
_dmp = os.path.join(tmp, "dump.txt")
w(_dmp, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n"
        "Date: Sun, 04 Oct 2026 03:21:00 GMT\r\n\r\n<b>denied</b>")
_st, _hdrs, _body, _dts = pv.parse_http_dump(open(_dmp, "rb").read())
chk("H10 折编解析：完整响应剥头/状态码/响应头/Date 时间戳",
    _st == 403 and _hdrs.get("Content-Type") == "text/html"
    and _body == b"<b>denied</b>" and _dts is not None and _dts.year == 2026)
chk("H11 折编解析：纯 body 非 dump 形态返回 None（走状态 0 + mtime 回退链）",
    pv.parse_http_dump(b"just-a-body") is None)

print("== I 入口清单汇编器（build_entry_list，evals #3） ==")
import build_entry_list as bel                                      # noqa: E402
FCOLS = ["接口路径", "基路径", "请求方式", "形态", "含占位符", "query", "参数名",
         "可疑", "出现次数", "来源文件", "站点", "值表达式", "状态", "验证结果"]

def frow(path, form, site, **kw):
    d = {c: "" for c in FCOLS}
    d.update({"接口路径": path, "形态": form, "站点": site, "含占位符": "否"})
    d.update(kw)
    return d

bd = os.path.join(tmp, "bel")
os.makedirs(bd, exist_ok=True)
fine1 = os.path.join(bd, "fine1.csv")
fine2 = os.path.join(bd, "fine2.csv")
probec = os.path.join(bd, "probe.csv")
fetchj = os.path.join(bd, "fetch.json")
with open(fine1, "w", encoding="utf-8-sig", newline="") as f:
    _w = csv.DictWriter(f, fieldnames=FCOLS); _w.writeheader()
    _w.writerow(frow("/a/index.aspx", "html", "s1.test"))
    _w.writerow(frow("/api/x", "call", "s1.test", 请求方式="GET", 状态="已验证", 验证结果="未鉴权可读"))
    _w.writerow(frow("/v9/x", "absolute", "s1.test", 基路径="https://cdn.other.net"))
with open(fine2, "w", encoding="utf-8-sig", newline="") as f:
    _w = csv.DictWriter(f, fieldnames=FCOLS); _w.writeheader()
    # 同一 URL（借 s1 基址）从 s2 站资产再发现——delivery §1 去重按 (URL,方法)，
    # host 不同本就是两行；「亦见于/状态取全/冲突」语义只在 URL 相同时发生
    _w.writerow(frow("/a/index.aspx", "html", "s2.test", 基路径="https://s1.test"))
    _w.writerow(frow("/api/x", "call", "s2.test", 基路径="https://s1.test",
                     请求方式="GET", 状态="已验证", 验证结果="需凭据"))
with open(probec, "w", encoding="utf-8-sig", newline="") as f:
    _w = csv.writer(f); _w.writerow(["模式", "站点", "编号/文件", "方法", "URL", "目标", "状态", "字节", "提示"])
    _w.writerow(["probe", "s1.test", "robots_txt", "GET", "https://s1.test/robots.txt",
                 "/robots.txt", "404", "2752", "404 提示"])
w(fetchj, json.dumps([{"verdict": "OK", "url": "https://s1.test/a/index.aspx", "file": "x.aspx"},
                      {"verdict": "HTTP_404", "url": "https://s1.test/lost.aspx", "file": "y.aspx"}]))
brows, bstats = bel.build([fine1, fine2], [probec], [fetchj])
bidx = {(r["URL"], r["方法"]): r for r in brows}
chk("I1 形态→来源映射（html→页面引用 / call·absolute→JS提取）",
    bidx[("https://s1.test/a/index.aspx", "?")]["来源"] == "页面引用"
    and bidx[("https://s1.test/api/x", "GET")]["来源"] == "JS提取"
    and bidx[("https://cdn.other.net/v9/x", "?")]["来源"] == "JS提取")
chk("I2 URL 组装：相对行=基址+路径，绝对行用精提基路径",
    bidx[("https://cdn.other.net/v9/x", "?")] is not None
    and ("https://s1.test/api/x", "GET") in bidx)
chk("I3 去重键 (URL,方法) + 状态取全 + 亦见于",
    len([r for r in brows if r["URL"] == "https://s1.test/a/index.aspx"]) == 1
    and "亦见于 s2.test" in bidx[("https://s1.test/a/index.aspx", "?")]["备注"])
chk("I4 两条已验证冲突 → 备注标跨站结果不一致（验证结果取首个）",
    bidx[("https://s1.test/api/x", "GET")]["验证结果"] == "未鉴权可读"
    and "跨站结果不一致" in bidx[("https://s1.test/api/x", "GET")]["备注"])
chk("I5 PROBE 行：来源=PROBE、状态未验证、验证结果留空、证据进备注",
    bidx[("https://s1.test/robots.txt", "GET")]["来源"] == "PROBE"
    and bidx[("https://s1.test/robots.txt", "GET")]["状态"] == "未验证"
    and bidx[("https://s1.test/robots.txt", "GET")]["验证结果"] == ""
    and "2752" in bidx[("https://s1.test/robots.txt", "GET")]["备注"])
chk("I6 页面路由升级：OK 判定→已验证留空（词表例外），非 OK 不升级",
    bidx[("https://s1.test/a/index.aspx", "?")]["状态"] == "已验证"
    and bidx[("https://s1.test/a/index.aspx", "?")]["验证结果"] == ""
    and "https://s1.test/lost.aspx" not in {r["URL"] for r in brows}
    and bstats["页面路由升级"] == 1)

print("\n===== %d 通过 / %d 失败 =====" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
