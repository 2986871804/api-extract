#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归自检（离线，零网络，零目标请求）。

分组覆盖面（断言数以运行输出为准，数字不复制进文档防漂移）：
  A 判定联动   _fetch_report 排除键、.hdr 侧车降级重建（Status+CL+chunked、旧侧车退化）
  B 路径重建   concat/模板串占位符、无前导斜杠归一化、绝对URL拆基址、前缀常量回填、参数名
  C 通道覆盖   hidden/concat/json/css/html/fetch/ws/sse/wss-url/graphql 各通道有产出
  D 注释扫描   .vue 双区切分（模板 // 不误切）、凭据触发词、内网置信二道判据、license 抑制
  E 响应体挖掘 五模式、数字段/uuid 归一化、危险词标记
  F 粗筛分级   grade A/B/C 路径分级
未覆盖：safe_fetch 的网络路径（重试/退避/CL 判定需真连接）；改动脚本后先跑本脚本。

用法：python evals/run_regression.py   （退出码 0=全过，1=有失败）
"""
import json
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
import extract_apis as ea               # noqa: E402
import scan_comments as sc              # noqa: E402
import mine_responses as mr             # noqa: E402

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
))
import collections                                                    # noqa: E402
consts = ee.build_consts([js])
chk("B1 常量表收录 wss 前缀", consts.get("WS_HOST") == "wss://h.io")
recs, url_total, hit, err = ee.extract_file(js, hidden=True,
                                            stats=collections.Counter(), consts=consts)
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

# ---------------------------------------------------------------- E 响应体挖掘
print("== E 响应体挖掘 ==")
body = os.path.join(tmp, "001.body")
w(body, ('{"path": "/api/v2/echo", "links": {"next": "/api/page/list"},'
         '"upload_url": "/api/up/file", "nested": "/users/123/orders",'
         '"d": "/api/export/all"}\n'))
found = mr.mine_file(body)
paths = {}
for norm, raw, pat, _ in found:
    paths.setdefault(norm, (raw, pat))       # 同路径多模式命中取首个（特异性序）
chk("E1 error_echo", paths.get("/api/v2/echo", ("", ""))[1] == "error_echo")
chk("E2 hateoas", "/api/page/list" in paths)
chk("E3 url_field", "/api/up/file" in paths)
chk("E4 嵌套资源数字段归一化", "/users/{id}/orders" in paths)
chk("E5 危险词标记", bool(mr.DANGER_WORDS.search("/api/export/all")))

# ---------------------------------------------------------------- F 粗筛分级
print("== F 粗筛分级 ==")
chk("F1 grade A/B/C", ea.grade("/api/user") == "A" and ea.grade("/get/list") == "B"
    and ea.grade("/static/img") == "C")

print("\n===== %d 通过 / %d 失败 =====" % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)
