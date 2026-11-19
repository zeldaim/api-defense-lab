#!/usr/bin/env python3
"""[모듈 inventory] 트래픽에서 실제로 쓰이는 API 를 찾아 공식 명세와 대조한다.

  docker compose --profile inventory run --rm inventory              기록된 트래픽 → 보고서 (reports/inventory/)
  docker compose --profile inventory run --rm inventory --sigma      + 관측 명세로 Sigma 룰 생성 ("명세 없이 시작")
  docker compose --profile inventory run --rm inventory --reset      기록 지우기 (새로 잡기 전에)

흐름
  ① inventory-proxy(mitmdump 역방향 프록시)가 남긴 /inv/flows.mitm 을 읽는다
  ② '처리 증거'가 있는 응답만 남긴다 — 404(없는 경로) · nginx 자동 차단 403(앱이 답한 게 아님)은 뺀다
  ③ mitmproxy2swagger 로 관측 명세를 만든다 (두 번 돌린다 — 아래 '자동화한 손작업')
  ④ 공식 명세(spec/dvra_openapi.json)와 (메서드, 경로) 단위로 대조 → 문서화됨 · Shadow · 관측 안 됨 · 차단돼 확인 못 함
  ⑤ 정답(DVRA 숨은 API 3개)과 맞춰 본다 — 정답은 채점에만 쓴다
  ⑥ (--sigma) 관측 명세에 경로 파라미터 정의를 붙여 tools/gen_sigma.py 로 룰 생성

자동화한 손작업 (mitmproxy2swagger 는 원래 반자동이다)
  - 1차 실행은 경로 목록을 'ignore:' 로 막아서 내놓는다 → 사람이 지우고 2차 실행. 여기서는 스크립트가 지운다.
  - 목록은 '위가 먼저, 탐욕 매칭' 이다. /orders/{id} 가 /orders/export 보다 위에 있으면 숨은 경로가
    파라미터로 빨려 들어가 사라진다 → 숫자 아닌 고정 경로를 먼저, 템플릿을 나중에 둔다.
  - 숫자 그대로인 경로(/orders/7)는 버리고 템플릿(/orders/{id})만 남긴다.
  - 관측 명세의 경로 파라미터는 작업마다 string 으로 들어간다 → gen_sigma 가 {id} 를 '아무 값'으로 보고
    /orders/abc 같은 명세 형식 위반을 놓친다. 템플릿은 숫자에서 나왔으므로 integer 로 바꾼다.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
from ruamel.yaml import YAML

BLOCK_BODY = b'{"detail":"blocked by api-defense-lab auto-response"}'   # nginx/nginx.conf 의 차단 응답
DOCS = {("GET", "/docs"), ("GET", "/docs/oauth2-redirect"), ("GET", "/openapi.json"), ("GET", "/redoc")}  # gen_sigma ALLOW 와 같게
# 정답: DVRA 소스에서 include_in_schema=False 인 숨은 API (traffic/lab_traffic.py 의 PROBES 주석과 같다). 판정에는 쓰지 않는다.
HIDDEN = [("GET", "/debug"), ("GET", "/delivery/orders"), ("GET", "/admin/reset-chef-password")]
NUM = re.compile(r"^\d+$")
yaml = YAML(typ="safe")


def norm(path):
    return re.sub(r"\{[^}]+\}", "{}", path.rstrip("/") or "/")


def tpl_regex(path):
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", r"\\d+", re.escape(path)) + "$")


def read_flows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        sys.exit(f"기록이 없다: {path}\n먼저 inventory-proxy 를 거쳐 트래픽을 보낸다:\n"
                 "  docker compose --profile inventory up -d\n"
                 "  docker compose run --rm -e LAB_TARGET=http://inventory-proxy:8080 traffic demo")
    out = []
    with open(path, "rb") as f:
        try:
            for fl in io.FlowReader(f).stream():
                if getattr(fl, "response", None) is not None and getattr(fl, "request", None) is not None:
                    out.append(fl)
        except FlowReadException as e:              # 프록시가 쓰는 중이면 마지막 기록이 잘릴 수 있다
            print(f"[주의] 기록 끝부분을 못 읽음 ({e}) — 읽은 데까지 쓴다", flush=True)
    return out


def m2s(src, out, prefix, suppress):
    cmd = ["mitmproxy2swagger", "-f", "flow", "-i", src, "-o", out, "-p", prefix] + (["-s"] if suppress else [])
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode:
        sys.exit(f"mitmproxy2swagger 실패: {r.stderr[-800:]}")


def accept_templates(path):
    """1차 결과의 x-path-templates: ignore: 를 떼고, 고정 경로 먼저 · 템플릿 나중, 숫자 경로는 버린다."""
    doc = yaml.load(open(path, encoding="utf-8"))
    items = [t.split("ignore:", 1)[-1] for t in doc.get("x-path-templates") or []]
    fixed = [t for t in items if "{" not in t and not any(NUM.match(s) for s in t.split("/") if s)]
    tpls = [t for t in items if "{" in t]
    doc["x-path-templates"] = fixed + tpls
    yaml.dump(doc, open(path, "w", encoding="utf-8"))
    return fixed, tpls


def spec_ops(path):
    doc = json.load(open(path, encoding="utf-8"))
    return {(m.upper(), norm(p)) for p, item in (doc.get("paths") or {}).items()
            for m in item if m.lower() in ("get", "post", "put", "patch", "delete", "head", "options")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", default="/inv/flows.mitm")
    ap.add_argument("--spec", default="/lab/spec/dvra_openapi.json")
    ap.add_argument("--out", default="/reports/inventory")
    ap.add_argument("--sigma", action="store_true", help="관측 명세로 Sigma 룰 생성 — 정상 트래픽만 잡았을 때만 의미 있다")
    ap.add_argument("--reset", action="store_true", help="기록(flows.mitm)을 지우고 끝낸다")
    a = ap.parse_args()

    if a.reset:
        open(a.flows, "wb").close() if os.path.exists(a.flows) else None
        print(f"기록을 비웠다: {a.flows}")
        return

    flows = read_flows(a.flows)
    ev, blocked, nf = [], [], []
    for fl in flows:
        st, body = fl.response.status_code, fl.response.raw_content or b""
        # 404 = 없는 경로, 405 = 경로는 있지만 그 메서드는 없음 → 그 (메서드, 경로) 작업의 증거가 아니다
        (blocked if st == 403 and body.strip() == BLOCK_BODY else nf if st in (404, 405) else ev).append(fl)
    if not ev:
        sys.exit("처리 증거가 있는 응답이 없다 (전부 404 · 차단)")
    prefix = f"{ev[0].request.scheme}://{ev[0].request.host_header or ev[0].request.host}"
    prefix = re.sub(r":80$", "", prefix)

    os.makedirs(a.out, exist_ok=True)
    tmp = "/tmp/evidence.mitm"
    with open(tmp, "wb") as f:
        w = io.FlowWriter(f)
        for fl in ev:
            w.add(fl)
    obs = os.path.join(a.out, "observed_openapi.yaml")
    if os.path.exists(obs):
        os.remove(obs)                               # 이전 결과에 덧붙지 않게 (mitmproxy2swagger 는 있으면 합친다)
    m2s(tmp, obs, prefix, False)
    fixed, tpls = accept_templates(obs)
    m2s(tmp, obs, prefix, True)
    odoc = yaml.load(open(obs, encoding="utf-8"))
    observed = sorted({(m.upper(), p) for p, item in (odoc.get("paths") or {}).items() for m in item
                       if m.lower() in ("get", "post", "put", "patch", "delete", "head", "options")})

    # 관측된 (메서드, 경로) 마다 증거: 요청 수 · 응답 코드 · 출발지 수 · 처음 · 마지막
    rx = [(p, tpl_regex(p)) for p in sorted({p for _, p in observed}, key=lambda s: ("{" in s, s))]
    agg = defaultdict(lambda: {"n": 0, "status": Counter(), "ips": set(), "first": None, "last": None})

    def match(path):
        return next((p for p, r in rx if r.match(path.split("?")[0].rstrip("/") or "/")), None)

    for fl in ev:
        p = match(fl.request.path)
        if not p:
            continue
        g = agg[(fl.request.method, p)]
        t = fl.request.timestamp_start
        g["n"] += 1
        g["status"][fl.response.status_code] += 1
        g["ips"].add(fl.request.headers.get("X-Client-IP") or (fl.client_conn.peername or ("?",))[0])
        g["first"] = min(g["first"] or t, t)
        g["last"] = max(g["last"] or t, t)

    official = spec_ops(a.spec)
    # 명세 경로 템플릿(값 자리는 아무 값) — /orders/export 가 422 면 '숨은 API'가 아니라 /orders/{order_id} 에 숫자 아닌 값을 넣은 것
    loose = [(m, re.compile("^" + re.sub(r"\\\{\\\}", "[^/]+", re.escape(p)) + "$")) for m, p in official if "{}" in p]
    onorm = {(m, norm(p)): (m, p) for m, p in observed}
    rows = []
    for (m, p) in observed:
        k = (m, norm(p))
        g = agg.get((m, p), {"n": 0, "status": Counter(), "ips": set(), "first": None, "last": None})
        if k in official:
            kind = "documented"
        elif (m, p) in DOCS:
            kind = "docs-page"
        elif set(g["status"]) == {422} and any(mm == m and r.match(p) for mm, r in loose):
            kind = "param-error"
        else:
            kind = "shadow"
        rows.append({"method": m, "path": p, "kind": kind, "requests": g["n"],
                     "status": dict(sorted(g["status"].items())), "sources": len(g["ips"]),
                     "first": datetime.fromtimestamp(g["first"], timezone.utc).isoformat() if g["first"] else None,
                     "last": datetime.fromtimestamp(g["last"], timezone.utc).isoformat() if g["last"] else None})
    unseen = sorted(k for k in official if k not in onorm)
    seen_paths = {(fl.request.method, fl.request.path.split("?")[0]) for fl in ev}
    blocked_only = Counter((fl.request.method, fl.request.path.split("?")[0]) for fl in blocked
                           if (fl.request.method, fl.request.path.split("?")[0]) not in seen_paths)
    shadow = {(r["method"], r["path"]) for r in rows if r["kind"] == "shadow"}
    answer = [{"method": m, "path": p,
               "result": "found" if (m, p) in shadow else "blocked-before-seen" if (m, p) in blocked_only else "missed"}
              for m, p in HIDDEN]

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools": {"mitmproxy2swagger": "0.15.0", "mitmproxy": "12.3.1"},
        "flows": {"total": len(flows), "evidence": len(ev), "no_operation_404_405": len(nf), "blocked_by_lab": len(blocked)},
        "summary": dict(Counter(r["kind"] for r in rows)) | {"unseen_documented": len(unseen),
                                                             "blocked_only": len(blocked_only)},
        "hidden_api_answer": answer,
        "endpoints": sorted(rows, key=lambda r: (r["kind"] != "shadow", r["kind"], r["path"], r["method"])),
        "unseen_documented": [{"method": m, "path": p} for m, p in unseen],
        "blocked_only": [{"method": m, "path": p, "requests": n} for (m, p), n in sorted(blocked_only.items())],
        "templates": {"fixed_first": fixed, "parameter": tpls},
    }
    json.dump(result, open(os.path.join(a.out, "inventory.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    # 관측 명세 → JSON (+ 경로 파라미터 정의). 템플릿은 숫자에서 만들어졌다 → integer
    for p, item in (odoc.get("paths") or {}).items():
        names = re.findall(r"\{([^}]+)\}", p)
        if names:
            item["parameters"] = [{"name": n, "in": "path", "required": True, "schema": {"type": "integer"}} for n in names]
            for op in item.values():                 # mitmproxy2swagger 는 작업마다 같은 파라미터를 string 으로 넣는다 → 덮어쓴다
                if isinstance(op, dict):
                    for pr in op.get("parameters") or []:
                        if pr.get("in") == "path" and pr.get("name") in names:
                            pr["schema"] = {"type": "integer"}
    odoc.setdefault("info", {})["title"] = "observed (mitmproxy2swagger)"
    ojson = os.path.join(a.out, "observed_openapi.json")
    json.dump(odoc, open(ojson, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    write_md(result, os.path.join(a.out, "inventory.md"))
    print_summary(result)

    if a.sigma:
        sig = os.path.join(a.out, "sigma")
        gen = os.environ.get("LAB_GEN_SIGMA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "gen_sigma.py")
        r = subprocess.run([sys.executable, gen, ojson, "--out", sig], capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip())
        print("[주의] 관측 명세 = '잡힌 트래픽이 정상이었다'는 가정. 공격이 섞인 기록으로 만들면 공격 경로가 정상으로 들어간다.")
    print(f"\n→ {a.out}/inventory.md · inventory.json · observed_openapi.json" + (" · sigma/" if a.sigma else ""))


def write_md(r, path):
    f = r["flows"]
    L = ["# API 인벤토리 — 트래픽 관측 vs 공식 명세", "",
         f"만든 시각 {r['generated_at']} · mitmproxy2swagger {r['tools']['mitmproxy2swagger']} · 합성 트래픽", "",
         f"기록 {f['total']}건 = 처리 증거 {f['evidence']} + 404·405 {f['no_operation_404_405']} + 연습장 차단 {f['blocked_by_lab']}", "",
         "## 숨은 API 정답 (DVRA include_in_schema=False)", "", "| 메서드 | 경로 | 결과 |", "|---|---|---|"]
    names = {"found": "✅ Shadow 로 찾음", "blocked-before-seen": "⛔ 차단돼서 확인 못 함", "missed": "❌ 관측 안 됨"}
    L += [f"| {x['method']} | `{x['path']}` | {names[x['result']]} |" for x in r["hidden_api_answer"]]
    L += ["", "## 관측된 API", "", "| 분류 | 메서드 | 경로 | 요청 | 응답 코드 | 출발지 수 |", "|---|---|---|---|---|---|"]
    kinds = {"shadow": "**Shadow**", "documented": "문서화됨", "docs-page": "문서 화면(예외)",
             "param-error": "명세 경로 + 잘못된 값(422)"}
    L += [f"| {kinds[e['kind']]} | {e['method']} | `{e['path']}` | {e['requests']} | "
          f"{' · '.join(f'{k}×{v}' for k, v in e['status'].items())} | {e['sources']} |" for e in r["endpoints"]]
    L += ["", f"## 명세에 있는데 관측 안 됨 ({len(r['unseen_documented'])})", "",
          "관측 안 됨 ≠ 폐기. 이 기록 동안 아무도 안 불렀을 뿐이다 — Zombie 후보로 확인할 목록.", ""]
    L += [f"- {x['method']} `{x['path']}`" for x in r["unseen_documented"]] or ["- 없음"]
    L += ["", f"## 차단돼서 확인 못 한 경로 ({len(r['blocked_only'])})", "",
          "자동 차단 뒤의 요청은 앱이 아니라 nginx 가 답했다 — 있는지 없는지 모른다.", ""]
    L += [f"- {x['method']} `{x['path']}` ({x['requests']})" for x in r["blocked_only"]] or ["- 없음"]
    open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")


def print_summary(r):
    f, s = r["flows"], r["summary"]
    print(f"기록 {f['total']} · 증거 {f['evidence']} · 404·405 {f['no_operation_404_405']} · 차단 {f['blocked_by_lab']}")
    print(f"관측 API: 문서화됨 {s.get('documented', 0)} · Shadow {s.get('shadow', 0)} · 문서 화면 {s.get('docs-page', 0)}"
          f" · 명세에 있는데 관측 안 됨 {s['unseen_documented']} · 차단돼 확인 못 함 {s['blocked_only']}")
    for e in r["endpoints"]:
        if e["kind"] == "shadow":
            print(f"  Shadow  {e['method']:6} {e['path']:32} 요청 {e['requests']:3}  {e['status']}  출발지 {e['sources']}")
    got = sum(x["result"] == "found" for x in r["hidden_api_answer"])
    print(f"숨은 API 정답 {got}/{len(r['hidden_api_answer'])}: "
          + " · ".join(f"{x['path']}={x['result']}" for x in r["hidden_api_answer"]))


if __name__ == "__main__":
    main()
