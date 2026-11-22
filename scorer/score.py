#!/usr/bin/env python3
"""채점기 — 정답지(labels.jsonl) × 탐지 기록(events.jsonl) × 접속 로그 → 채점표 + HTML 보고서.

  docker compose run --rm scorer                   지금까지의 모든 실행
  docker compose run --rm scorer --run <실행 ID>   그 실행만 (traffic 이 시작할 때 출력하는 ID)
  docker compose run --rm scorer --last 30         최근 30분에 시작한 행위자만

공격자(probe · bola): 탐지됐나 · 첫 요청부터 탐지 · 차단 결정까지 몇 초 · nginx 가 실제로 막기 전에 성공한 공격 요청 수
                      (가입 · 로그인 제외) · 차단 응답(403) 수
정상(normal):         차단된 IP(오탐 차단) · 룰 경보를 받은 IP(오탐 경보) · ML high 창
결과: 화면 표 + /reports/report.html (+ 시각 붙은 사본) + /reports/score.json
"""
import argparse
import html
import json
import os
import re
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)')
BLOCK_BYTES = len('{"detail":"blocked by api-defense-lab auto-response"}')    # nginx 차단 응답 (nginx/nginx.conf)
AUTH = {("POST", "/register"), ("POST", "/token")}                            # 공격 내용이 아닌 가입 · 로그인
HERE = os.path.dirname(os.path.abspath(__file__))
GRACE = 60          # 행위가 끝난 뒤에도 이만큼(초)은 그 행위의 탐지로 센다 (5초 주기 · 창 채점 지연)
e = lambda s: html.escape(str(s if s is not None else ""))


def ts(s):
    return datetime.fromisoformat(s).timestamp() if s else None


def hms(t):
    return datetime.fromtimestamp(t).astimezone().strftime("%m-%d %H:%M:%S %Z") if t else "-"


def jsonl(path):
    out = []
    if os.path.exists(path):
        for l in open(path, encoding="utf-8"):
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
    return out


def load(a):
    actors = {}
    for d in jsonl(os.path.join(a.data, "run", "labels.jsonl")):
        actors[(d["run"], d["ip"], d["role"])] = d          # 같은 행위자의 마지막 줄(end 채워진 것)이 남는다
    actors = list(actors.values())
    if a.run:
        actors = [x for x in actors if x["run"] == a.run]
    if a.last:
        actors = [x for x in actors if ts(x["start"]) >= time.time() - a.last * 60]
    ev = jsonl(os.path.join(a.data, "run", "events.jsonl"))
    for x in ev:
        x["t"] = ts(x["timestamp"])
    acc = defaultdict(list)
    ap = os.path.join(a.data, "logs", "access.log")
    if os.path.exists(ap):
        for l in open(ap, encoding="utf-8", errors="replace"):
            m = LINE.match(l)
            if m:
                t = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp()
                blocked = m.group(5) == "403" and m.group(6) == str(BLOCK_BYTES)
                acc[m.group(1)].append((t, m.group(3), m.group(4).split("?")[0], int(m.group(5)), blocked))
    return actors, ev, acc


def ip_of(v):
    return v.get("client_ip") or v.get("data", {}).get("client_ip")


def score_actor(x, ev, acc, now):
    ip, t0 = x["ip"], ts(x["start"])
    t1 = ts(x["end"]) or now
    lo, hi = t0 - 1, t1 + GRACE
    reqs = [r for r in acc.get(ip, []) if t0 - 1 <= r[0] <= t1 + 5]
    mine = [v for v in ev if ip_of(v) == ip]
    alerts = [v for v in mine if v["type"] == "alert" and lo <= v["t"] <= hi]
    mls = [v for v in mine if v["type"] == "ml" and v["level"] == "high" and lo <= v["t"] <= hi]
    blocks = [v for v in mine if v["type"] == "block"]
    pre = next((b for b in blocks if b["t"] < lo), None)                # 이 행위 전에 이미 차단돼 있었다
    blk = next((b for b in blocks if lo <= b["t"] <= hi), None)
    first = reqs[0][0] if reqs else t0
    det = sorted([("룰", v["t"]) for v in alerts] + [("ML", v["t"]) for v in mls], key=lambda z: z[1])
    bt = blk["t"] if blk else None
    eff = next((i for i, r in enumerate(reqs) if r[4]), len(reqs))     # nginx 가 실제로 처음 막은 요청
    return {
        "run": x["run"], "ip": ip, "role": x["role"], "scenario": x.get("scenario"), "start": t0, "end": ts(x["end"]),
        "requests": len(reqs),
        "detected": bool(det), "detected_by": sorted({d[0] for d in det}),
        "detect_s": round(max(det[0][1] - first, 0), 1) if det else None,
        "blocked": bool(blk), "block_s": round(max(bt - first, 0), 1) if blk else None,
        "block_source": blk["source"] if blk else None, "block_reason": blk["reason"] if blk else None,
        "block_detail": blk.get("detail") if blk else None,
        "already_blocked": bool(pre), "allowlisted": any(v["type"] == "allowlisted" for v in mine),
        "block_effective_s": round(max(reqs[eff][0] - first, 0), 1) if eff < len(reqs) else None,
        "ok_before_block": sum(1 for r in reqs[:eff] if 200 <= r[3] < 300 and (r[1], r[2]) not in AUTH),
        "forbidden_after_block": sum(1 for r in reqs if r[4]),
        "rate_limited": sum(1 for r in reqs if r[3] == 429),                 # 레이트 리밋(LAB_RATE)이 거절한 요청
        "alerts": len(alerts), "alert_levels": dict(Counter(f"L{v['rule']['level']}" for v in alerts)),
        "ml_high": len(mls), "_reqs": reqs,
    }


def med(xs):
    xs = [v for v in xs if v is not None]
    return round(statistics.median(xs), 1) if xs else None


def summarize(rows):
    by = defaultdict(list)
    for r in rows:
        by[r["role"]].append(r)
    out = {}
    for role, rs in sorted(by.items()):
        s = {"actors": len(rs), "requests": sum(r["requests"] for r in rs),
             "detected": sum(r["detected"] for r in rs), "blocked": sum(r["blocked"] for r in rs),
             "median_detect_s": med([r["detect_s"] for r in rs]), "median_block_s": med([r["block_s"] for r in rs]),
             "already_blocked": sum(r["already_blocked"] for r in rs)}
        if role == "normal":
            s["fp_blocked_ips"] = s["blocked"]
            s["fp_alerted_ips"] = sum(1 for r in rs if r["alerts"])
            s["ml_high_windows"] = sum(r["ml_high"] for r in rs)
            s["rate_limited_ips"] = sum(1 for r in rs if r["rate_limited"])   # 레이트 리밋 오탐 (429 를 받은 정상 IP)
            s["rate_limited"] = sum(r["rate_limited"] for r in rs)
        else:
            s["ok_before_block"] = sum(r["ok_before_block"] for r in rs)
            s["rate_limited"] = sum(r["rate_limited"] for r in rs)
        out[role] = s
    return out


def wide(s):
    return sum(2 if ord(c) > 0x1100 else 1 for c in str(s))


def table(headers, rows):
    w = [max([wide(h)] + [wide(r[i]) for r in rows]) for i, h in enumerate(headers)]
    pad = lambda s, n: str(s) + " " * max(0, n - wide(s))
    line = "  ".join(pad(h, w[i]) for i, h in enumerate(headers))
    return "\n".join([line, "-" * wide(line)] + ["  ".join(pad(c, w[i]) for i, c in enumerate(r)) for r in rows])


def dash(v, unit=""):
    return "-" if v is None else f"{v}{unit}"


def block_cell(r):
    return r["block_source"] if r["blocked"] else ("이미 차단" if r["already_blocked"] else "✗")


def render_text(rows, summ):
    out = ["", "■ 공격 (정답: probe · bola)"]
    atk = [r for r in rows if r["role"] != "normal"]
    out.append(table(["역할", "IP", "요청", "탐지", "탐지까지", "차단", "차단 결정까지", "새어 나간 성공", "차단 응답 403", "레이트 리밋 429"],
                     [[r["role"], r["ip"], r["requests"], "+".join(r["detected_by"]) or "✗", dash(r["detect_s"], "초"),
                       block_cell(r), dash(r["block_s"], "초"), r["ok_before_block"], r["forbidden_after_block"], r["rate_limited"]]
                      for r in atk]) if atk else "(공격 기록 없음 — docker compose run --rm traffic attack probe)")
    n = summ.get("normal")
    out += ["", "■ 정상 사용자 (오탐)"]
    out.append(f"IP {n['actors']}개 · 요청 {n['requests']} · 오탐 차단 IP {n['fp_blocked_ips']} · 룰 경보 받은 IP {n['fp_alerted_ips']}"
               f" · ML high 창 {n['ml_high_windows']} · 429 받은 IP {n['rate_limited_ips']} ({n['rate_limited']}건)" if n else "(정상 기록 없음 — docker compose run --rm traffic normal)")
    srows = [[role, s["actors"], f"{s['detected']}/{s['actors']}", f"{s['blocked']}/{s['actors']}",
              dash(s["median_detect_s"], "초"), dash(s["median_block_s"], "초"), s["ok_before_block"]]
             for role, s in summ.items() if role != "normal"]
    out += ["", "■ 요약", table(["공격", "행위자", "탐지", "차단", "탐지까지(중앙)", "차단 결정까지(중앙)", "새어 나간 성공 합"], srows)
            if srows else "-"]
    if n:
        out.append(f"정상 오탐 차단 {n['fp_blocked_ips']}/{n['actors']} IP")
    return "\n".join(out)


def bola_chart(r):
    reqs = r["_reqs"]
    t0 = reqs[0][0]
    bins = defaultdict(Counter)
    for t, m, p, st, _ in reqs:
        bins[int((t - t0) // 5)]["403" if st == 403 else "2xx" if st < 300 else "4xx"] += 1
    nb = max(bins) + 1
    W, H, pad = 900, 180, 30
    bw = (W - 2 * pad) / nb
    mx = max(sum(c.values()) for c in bins.values())
    cols = {"2xx": "var(--bad)", "4xx": "var(--warn)", "403": "var(--s1)"}
    rects = []
    for i in range(nb):
        y = H - pad
        for k in ("2xx", "4xx", "403"):
            v = bins[i][k]
            if v:
                h = (H - 2 * pad) * v / mx
                y -= h
                rects.append(f"<rect x='{pad + i * bw:.1f}' y='{y:.1f}' width='{max(bw - 2, 1):.1f}' height='{h:.1f}' "
                             f"fill='{cols[k]}' data-tip='{i * 5}~{i * 5 + 5}초: {k} {v}건'/>")
    bx = ""
    if r["block_s"] is not None:
        xb = pad + r["block_s"] / 5 * bw
        bx = (f"<line x1='{xb:.1f}' x2='{xb:.1f}' y1='{pad - 10}' y2='{H - pad}' stroke='var(--thr)' stroke-dasharray='4 3'/>"
              f"<text x='{xb + 4:.1f}' y='{pad - 2}'>자동 차단 {r['block_s']}초</text>")
    return (f"<h2>BOLA 공격자 응답 ({e(r['ip'])}, 5초 칸) — 차단 전 성공, 차단 뒤 403</h2>"
            "<div class='legend'><span><span class='sw' style='background:var(--bad)'></span>남의 주문 열람 성공(2xx)</span>"
            "<span><span class='sw' style='background:var(--warn)'></span>없는 주문(4xx)</span>"
            "<span><span class='sw' style='background:var(--s1)'></span>차단(403)</span></div>"
            f"<div class='wrap'><svg viewBox='0 0 {W} {H}' width='100%' role='img' aria-label='BOLA 공격자 응답 추이'>"
            f"{''.join(rects)}{bx}<text x='{pad}' y='{H - 8}'>공격 시작</text>"
            f"<text x='{W - pad - 60}' y='{H - 8}'>{nb * 5}초</text></svg></div>")


def badge(ok, yes, no):
    return f"<span class='badge {'ok' if ok else 'no'}'>{e(yes if ok else no)}</span>"


def stat(v, label):
    return f"<div><div class='big'>{e(v)}</div><span class='sm'>{e(label)}</span></div>"


def render_html(rows, summ, ev, args):
    css = open(os.path.join(HERE, "report.css"), encoding="utf-8").read()
    names = {"probe": "명세 밖 탐색 (probe)", "bola": "명세 안 BOLA (bola)"}
    cards = []
    for role, s in summ.items():
        if role == "normal":
            cards.append(f"<div class='card'><h3>정상 사용자 — 오탐 {badge(s['fp_blocked_ips'] == 0, '✓ 차단 0', '✗ 차단 있음')}</h3>"
                         "<div class='row'>" + stat(s["actors"], "IP") + stat(s["requests"], "요청")
                         + stat(s["fp_blocked_ips"], "오탐 차단 IP") + stat(s["fp_alerted_ips"], "룰 경보 받은 IP")
                         + stat(s["ml_high_windows"], "ML high 창") + stat(s["rate_limited_ips"], "429 받은 IP") + "</div></div>")
        else:
            ok = s["blocked"] == s["actors"]
            no_msg = f"✗ 차단 {s['blocked']}/{s['actors']}"
            cards.append(f"<div class='card'><h3>{e(names.get(role, role))} {badge(ok, '✓ 전부 차단', no_msg)}</h3>"
                         "<div class='row'>" + stat(f"{s['detected']}/{s['actors']}", "탐지")
                         + stat(dash(s["median_detect_s"], "초"), "탐지까지 (중앙값)")
                         + stat(dash(s["median_block_s"], "초"), "차단 결정까지 (중앙값)")
                         + stat(s["ok_before_block"], "새어 나간 성공(2xx)") + stat(s["rate_limited"], "레이트 리밋 429") + "</div></div>")
    atk = [r for r in rows if r["role"] != "normal"]
    atab = "".join(
        f"<tr><td>{e(r['role'])}</td><td><code>{e(r['ip'])}</code></td><td>{hms(r['start'])}</td><td>{r['requests']}</td>"
        f"<td>{e('+'.join(r['detected_by']) or '✗')}</td><td>{dash(r['detect_s'], '초')}</td>"
        f"<td>{e(block_cell(r))}</td><td>{dash(r['block_s'], '초')}</td>"
        f"<td>{r['ok_before_block']}</td><td>{r['forbidden_after_block']}</td>"
        f"<td class='sm'>{e(r['block_reason'] or '')} {e(r['block_detail'] or '')}<br>"
        f"{e(' · '.join(f'{k} {v}' for k, v in sorted(r['alert_levels'].items())))}</td></tr>" for r in atk)
    nfp = [r for r in rows if r["role"] == "normal" and (r["blocked"] or r["alerts"] or r["ml_high"])]
    ntab = "".join(f"<tr><td><code>{e(r['ip'])}</code></td><td>{r['requests']}</td><td>{'차단' if r['blocked'] else '-'}</td>"
                   f"<td>{r['alerts']}</td><td>{r['ml_high']}</td><td class='sm'>{e(r['block_reason'] or '')}</td></tr>" for r in nfp)
    bolas = [r for r in atk if r["role"] == "bola" and r["_reqs"]]
    btab = "".join(f"<tr><td>{hms(b['t'])}</td><td><code>{e(b['client_ip'])}</code></td><td>{e(b['source'])}</td>"
                   f"<td>{e(b['reason'])}</td><td>{e(b.get('detail'))}</td><td>{e(b.get('label'))}</td></tr>"
                   for b in ev if b["type"] == "block")
    scope = f"실행 <code>{e(args.run)}</code>" if args.run else (f"최근 {args.last}분" if args.last else "모든 실행")
    groups = os.environ.get("LAB_BLOCK_GROUPS", "shadow_api_exploit,shadow_api_recon_burst,shadow_api_mass_exfil,lab_block")
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>방어 연습장 채점</title><style>{css}</style></head><body class="viz-root"><main>
<h1>API 방어 연습장 — 채점 보고서</h1>
<div class="mut">{scope} · 채점 {hms(time.time())} · <b>DVRA · 합성 트래픽</b> · 모델 <code>{e(os.environ.get('LAB_MODEL', '-'))}</code><br>
정답지(labels.jsonl)는 traffic 이 남긴 것이고 탐지기는 정답지를 보지 않는다. 행위가 끝난 뒤 {GRACE}초까지의 탐지를 그 행위의 것으로 센다.</div>
<div class="cards">{''.join(cards)}</div>
<h2>공격자별</h2><div class="wrap"><table><tr><th>역할</th><th>IP</th><th>시작</th><th>요청</th><th>탐지</th><th>탐지까지</th><th>차단</th><th>차단 결정까지</th><th>새어 나간 성공</th><th>차단 응답 403</th><th>근거</th></tr>{atab}</table></div>
{''.join(bola_chart(r) for r in bolas[-1:])}
<h2>정상 사용자 중 무언가에 걸린 IP</h2><div class="wrap"><table><tr><th>IP</th><th>요청</th><th>차단</th><th>룰 경보</th><th>ML high 창</th><th>이유</th></tr>{ntab or "<tr><td colspan='6'>없음</td></tr>"}</table></div>
<h2>자동 차단 기록 (전체)</h2><div class="wrap"><table><tr><th>시각</th><th>IP</th><th>탐지</th><th>이유</th><th>근거</th><th>정답</th></tr>{btab}</table></div>
<p class="sm">차단 정책: ML high(창 요청 {e(os.environ.get('LAB_BLOCK_MIN_REQ', '15'))}건 이상) · 룰 그룹 {e(groups)} → 차단 / 나머지 경보 → 기록만.</p>
</main><div class="tip" id="tip"></div>
<script>
const tip=document.getElementById('tip');
document.querySelectorAll('[data-tip]').forEach(n=>{{
  n.addEventListener('mousemove',ev=>{{tip.innerHTML=n.dataset.tip;tip.style.display='block';
    tip.style.left=Math.min(ev.clientX+12,innerWidth-370)+'px';tip.style.top=(ev.clientY+12)+'px';}});
  n.addEventListener('mouseleave',()=>tip.style.display='none');}});
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run")
    ap.add_argument("--last", type=int, help="최근 N분에 시작한 행위자만")
    ap.add_argument("--data", default="/data")
    ap.add_argument("--out", default="/reports")
    a = ap.parse_args()
    actors, ev, acc = load(a)
    if not actors:
        raise SystemExit("정답지가 비어 있다 — 먼저 docker compose run --rm traffic demo (또는 normal · attack ...)")
    now = time.time()
    rows = sorted((score_actor(x, ev, acc, now) for x in actors), key=lambda r: (r["role"] == "normal", r["start"]))
    summ = summarize(rows)
    print(render_text(rows, summ))
    os.makedirs(a.out, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    page = render_html(rows, summ, ev, a)
    for name in ("report.html", f"report_{stamp}.html"):
        open(os.path.join(a.out, name), "w", encoding="utf-8").write(page)
    json.dump({"scored_at": datetime.now(timezone.utc).isoformat(), "filter": {"run": a.run, "last_min": a.last},
               "summary": summ, "actors": [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]},
              open(os.path.join(a.out, "score.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\n→ reports/report.html · reports/report_{stamp}.html · reports/score.json")


if __name__ == "__main__":
    main()
