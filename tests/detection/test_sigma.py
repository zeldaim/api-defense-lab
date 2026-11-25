#!/usr/bin/env python3
"""Sigma 룰을 detector 의 Sigma 엔진으로 — cases.json 의 정답 단계와 같은지, 빈도 룰(F1 · F2)이 맞게 걸리는지.
  python tests/detection/test_sigma.py        (pyyaml 필요, 저장소 루트에서)
"""
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "detector"))
import sigma_engine  # noqa: E402

LEVEL = {"100510": "L1", "100511": "L2", "100512": "L3", "100513": "L3E"}
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')


def event(line):
    ip, ts, meth, url, st, ua = LINE.match(line).groups()
    path, _, q = url.partition("?")
    t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    return {"c-ip": ip, "cs-method": meth, "cs-uri-stem": path, "cs-uri-query": q, "sc-status": st, "cs-user-agent": ua}, t


def main():
    fails = 0
    cases = json.load(open(os.path.join(os.path.dirname(__file__), "cases.json"), encoding="utf-8"))
    for c in cases:
        eng = sigma_engine.Engine(os.environ.get("SIGMA_RULES", os.path.join(ROOT, "rules", "sigma")), quiet=True)     # 사례마다 새로 (빈도 상태 섞이지 않게)
        ev, t = event(c["line"])
        got = sorted(LEVEL[a["rule"]["id"]] for a in eng.evaluate(ev, t) if a["rule"]["id"] in LEVEL) or ["none"]
        ok = got == [c["expect"]]
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']}  (기대 {c['expect']} · Sigma {','.join(got)})")

    # 빈도: 30초에 L1 25회 → F1 1번(60초 동안 다시 안 냄) · 60초에 L3 12회 → F2 1번 · 38초에 L1 19회 → F1 없음
    eng = sigma_engine.Engine(os.environ.get("SIGMA_RULES", os.path.join(ROOT, "rules", "sigma")), quiet=True)
    cnt = Counter()
    mk = lambda ip, p, st: {"c-ip": ip, "cs-method": "GET", "cs-uri-stem": p, "cs-uri-query": "", "sc-status": st, "cs-user-agent": "t"}
    for i in range(25):
        cnt.update(a["rule"]["id"] for a in eng.evaluate(mk("1.1.1.1", f"/nope{i}", "404"), 1000 + i * 0.4))
    for i in range(12):
        cnt.update(a["rule"]["id"] for a in eng.evaluate(mk("2.2.2.2", "/debug", "200"), 2000 + i * 3))
    for i in range(19):
        cnt.update("slow-" + a["rule"]["id"] for a in eng.evaluate(mk("3.3.3.3", f"/x{i}", "404"), 3000 + i * 2))
    for name, ok in (("F1 자동화 정찰 — 30초에 L1 25회 → 1번", cnt["100520"] == 1),
                     ("F2 대량 유출 — 60초에 L3 12회 → 1번", cnt["100521"] == 1),
                     ("F1 아님 — 38초에 L1 19회 (30초 창에 20 미만)", cnt["slow-100520"] == 0)):
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    # AI 에이전트 (artex-fingerprint): UA 룰 · 401 순회 상관 룰 — 그룹 이름으로 센다 (id 는 파일 순서로 정해짐)
    eng = sigma_engine.Engine(os.environ.get("SIGMA_RULES", os.path.join(ROOT, "rules", "sigma")), quiet=True)
    g = Counter()
    ua = lambda ip, u: {**mk(ip, "/", "200"), "cs-user-agent": u}
    walk = lambda ip, st: {**mk(ip, "/profile", st), "cs-user-agent": "Mozilla/5.0 (api-defense-lab)"}
    seen = lambda tag, al: g.update(f"{tag}:{x}" for a in al for x in a["rule"]["groups"] if x.startswith("sigma_agent") and a["rule"]["level"] >= 12)
    seen("ua", eng.evaluate(ua("4.4.4.4", "artex-enrich/1.0"), 4000))
    seen("normal-ua", eng.evaluate(ua("4.4.4.5", "Mozilla/5.0 (api-defense-lab)"), 4001))
    seen("framework-ua", eng.evaluate(ua("4.4.4.6", "norma/0.4"), 4002))          # 다섯 번째 갈래 — 팀 랩 로그에서만 관측, ARTEX 소스엔 없음
    for i in range(21):
        seen("fast", eng.evaluate(walk("5.5.5.5", "401"), 5000 + i * 1.1))          # 경로마다 1.1초 (기본 · ua-changed)
    for i in range(21):
        seen("slow", eng.evaluate(walk("6.6.6.6", "401"), 6000 + i * 9))            # 경로마다 9초 (slow)
    seen("relogin", eng.evaluate(walk("7.7.7.7", "401"), 7000))                    # 정상: 토큰 만료 401 한 번
    corr = "sigma_agent_auth_fail_walk"
    for name, ok in (("에이전트 UA → UA 룰", g["ua:sigma_agent_tool_ua"] == 1),
                     ("정상 UA → UA 룰 없음", g["normal-ua:sigma_agent_tool_ua"] == 0),
                     ("다섯 번째 갈래(norma/0.4) → UA 룰", g["framework-ua:sigma_agent_tool_ua"] == 1),
                     ("401 순회 1.1초 간격 21회 → 상관 룰 (60초 무시 → 1번)", g[f"fast:{corr}"] == 1),
                     ("401 순회 9초 간격 → 상관 룰 없음 (알려진 한계)", g[f"slow:{corr}"] == 0),
                     ("정상 401 한 번 → 상관 룰 없음", g[f"relogin:{corr}"] == 0)):
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    # Honey API: 번들에만 적힌 미끼 경로(/internal/) — 느린 에이전트도 첫 접촉에서 즉시 잡힌다 (401 순회 상관 룰의 사각을 메움)
    eng = sigma_engine.Engine(os.environ.get("SIGMA_RULES", os.path.join(ROOT, "rules", "sigma")), quiet=True)
    honey_hit = lambda ip, path: any(x == "lab_block" for a in eng.evaluate({**mk(ip, path, "401"), "cs-user-agent": "t"}, 9000) for x in a["rule"]["groups"])
    for name, ok in (("미끼 경로 한 번 → 즉시 lab_block (느린 에이전트도 잡힘)", honey_hit("8.8.8.8", "/internal/debug/config")),
                     ("정상 보호 경로(/profile) 401 한 번 → lab_block 아님", not honey_hit("8.8.8.9", "/profile"))):
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{'모두 통과' if not fails else f'실패 {fails}건'} — 사례 {len(cases)} + 빈도 3 + 에이전트 5 + 허니 2")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
