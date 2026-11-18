#!/usr/bin/env python3
"""Sigma 룰과 Wazuh 룰이 같은 판정을 내는지 — 연습장 접속 로그 한 벌에 둘 다 적용해 줄 단위로 대조한다.

  docker compose run --rm -v ./tools:/lab/tools:ro -v ./rules:/lab/rules:ro --entrypoint python scorer tools/sigma_vs_wazuh.py

Sigma 쪽은 rules/sigma/shadow_api_l*.yml 의 selection / filter_* 를 그대로 해석한다 (이 룰 모양 전용 — 범용 Sigma 엔진 아님).
Wazuh 쪽은 detector 가 남긴 경보(events.jsonl)를 쓴다. 대조 키 = (IP, 메서드, 경로, 응답 코드, 단계).
"""
import glob
import json
import re
import sys
from collections import Counter
from datetime import datetime

import yaml

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')
WAZUH = {"100510": "l1_recon", "100511": "l2_discovery", "100512": "l3_exploit", "100513": "l3e_error"}


def load_rules(pattern):
    rules = []
    for p in sorted(glob.glob(pattern)):
        d = yaml.safe_load(open(p, encoding="utf-8"))
        det = d["detection"]
        filters = [v for k, v in det.items() if k.startswith("filter_")]
        name = re.search(r"shadow_api_(\w+)\.yml$", p).group(1)
        rules.append((name, det["selection"], filters))
    return rules


def field_match(spec, ev):
    for k, v in spec.items():
        f, _, mod = k.partition("|")
        if mod == "re":
            if not re.search(v, str(ev[f])):
                return False
        elif str(ev[f]) != str(v):
            return False
    return True


def main():
    rules = load_rules("/lab/rules/sigma/shadow_api_l*.yml")
    sigma, n = Counter(), 0
    for l in open("/data/logs/access.log", encoding="utf-8", errors="replace"):
        m = LINE.match(l)
        if not m:
            continue
        n += 1
        ip, ts, meth, url, st = m.groups()
        t = int(datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp())
        ev = {"c-ip": ip, "cs-method": meth, "cs-uri-stem": url.split("?")[0], "sc-status": st}
        for name, sel, filters in rules:
            if field_match(sel, ev) and not any(field_match(f, ev) for f in filters):
                sigma[(ip, meth, ev["cs-uri-stem"], st, name)] += 1
    wazuh = Counter()
    for l in open("/data/run/events.jsonl", encoding="utf-8"):
        d = json.loads(l)
        if d.get("type") == "alert" and d["rule"]["id"] in WAZUH:
            x = d["data"]
            wazuh[(x["client_ip"], x["method"], x["path"], str(x["status"]), WAZUH[d["rule"]["id"]])] += 1
    only_s, only_w = sigma - wazuh, wazuh - sigma
    print(f"접속 로그 {n}줄 · Sigma 판정 {sum(sigma.values())} · Wazuh 판정 {sum(wazuh.values())} (F1/F2 빈도 룰은 대조에서 뺌)")
    for k, c in Counter(k[4] for k in sigma.elements()).items():
        print(f"  {k:14s} Sigma {c:4d} · Wazuh {sum(v for kk, v in wazuh.items() if kk[4] == k):4d}")
    for title, diff in (("Sigma 에만", only_s), ("Wazuh 에만", only_w)):
        for k, c in list(diff.items())[:20]:
            print(f"  [{title}] {k} ×{c}")
    print("일치" if not only_s and not only_w else "불일치 있음")
    sys.exit(0 if not only_s and not only_w else 1)


if __name__ == "__main__":
    main()
