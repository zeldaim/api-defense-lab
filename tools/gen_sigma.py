#!/usr/bin/env python3
"""OpenAPI 명세 → Shadow API 탐지 Sigma 룰 (Wazuh 를 안 쓰는 사람용 — rules/wazuh 의 룰과 같은 판정).

  python tools/gen_sigma.py [spec/dvra_openapi.json] [--out rules/sigma]

판정: 웹 서버 로그에서 "명세에 없는 (메서드, 경로)" 호출을 응답 코드로 나눈다.
  L1 정찰 404·405 / L2 발견 401·403 / L3 악용 2xx / L3-E 서버 오류 5xx
  F1 같은 IP 30초 안에 L1 20회 이상 / F2 같은 IP 60초 안에 L3 10회 이상 (Sigma 상관 룰)
범위: 루트(/)와 정적 파일(.css .js .png …)은 뺀다. 경로 파라미터는 명세 형식대로(integer → 숫자).
필드: Sigma webserver 표준 — cs-method · cs-uri-stem(쿼리 뺀 경로) · sc-status · c-ip
표준 라이브러리만 쓴다. id 는 명세 경로 + 룰 이름에서 uuid5 로 만든다 (다시 만들어도 같은 id).
"""
import argparse
import json
import os
import re
import uuid
from collections import defaultdict
from datetime import date

STATIC = r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?|txt)$"
METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
NS = uuid.UUID("6c1f0c1e-7a57-4d1b-9a55-0a91de5e1ab0")

LEVELS = [  # 이름, 제목, 응답 코드 정규식, Sigma level, Wazuh 룰 대응
    ("l1_recon", "L1 정찰 — 명세 밖 호출이 404/405", r"^40[45]$", "low", "100510"),
    ("l2_discovery", "L2 발견 — 명세 밖 호출이 401/403 (숨은 API 가 있다는 뜻)", r"^40[13]$", "medium", "100511"),
    ("l3_exploit", "L3 악용 — 명세 밖 호출이 2xx 성공 (숨은 API 사용)", r"^2\d\d$", "high", "100512"),
    ("l3e_error", "L3-E 서버 오류 — 명세 밖 호출이 5xx", r"^5\d\d$", "medium", "100513"),
]


def spec_ops(path):
    doc = json.load(open(path, encoding="utf-8"))
    ops = defaultdict(list)
    for p, item in (doc.get("paths") or {}).items():
        params = list(item.get("parameters") or [])
        for m, op in item.items():
            if m.lower() not in METHODS or not isinstance(op, dict):
                continue
            fm = {}
            for pr in params + list(op.get("parameters") or []):
                if pr.get("in") == "path":
                    sc = pr.get("schema") or pr
                    fm[pr["name"]] = r"\d+" if sc.get("type") == "integer" else r"[^/]+"
            rx = re.sub(r"\\\{([^}]+)\\\}", lambda mm: fm.get(mm.group(1), r"[^/]+"), re.escape(p))
            ops[m.upper()].append(rx.replace("\\-", "-").replace("\\_", "_"))
    return dict(sorted(ops.items())), doc.get("info", {}).get("title", path)


def q(s):
    return "'" + s.replace("'", "''") + "'"


def rule(name, title, status_rx, level, wazuh_id, ops, app, spec_name):
    rid = uuid.uuid5(NS, f"{spec_name}:{name}")
    lines = [
        f"title: 'Shadow API {title}'",
        f"id: {rid}",
        "status: experimental",
        f"description: |",
        f"  {app} 명세에 없는 (메서드, 경로) 호출 중 응답 코드가 {status_rx} 인 것.",
        f"  명세에서 자동 생성 (tools/gen_sigma.py, 명세 {spec_name}) — Wazuh 룰 {wazuh_id} 와 같은 판정.",
        "references:",
        "  - https://github.com/zeldaim/api-defense-lab",
        "author: YHC",
        f"date: {date.today():%Y-%m-%d}",
        "tags:",
        "  - attack.reconnaissance" if name == "l1_recon" else "  - attack.initial-access",
        "  - attack.t1595.003" if name == "l1_recon" else "  - attack.t1190",
        "logsource:",
        "  category: webserver",
        "detection:",
        "  selection:",
        f"    sc-status|re: {q(status_rx)}",
        "  filter_root:",
        "    cs-uri-stem: '/'",
        "  filter_static:",
        f"    cs-uri-stem|re: {q(STATIC)}",
    ]
    for m, rxs in ops.items():
        lines += [f"  filter_spec_{m.lower()}:", f"    cs-method: {m}",
                  f"    cs-uri-stem|re: {q('^(?:' + '|'.join(sorted(rxs)) + ')/*$')}"]
    lines += ["  condition: selection and not 1 of filter_*",
              "fields:", "  - c-ip", "  - cs-method", "  - cs-uri-stem", "  - sc-status",
              "falsepositives:", "  - 명세가 실제 앱보다 오래됐을 때 (새 API 가 명세에 아직 없음) — 명세를 고치고 다시 생성",
              f"level: {level}", ""]
    return name, rid, "\n".join(lines)


def correlation(name, title, base_id, base_name, timespan, count, level):
    rid = uuid.uuid5(NS, f"corr:{name}")
    return name, rid, "\n".join([
        f"title: 'Shadow API {title}'",
        f"id: {rid}",
        "status: experimental",
        f"description: 같은 출발지 IP 가 {timespan} 안에 {base_name} 판정 {count}회 이상 — Wazuh 룰 F1/F2 와 같은 판정.",
        "author: YHC",
        f"date: {date.today():%Y-%m-%d}",
        "correlation:",
        "  type: event_count",
        "  rules:",
        f"    - {base_id}",
        "  group-by:",
        "    - c-ip",
        f"  timespan: {timespan}",
        "  condition:",
        f"    gte: {count}",
        f"level: {level}",
        ""])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("spec", nargs="?", default="spec/dvra_openapi.json")
    ap.add_argument("--out", default="rules/sigma")
    a = ap.parse_args()
    ops, app = spec_ops(a.spec)
    spec_name = os.path.basename(a.spec)
    os.makedirs(a.out, exist_ok=True)
    made = [rule(*lv, ops, app, spec_name) for lv in LEVELS]
    ids = {n: i for n, i, _ in made}
    made += [correlation("f1_recon_burst", "F1 자동화 정찰 — 30초 안에 L1 20회 이상", ids["l1_recon"], "L1", "30s", 20, "high"),
             correlation("f2_mass_exfil", "F2 대량 유출 — 60초 안에 L3 10회 이상", ids["l3_exploit"], "L3", "60s", 10, "critical")]
    for n, _, text in made:
        p = os.path.join(a.out, f"shadow_api_{n}.yml")
        open(p, "w", encoding="utf-8", newline="\n").write(text)
        print(f"→ {p}")
    print(f"명세 작업 {sum(len(v) for v in ops.values())}개 ({app})")


if __name__ == "__main__":
    main()
