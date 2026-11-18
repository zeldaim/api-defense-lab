#!/usr/bin/env python3
"""탐지 파이프라인 (detector 컨테이너) — 2초마다 (LAB_EVERY)
  ① nginx 접속 로그 새 줄          → ES lab-access
  ② Wazuh 경보(alerts.json) 새 줄  → ES lab-alerts   (사용자 룰 범위 100000~199999 만)
  ③ ML 모델로 IP × 5분 창 채점     → ES lab-ml
  ④ 차단 정책에 걸리면 차단 목록(ips.map)에 추가 (nginx 가 다시 읽어 403) → ES lab-response
  모든 판정은 /data/run/events.jsonl 에도 남는다 — 채점기(scorer)가 이 파일을 정답지와 맞춰 본다.

차단 정책 (README 와 같게 유지)
  ML high (그 창 요청 LAB_BLOCK_MIN_REQ 건 이상)   → 자동 차단 (명세 안 BOLA — 룰이 못 잡는다)
  룰 그룹이 LAB_BLOCK_GROUPS 중 하나                → 자동 차단 (기본: Shadow L3 · F1 · F2 · lab_block)
  그 밖의 룰 경보                                    → 기록만
  허용 목록(LAB_ALLOW, 기본 10.1.0.1)                → 걸려도 차단하지 않고 기록만

정답 라벨(normal · probe · bola)은 traffic 이 남긴 labels.jsonl 에서 읽어 화면 표시에만 쓴다 — 판정에는 안 쓴다.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import features as F  # noqa: E402  (v2.1 — v2 모듈에 바꿔 끼운 함수)

import joblib  # noqa: E402
import numpy as np  # noqa: E402

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')
env = os.environ.get


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


class Labels:
    """traffic 가 남긴 정답지 → IP 별 역할. 파일이 바뀔 때만 다시 읽는다."""

    def __init__(self, path):
        self.path, self.mtime, self.map = path, None, {}

    def get(self, ip):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return "other"
        if m != self.mtime:
            self.mtime, self.map = m, {}
            for l in open(self.path, encoding="utf-8"):
                try:
                    d = json.loads(l)
                    self.map[d["ip"]] = d["role"]
                except (ValueError, KeyError):
                    pass
        return self.map.get(ip, "other")


def es(method, url, body=None, ctype="application/json", tries=6):
    """ES 가 잠깐 느려도 죽지 않게 재시도 (시작 직후 타임아웃으로 멈춘 적 있음)."""
    for k in range(tries):
        req = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (400, 404) and method in ("PUT", "HEAD"):
                return {}
            raise
        except (TimeoutError, urllib.error.URLError, ConnectionError) as e:
            print(f"[ES 재시도 {k + 1}/{tries}] {e}", flush=True)
            time.sleep(5)
    raise RuntimeError(f"ES 응답 없음: {method} {url}")


def bulk(base, index, docs, ids=None):
    if not docs:
        return
    lines = []
    for i, d in enumerate(docs):
        lines.append(json.dumps({"index": {"_id": ids[i]}} if ids else {"index": {}}))
        lines.append(json.dumps(d, ensure_ascii=False))
    es("POST", f"{base}/{index}/_bulk", ("\n".join(lines) + "\n").encode(), "application/x-ndjson")


class Tail:
    """파일 새 줄만 읽는다 (잘리면 처음부터). 읽은 위치는 state 에 저장 — 재시작해도 같은 줄을 두 번 세지 않는다."""

    def __init__(self, path, pos=0):
        self.path, self.pos = path, pos

    def lines(self):
        if not os.path.exists(self.path):
            return []
        if os.path.getsize(self.path) < self.pos:
            self.pos = 0
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            data = f.read()
        data = data[: data.rfind(b"\n") + 1]        # 쓰는 중인 마지막 줄은 다음 주기에
        self.pos += len(data)
        return [l for l in data.decode("utf-8", errors="replace").split("\n") if l.strip()]


MAPS = {
    "lab-access": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                   "path": {"type": "keyword"}, "status": {"type": "integer"}, "label": {"type": "keyword"},
                   "blocked": {"type": "boolean"}},
    "lab-alerts": {"timestamp": {"type": "date"},
                   "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"},
                                           "description": {"type": "keyword"}, "groups": {"type": "keyword"}}},
                   "data": {"properties": {"client_ip": {"type": "keyword"}, "method": {"type": "keyword"},
                                           "path": {"type": "keyword"}, "status": {"type": "keyword"}}},
                   "label": {"type": "keyword"}},
    "lab-ml": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "level": {"type": "keyword"},
               "label": {"type": "keyword"}, "score": {"type": "float"}},
    "lab-response": {"timestamp": {"type": "date"}, "client_ip": {"type": "keyword"}, "source": {"type": "keyword"},
                     "reason": {"type": "keyword"}, "label": {"type": "keyword"}},
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", default="/data/logs/access.log")
    p.add_argument("--alerts", default="/alerts/alerts.json")
    p.add_argument("--model", default=env("LAB_MODEL", "/lab/model/dvra_v1"))
    p.add_argument("--blocked", default="/data/blocked/ips.map")
    p.add_argument("--run", default="/data/run")
    p.add_argument("--es", default=env("LAB_ES", "http://elasticsearch:9200"))
    p.add_argument("--every", type=float, default=float(env("LAB_EVERY", "2")), help="주기 (초)")
    p.add_argument("--window", type=int, default=5, help="ML 창 (분) — 모델을 학습한 창과 같아야 한다")
    p.add_argument("--allow", default=env("LAB_ALLOW", "10.1.0.1"), help="차단하지 않을 IP (쉼표) — 헬스체크 · 모니터링")
    p.add_argument("--block-min-req", type=int, default=int(env("LAB_BLOCK_MIN_REQ", "15")),
                   help="ML 로 차단하려면 그 창 요청이 이만큼 쌓여야 한다 — 접속 직후 짧은 창 오탐 방지(대응 정책, 모델은 그대로)")
    p.add_argument("--block-groups", default=env("LAB_BLOCK_GROUPS",
                                                 "shadow_api_exploit,shadow_api_recon_burst,shadow_api_mass_exfil,lab_block"))
    a = p.parse_args()
    block_groups = {x.strip() for x in a.block_groups.split(",") if x.strip()}
    allow = {x.strip() for x in a.allow.split(",") if x.strip()}

    print(f"[명세] {F.load_spec()} · 작업 {len(F.SPEC)}", flush=True)
    meta = json.load(open(os.path.join(a.model, "model_meta.json"), encoding="utf-8"))
    model = joblib.load(os.path.join(a.model, "model.joblib"))
    FEAT, HI, MD = meta["features"], meta["threshold_high"], meta["threshold_medium"]
    os.makedirs(a.run, exist_ok=True)
    os.makedirs(os.path.dirname(a.blocked), exist_ok=True)
    if not os.path.exists(a.blocked):
        open(a.blocked, "w").close()
    events = open(os.path.join(a.run, "events.jsonl"), "a", encoding="utf-8")
    labels = Labels(os.path.join(a.run, "labels.jsonl"))
    state_path = os.path.join(a.run, "pipeline_state.json")
    st = json.load(open(state_path)) if os.path.exists(state_path) else {}

    for idx, m in MAPS.items():                      # 이미 있으면 그대로 (재시작해도 데이터 유지)
        es("PUT", f"{a.es}/{idx}", json.dumps({"settings": {"number_of_replicas": 0, "refresh_interval": "2s"},
                                               "mappings": {"properties": m}}).encode())

    blocked = {}
    for l in open(a.blocked, encoding="utf-8"):
        if l.strip():
            blocked[l.split()[0]] = "(시작 전부터)"

    def emit(ev):
        events.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def block(ip, source, reason, detail):
        if ip in blocked:
            return
        now = time.time()
        if ip in allow:                              # 허용 목록 — 차단하지 않고 기록만 (한 번)
            blocked[ip] = "(허용 목록 — 차단 안 함)"
            emit({"type": "allowlisted", "timestamp": iso(now), "client_ip": ip, "source": source,
                  "reason": reason, "detail": detail})
            print(f"[허용 목록] {ip} ← {source}: {reason} — 차단하지 않음", flush=True)
            return
        blocked[ip] = reason
        with open(a.blocked, "a", encoding="utf-8") as f:
            f.write(f"{ip} 1;\n")
        ev = {"timestamp": iso(now), "client_ip": ip, "source": source, "reason": reason, "detail": detail,
              "label": labels.get(ip)}
        bulk(a.es, "lab-response", [ev])
        emit({"type": "block", **ev})
        print(f"[차단] {ip} ← {source}: {reason} ({detail})", flush=True)

    acc, alr = Tail(a.log, st.get("access", 0)), Tail(a.alerts, st.get("alerts", 0))
    ml_seen = {}                   # (ip, 창) → 마지막으로 기록한 판정
    print(f"[시작] 모델 {a.model} (학습 창 {meta.get('n_windows')}) · high<{HI} · medium<{MD} · "
          f"차단: ML high(요청 {a.block_min_req}+) / 룰 그룹 {sorted(block_groups)} · 허용 {sorted(allow)}", flush=True)
    rows = []

    def step():
        nonlocal rows
        # ① 접속 로그
        docs = []
        for line in acc.lines():
            m = LINE.match(line)
            if not m:
                continue
            ip, ts, meth, url, code, _, ua = m.groups()
            try:
                t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                continue
            path, _, q = url.partition("?")
            rows.append((ip, t, meth, path, int(code), ua, q))
            docs.append({"timestamp": iso(t), "client_ip": ip, "method": meth, "path": path, "status": int(code),
                         "label": labels.get(ip), "blocked": ip in blocked and int(code) == 403})
        bulk(a.es, "lab-access", docs)

        # ② Wazuh 경보 — 사용자 룰(100000~199999)만. 기본 룰(웹 400 오류 등)은 이 연습장의 대상이 아니다
        adocs = []
        for line in alr.lines():
            try:
                al = json.loads(line)
                rid = int(al.get("rule", {}).get("id", 0))
            except ValueError:
                continue
            if not 100000 <= rid < 200000:
                continue
            g = al["rule"].get("groups", [])
            d = al.get("data", {})
            ip = d.get("srcip", "")
            try:
                t = datetime.strptime(al.get("timestamp", ""), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
            except ValueError:
                t = time.time()
            doc = {"timestamp": iso(t), "rule": {k: al["rule"].get(k) for k in ("id", "level", "description", "groups")},
                   "data": {"client_ip": ip, "method": d.get("protocol", ""), "path": (d.get("url", "") or "").split("?")[0],
                            "status": d.get("id", "")},
                   "label": labels.get(ip)}
            adocs.append(doc)
            emit({"type": "alert", **doc})
            hit = block_groups & set(g)
            if ip and hit:
                block(ip, "룰", f"{sorted(hit)[0]} (레벨 {al['rule'].get('level')})", doc["data"]["path"])
        bulk(a.es, "lab-alerts", adocs)

        # ③ ML — 최근 두 창만 채점 (지난 창은 끝난 값으로 고정됨)
        if rows:
            now = time.time()
            recent = [r for r in rows if r[1] >= now - 2 * a.window * 60]
            mdocs, ids = [], []
            for ip, start, ft in F.windows(recent, a.window, 5):
                s = float(model.decision_function(np.array([[ft[k] for k in FEAT]]))[0])
                lvl = "high" if s < HI else "medium" if s < MD else "-"
                key = f"{ip}-{int(start)}"
                mdocs.append({"timestamp": iso(start), "client_ip": ip, "score": round(s, 5), "level": lvl,
                              "n_req": ft["n_req"], "seq_id_run": ft["seq_id_run"], "id_span_log": round(ft["id_span_log"], 3),
                              "label": labels.get(ip)})
                ids.append(key)
                if lvl != "-" and ml_seen.get(key) != lvl:
                    ml_seen[key] = lvl
                    emit({"type": "ml", "timestamp": iso(now), "window_start": iso(start), "client_ip": ip, "level": lvl,
                          "score": round(s, 5), "n_req": ft["n_req"], "seq_id_run": ft["seq_id_run"], "label": labels.get(ip)})
                if lvl == "high" and ft["n_req"] >= a.block_min_req:
                    block(ip, "ML", "BOLA 의심 (high)", f"점수 {s:.3f} · 요청 {ft['n_req']} · 연속 ID {ft['seq_id_run']}")
            bulk(a.es, "lab-ml", mdocs, ids)
            rows = [r for r in rows if r[1] >= now - 3 * a.window * 60]
        events.flush()
        json.dump({"access": acc.pos, "alerts": alr.pos}, open(state_path, "w"))

    while True:
        try:
            step()
        except Exception as e:                      # 한 번 실패해도 멈추지 않게
            print(f"[오류 — 다음 주기에 계속] {type(e).__name__}: {e}", flush=True)
        time.sleep(a.every)


if __name__ == "__main__":
    main()
