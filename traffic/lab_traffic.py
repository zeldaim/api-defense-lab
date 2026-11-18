#!/usr/bin/env python3
"""연습장 트래픽 생성기 — 정상 사용자와 공격을 nginx 앞단으로 보내고, 정답지(labels.jsonl)를 남긴다.
합성 트래픽이다 (실제 사용자 아님). 출발지는 X-Client-IP 헤더로 흉내 낸다 — 연습장 전용 단순화.

  normal [--users 20 --rounds 45 --pause 1.0]   정상: 가입 · 로그인 · 메뉴 · 주문 · 내 주문 · 내 정보 (IP 10.10.0.x)
  attack probe [--ip 10.66.0.N]                 명세 밖 탐색 15곳 — 숨은 API 3개 포함 (IP 기본 10.66.0.x 무작위)
  attack bola  [--n 150] [--ip 10.77.0.N]       명세 안 BOLA — 남의 주문 1..n 열거 (IP 기본 10.77.0.x 무작위)
  demo                                          정상 20명 · 30회 + 60초 뒤 탐색 + 150초 뒤 BOLA (약 10분)

정답지 한 줄 = {"run", "ip", "role", "scenario", "start", "end"} (end 가 null 이면 아직 진행 중).
표준 라이브러리만 쓴다.
"""
import argparse
import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("LAB_TARGET", "http://nginx")
LABELS = os.environ.get("LAB_LABELS", "/data/run/labels.jsonl")
RUN = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{random.randint(0, 0xffff):04x}"
PW = "Passw0rd!x"
_lock = threading.Lock()


def iso(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).isoformat()


def label(ip, role, scenario, start, end=None):
    with _lock:
        os.makedirs(os.path.dirname(LABELS), exist_ok=True)
        with open(LABELS, "a", encoding="utf-8") as f:
            f.write(json.dumps({"run": RUN, "ip": ip, "role": role, "scenario": scenario,
                                "start": iso(start), "end": iso(end) if end else None}) + "\n")


def _req(method, path, ip, body=None, token=None, form=False):
    h = {"X-Client-IP": ip, "User-Agent": "Mozilla/5.0 (api-defense-lab)"}
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        return 0, str(e)


class User:
    """계정 하나. DVRA 토큰은 30분이면 만료된다 → 401 이 오면 사람처럼 다시 로그인하고 한 번 더 보낸다."""

    def __init__(self, ip, name):
        self.ip, self.name, self.token, self.orders = ip, name, None, []
        _req("POST", "/register", ip, {"username": name, "password": PW, "phone_number": self._phone(),
                                       "first_name": name, "last_name": "test"})
        self.login()

    def _phone(self):                                 # 앱이 전화번호 중복을 막는다 → 이름 + 실행마다 다른 번호
        return "010-%04d-%04d" % (random.randint(0, 9999), random.randint(0, 9999))

    def login(self):
        st, body = _req("POST", "/token", self.ip, {"username": self.name, "password": PW}, form=True)
        try:
            self.token = json.loads(body)["access_token"]
        except (ValueError, KeyError):
            self.token = None

    def req(self, method, path, body=None):
        st, b = _req(method, path, self.ip, body, self.token)
        if st == 401 and self.token:
            self.login()
            st, b = _req(method, path, self.ip, body, self.token)
        return st, b

    def order(self):
        st, body = self.req("POST", "/orders", {"delivery_address": "Seoul", "phone_number": "010-1111-2222",
                                                "items": [{"menu_item_id": random.randint(1, 5), "quantity": 1}]})
        try:
            self.orders.append(json.loads(body)["id"])
        except (ValueError, KeyError):
            pass


def normal(users=20, rounds=45, pause=1.0, scenario="normal"):
    t0 = time.time()
    ips = [f"10.10.0.{i + 1}" for i in range(users)]
    for ip in ips:
        label(ip, "normal", scenario, t0)
    accts = []
    for i, ip in enumerate(ips):
        u = User(ip, f"guest{i + 1:02d}")
        u.order()
        accts.append(u)
    for r in range(rounds):
        for u in accts:
            steps = [("GET", "/menu"), ("GET", "/orders"), ("GET", "/profile")]
            if u.orders:
                oid = random.choice(u.orders)
                steps += [("GET", f"/orders/{oid}"), ("GET", f"/orders/status/{oid}")]
            random.shuffle(steps)
            for m, p in steps[: random.randint(2, 4)]:
                u.req(m, p)
            if random.random() < 0.15:
                u.order()
            time.sleep(pause)
        if (r + 1) % 10 == 0:
            print(f"[정상] {r + 1}/{rounds}회", flush=True)
    _req("GET", "/docs", ips[0])                     # 개발자가 문서 화면을 연다 (현실적인 정상 행동)
    _req("GET", "/openapi.json", ips[0])
    t1 = time.time()
    for ip in ips:
        label(ip, "normal", scenario, t0, t1)
    print(f"[정상] 끝: 사용자 {users} · {rounds}회 · {t1 - t0:.0f}초", flush=True)


PROBES = [  # 숨은 API 3개(앱 소스에서 include_in_schema=False) + 흔한 탐색 경로
    ("GET", "/debug"), ("GET", "/delivery/orders"), ("GET", "/admin/reset-chef-password"),
    ("GET", "/admin"), ("GET", "/api/v1/users"), ("GET", "/swagger.json"), ("GET", "/actuator/health"),
    ("GET", "/orders/export"), ("GET", "/menu/abc"), ("GET", "/users"), ("POST", "/menu"), ("DELETE", "/orders/1"),
    ("GET", "/backup.zip"), ("GET", "/admin/stats/memory"), ("GET", "/internal/metrics"),
]


def pick_ip(prefix, ip):
    return ip or f"{prefix}.{random.randint(2, 254)}"


def probe(ip=None, scenario="probe"):
    ip = pick_ip("10.66.0", ip)
    t0 = time.time()
    label(ip, "probe", scenario, t0)
    print(f"[탐색] 출발지 {ip} — 명세 밖 {len(PROBES)}곳", flush=True)
    u = User(ip, f"prober_{ip.split('.')[-1]}")
    for m, p in PROBES:
        st, _ = u.req(m, p)
        print(f"  {m} {p} -> {st}", flush=True)
        time.sleep(0.5)
    label(ip, "probe", scenario, t0, time.time())
    print(f"[탐색] 끝 ({time.time() - t0:.1f}초)", flush=True)


def bola(n=150, ip=None, scenario="bola"):
    ip = pick_ip("10.77.0", ip)
    t0 = time.time()
    label(ip, "bola", scenario, t0)
    print(f"[BOLA] 출발지 {ip} — 남의 주문 1..{n}", flush=True)
    u = User(ip, f"attacker_{ip.split('.')[-1]}")
    first403, ok = None, 0
    for oid in range(1, n + 1):
        st, _ = u.req("GET", f"/orders/{oid}")
        ok += 200 <= st < 300
        if st == 403 and first403 is None:
            first403 = oid
            print(f"  *** 차단됨: 주문 {oid} 부터 403 ({time.time() - t0:.1f}초) ***", flush=True)
        if oid % 10 == 0:
            print(f"  주문 {oid} -> {st}", flush=True)
        time.sleep(0.4)
    label(ip, "bola", scenario, t0, time.time())
    print(f"[BOLA] 끝: 열거 {n}건 · 성공(2xx) {ok} · 첫 403 = {first403}", flush=True)


def demo():
    print("[데모] 정상 20명 시작 → 60초 뒤 탐색 → 150초 뒤 BOLA (약 10분)", flush=True)
    th = threading.Thread(target=normal, kwargs={"users": 20, "rounds": 30, "pause": 1.0, "scenario": "demo"})
    th.start()
    time.sleep(60)
    probe(scenario="demo")
    time.sleep(90)
    bola(scenario="demo")
    th.join()
    print("[데모] 끝 — 채점: docker compose run --rm scorer", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    n = sp.add_parser("normal")
    n.add_argument("--users", type=int, default=20)
    n.add_argument("--rounds", type=int, default=45)
    n.add_argument("--pause", type=float, default=1.0)
    at = sp.add_parser("attack")
    at.add_argument("kind", choices=["probe", "bola"])
    at.add_argument("--ip")
    at.add_argument("--n", type=int, default=150)
    sp.add_parser("demo")
    a = ap.parse_args()
    print(f"[실행 {RUN}] 대상 {BASE} · 정답지 {LABELS}", flush=True)
    if a.cmd == "normal":
        normal(a.users, a.rounds, a.pause)
    elif a.cmd == "attack":
        probe(a.ip) if a.kind == "probe" else bola(a.n, a.ip)
    else:
        demo()


if __name__ == "__main__":
    main()
