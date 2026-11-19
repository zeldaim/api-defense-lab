#!/usr/bin/env python3
"""inventory 모듈 시험 — 기록 고정본(fixture.mitm)으로 discover.py 를 돌려 정답과 맞춘다.

  docker build -f inventory/Dockerfile -t lab-inventory .
  docker run --rm -v "$PWD:/r:ro" -w /r lab-inventory python tests/inventory/test_inventory.py

fixture.mitm: 정상 3명 · 4회 + 허용 목록 IP(10.1.0.1)의 탐색 15곳 — 차단 없이 앱이 실제로 답한 기록 (2026-11-19).
토큰 · 가입 · 로그인 본문과 /debug 응답(DVRA 가 컨테이너 환경 변수를 그대로 내놓음)은 지웠다.
기대: 숨은 API 3개를 전부 Shadow 로 · 그 밖의 Shadow 0 · /orders/export(422) 는 Shadow 가 아니라 '명세 경로 + 잘못된 값'
      · 관측 명세로 만든 Sigma 룰이 /orders/abc(명세 형식 위반)를 L3 로 본다 (경로 파라미터 integer 보정)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))


def main():
    out = tempfile.mkdtemp()
    r = subprocess.run([sys.executable, os.path.join(ROOT, "inventory", "discover.py"), "--flows", os.path.join(HERE, "fixture.mitm"),
                        "--spec", os.path.join(ROOT, "spec", "dvra_openapi.json"), "--out", out, "--sigma"],
                       capture_output=True, text=True)
    print(r.stdout)
    if r.returncode:
        print(r.stderr)
        sys.exit("discover.py 실패")
    res = json.load(open(os.path.join(out, "inventory.json"), encoding="utf-8"))
    fails = []

    def check(ok, msg):
        print(("PASS  " if ok else "FAIL  ") + msg)
        if not ok:
            fails.append(msg)

    check(all(x["result"] == "found" for x in res["hidden_api_answer"]), "숨은 API 3개 모두 Shadow 로 찾음")
    shadow = sorted((e["method"], e["path"]) for e in res["endpoints"] if e["kind"] == "shadow")
    hidden = sorted((x["method"], x["path"]) for x in res["hidden_api_answer"])
    check(shadow == hidden, f"Shadow 는 숨은 API 3개뿐 (실제 {shadow})")
    kinds = {(e["method"], e["path"]): e["kind"] for e in res["endpoints"]}
    check(kinds.get(("GET", "/orders/export")) == "param-error", "/orders/export 422 → 명세 경로 + 잘못된 값 (Shadow 아님)")
    check(res["flows"]["blocked_by_lab"] == 0, "고정본에는 연습장 차단 응답이 없다")

    import gen_sigma  # noqa: E402 — 표준 라이브러리만
    ops, _ = gen_sigma.spec_ops(os.path.join(out, "observed_openapi.json"))
    import re
    get_rx = [re.compile("^(?:" + x + ")/*$") for x in ops.get("GET", [])]
    check(not any(x.match("/orders/abc") for x in get_rx), "관측 명세 룰: /orders/abc 는 명세 밖 (integer 보정)")
    check(any(x.match("/orders/12") for x in get_rx), "관측 명세 룰: /orders/12 는 명세 안")
    check(os.path.exists(os.path.join(out, "sigma", "shadow_api_l3_exploit.yml")), "Sigma 룰 파일 생성")

    print(f"\n{'실패 ' + str(len(fails)) + '건' if fails else '전부 통과'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
