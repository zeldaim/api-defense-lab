#!/usr/bin/env python3
"""rules/wazuh 룰을 실제 Wazuh manager 의 wazuh-logtest 로 — cases.json 의 정답 단계와 같은지.
  python tests/detection/test_wazuh.py <wazuh 컨테이너 이름>
컨테이너는 이 저장소의 wazuh 이미지(룰 · 디코더 적용)로 떠 있어야 한다. 사례마다 logtest 를 새로 돌려 상태가 섞이지 않게 한다.
"""
import json
import os
import re
import subprocess
import sys

LEVEL = {"100510": "L1", "100511": "L2", "100512": "L3", "100513": "L3E"}


def logtest(container, line):
    # 로그 줄은 환경변수로 넘겨 컨테이너 안에서 파이프한다 — `docker exec -i` 로 표준입력을 주면
    # Windows 에서 입력 끝(EOF)이 전달되지 않아 wazuh-logtest 가 다음 줄을 계속 기다린다 (작성 중 실제로 멈춤)
    r = subprocess.run(["docker", "exec", "-e", f"L={line}", container, "sh", "-c",
                        'printf "%s\\n" "$L" | /var/ossec/bin/wazuh-logtest'],
                       capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr          # wazuh-logtest 는 결과를 stderr 로 쓴다 (stdout 만 보면 늘 비어 '경보 없음'으로 오판)
    if "**Phase 2" not in out:         # 디코딩조차 안 됐으면 시험 자체가 잘못된 것 — 통과로 치지 않는다
        raise SystemExit(f"logtest 출력 이상 (rc={r.returncode}):\n{out[-800:]}")
    phase3 = out.split("**Phase 3", 1)[-1] if "**Phase 3" in out else ""
    ids = re.findall(r"id: '(\d+)'", phase3)
    return ids[-1] if ids else None, out


def main():
    container = sys.argv[1]
    cases = json.load(open(os.path.join(os.path.dirname(__file__), "cases.json"), encoding="utf-8"))
    fails = 0
    for c in cases:
        rid, raw = logtest(container, c["line"])
        got = LEVEL.get(rid, "none")
        ok = got == c["expect"]
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']}  (기대 {c['expect']} · Wazuh 룰 {rid} → {got})")
        if not ok:
            print(raw[-800:])
    print(f"\n{'모두 통과' if not fails else f'실패 {fails}건'} — 사례 {len(cases)}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
