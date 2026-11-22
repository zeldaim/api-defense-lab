#!/usr/bin/env bash
# 레이트 리밋 비교 실험 (docs/rate-limit.md) — 조건마다 새 볼륨, 별도 프로젝트 이름 rlx
#   A 탐지·차단만   B 레이트 리밋만   C 레이트 리밋 + 탐지·차단
#   D 느린 BOLA · 레이트 리밋만   E 느린 BOLA · 레이트 리밋 + 탐지·차단
# 사용: bash docs/results/rate-limit_2026-11-22/run.sh <결과 폴더>    (조건 하나 약 12분, 전부 약 1시간)
set -uo pipefail
export MSYS_NO_PATHCONV=1                 # Git Bash 경로 변환 끄기 (Linux · macOS 에선 영향 없음)
OUT=$(mkdir -p "${1:?결과 폴더}" && cd "$1" && pwd)
cd "$(dirname "$0")/../../.."             # 레포 루트
RATE=30r/m                                 # 0.5 req/s, burst 10
SLOW=2.5                                   # 느린 BOLA 간격(초) = 0.4 req/s → 제한 아래
NOBLOCK="LAB_BLOCK_GROUPS=none LAB_BLOCK_MIN_REQ=999999"   # 탐지는 하되 차단은 안 함
dc() { docker compose -p rlx "$@"; }

run_cond() {  # $1 이름  $2 env  $3 fast|slow
  local name=$1 envs=$2 kind=$3
  echo "=== [$name] $(date +%T) env: ${envs:-없음} · $kind"
  dc --profile "*" down -v >/dev/null 2>&1
  unset LAB_RATE LAB_BURST LAB_BLOCK_GROUPS LAB_BLOCK_MIN_REQ
  # export 필수: `compose run traffic` 도 같은 env 로 계산해야 한다.
  # 안 그러면 compose 가 nginx 를 env 없이 다시 만들어 레이트 리밋이 꺼진다 (1회차가 이렇게 무효가 됨).
  for kv in $envs; do export "$kv"; done
  dc up -d --build >/dev/null 2>&1
  for _ in $(seq 1 60); do dc ps detector --format '{{.Status}}' | grep -q Up && break; sleep 2; done
  sleep 10
  if [ "$kind" = fast ]; then
    dc run --rm traffic demo > "$OUT/${name}_traffic.log" 2>&1
  else
    dc run --rm traffic normal --rounds 30 > "$OUT/${name}_normal.log" 2>&1 &
    local np=$!
    sleep 60
    dc run --rm traffic attack bola --delay $SLOW > "$OUT/${name}_traffic.log" 2>&1
    wait $np
  fi
  sleep 70                                 # 채점 GRACE(60초) 동안 늦은 탐지까지
  dc run --rm scorer > "$OUT/${name}_score.txt" 2>&1
  cp reports/score.json "$OUT/${name}_score.json"
  dc logs nginx > "$OUT/${name}_nginx.log" 2>&1
  dc logs detector > "$OUT/${name}_detector.log" 2>&1
  echo "    nginx '레이트 리밋 켬' 줄: $(grep -c '레이트 리밋 켬' "$OUT/${name}_nginx.log") · nginx 재생성: $(grep -c Recreate "$OUT/${name}_traffic.log")"
}

run_cond A_baseline       ""                          fast
run_cond B_ratelimit      "LAB_RATE=$RATE $NOBLOCK"   fast
run_cond C_rl_detect      "LAB_RATE=$RATE"            fast
run_cond D_slow_rl        "LAB_RATE=$RATE $NOBLOCK"   slow
run_cond E_slow_rl_detect "LAB_RATE=$RATE"            slow
dc --profile "*" down -v >/dev/null 2>&1
echo "끝 — $OUT"
