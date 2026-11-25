#!/usr/bin/env bash
# 허니 API 시연 기록 (docs/honey-api.md) — 코어만, 깨끗한 상태에서
#   bash docs/results/honey-api_2026-11-25/run.sh <결과 폴더>
set -uo pipefail
export MSYS_NO_PATHCONV=1
OUT=$(mkdir -p "${1:?결과 폴더}" && cd "$1" && pwd)
cd "$(dirname "$0")/../../.."
dc() { docker compose "$@"; }

echo "=== 초기화 ==="; dc down -v >/dev/null 2>&1
dc up -d --build > "$OUT/up.log" 2>&1

echo "=== 1) 정상 사용자 + 화면 번들 (오탐 시험) ==="
dc run --rm traffic normal --users 15 --rounds 8 --pause 0.3 --bundle > "$OUT/1_normal_bundle.log" 2>&1

echo "=== 2) 허니 에이전트 — ua-changed (UA 정상, 번들에서 경로 수집) ==="
dc run --rm traffic attack agent --variant ua-changed --honey --ip 10.88.0.210 > "$OUT/2_agent_honey_ua-changed.log" 2>&1

echo "=== 3) 허니 에이전트 — slow (경로마다 6~12초, 401 순회 빈도 룰은 못 잡는 변형) ==="
dc run --rm traffic attack agent --variant slow --honey --ip 10.88.0.211 > "$OUT/3_agent_honey_slow.log" 2>&1

echo "=== 채점 ==="
dc run --rm scorer > "$OUT/4_score.txt" 2>&1
dc logs detector > "$OUT/5_detector.log" 2>&1
dc logs nginx > "$OUT/6_nginx.log" 2>&1
cp reports/score.json "$OUT/score.json" 2>/dev/null || true
dc down -v > "$OUT/down.log" 2>&1
echo "완료 → $OUT"
