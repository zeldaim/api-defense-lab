#!/usr/bin/with-contenv bash
# 0-wazuh-init(설정 파일 준비) 뒤, 2-manager(시작) 전에 실행된다.
set -e
CONF=/var/ossec/etc/ossec.conf

# ① 취약점 탐지 끄기 (필수) — 켜 두면 CVE 데이터를 내려받아 /var/ossec/queue/vd 가 몇 GB 씩 커진다.
#    2026-11-18 작성자 PC 에서 컨테이너가 16GB 까지 커져 디스크가 가득 차고 Docker 가 멈췄다.
sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/ s#<enabled>yes</enabled>#<enabled>no</enabled>#' "$CONF"
sed -i '/<indexer>/,/<\/indexer>/ s#<enabled>yes</enabled>#<enabled>no</enabled>#' "$CONF"
rm -rf /var/ossec/queue/vd/* 2>/dev/null || true

# ② 접속 로그를 실시간으로 읽기 (한 번만 추가)
grep -q '/data/logs/access.log' "$CONF" || cat /lab/localfile.xml >> "$CONF"

# ③ 룰: rules/wazuh/*.xml (사용자 룰 포함) 을 그대로 넣는다
rm -f /var/ossec/etc/rules/lab_*.xml
for f in /lab/rules/*.xml; do
  [ -e "$f" ] || continue
  cp "$f" "/var/ossec/etc/rules/lab_$(basename "$f")"
  echo "[lab] 룰 적용: $(basename "$f")"
done
chown wazuh:wazuh /var/ossec/etc/rules/lab_*.xml 2>/dev/null || true
echo "[lab] 취약점 탐지 끔 · 접속 로그 /data/logs/access.log 실시간"
