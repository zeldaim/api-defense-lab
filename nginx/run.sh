#!/bin/sh
# 차단 목록이 바뀌면 nginx 를 다시 읽힌다 (1초마다 확인)
set -e
mkdir -p /data/logs /data/blocked
touch /data/logs/access.log /data/blocked/ips.map
# 레이트 리밋 (선택): LAB_RATE=30r/m 처럼 주면 출발지($client)마다 제한, 넘친 요청은 429. 비어 있으면 꺼짐(기본).
mkdir -p /etc/nginx/lab
if [ -n "${LAB_RATE:-}" ]; then
  echo "limit_req_zone \$client zone=lab_perip:10m rate=${LAB_RATE}; limit_req_status 429; limit_req_log_level warn;" > /etc/nginx/lab/ratelimit_http.conf
  echo "limit_req zone=lab_perip burst=${LAB_BURST:-10} nodelay;" > /etc/nginx/lab/ratelimit_location.conf
  echo "[nginx] 레이트 리밋 켬: ${LAB_RATE} · burst ${LAB_BURST:-10} (출발지마다, 넘치면 429)"
else
  : > /etc/nginx/lab/ratelimit_http.conf
  : > /etc/nginx/lab/ratelimit_location.conf
fi
nginx
old=""
while sleep 1; do
  new=$(md5sum /data/blocked/ips.map)
  if [ "$new" != "$old" ]; then
    [ -n "$old" ] && nginx -s reload && echo "[nginx] 차단 목록 다시 읽음: $(wc -l < /data/blocked/ips.map) IP"
    old=$new
  fi
done
