#!/bin/sh
# 차단 목록이 바뀌면 nginx 를 다시 읽힌다 (1초마다 확인)
set -e
mkdir -p /data/logs /data/blocked
touch /data/logs/access.log /data/blocked/ips.map
nginx
old=""
while sleep 1; do
  new=$(md5sum /data/blocked/ips.map)
  if [ "$new" != "$old" ]; then
    [ -n "$old" ] && nginx -s reload && echo "[nginx] 차단 목록 다시 읽음: $(wc -l < /data/blocked/ips.map) IP"
    old=$new
  fi
done
