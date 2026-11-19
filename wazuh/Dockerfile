# Wazuh manager — 연습장용. 접속 로그를 실시간으로 읽어 rules/wazuh/*.xml 로 판정한다.
FROM wazuh/wazuh-manager:4.14.9@sha256:9d07740f780024600101d759ddab9a4413bdcb3412ccb81dccc143b3cdc702a2
COPY lab-init.sh /etc/cont-init.d/1-lab-config
COPY localfile.xml /lab/localfile.xml
# filebeat(경보 → Wazuh indexer)는 쓰지 않는다 — 경보는 alerts.json 을 detector 가 직접 읽는다
RUN chmod 755 /etc/cont-init.d/1-lab-config && rm -rf /etc/services.d/filebeat
