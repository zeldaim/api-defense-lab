# [모듈 inventory] 트래픽 기록(mitmproxy 역방향 프록시) + 실제 쓰이는 API 명세 만들기(mitmproxy2swagger) + 공식 명세와 대조
# 버전 고정. root 로 돌지 않는다 (Trivy 설정 검사 AVD-DS-0002).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN pip install --no-cache-dir mitmproxy==12.3.1 mitmproxy2swagger==0.15.0 \
 && useradd --create-home --uid 10001 lab \
 && mkdir -p /inv && chown lab:lab /inv
WORKDIR /lab
COPY inventory/discover.py /lab/inventory/discover.py
COPY tools/gen_sigma.py /lab/tools/gen_sigma.py
COPY spec/ /lab/spec/
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
USER lab
