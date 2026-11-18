# detector · traffic · scorer · trainer 가 함께 쓰는 이미지 (버전 고정 — 모델 파일은 scikit-learn 1.5.2 로 저장됨)
FROM python:3.12-slim
RUN pip install --no-cache-dir numpy==2.1.3 scikit-learn==1.5.2 joblib==1.4.2 pyyaml==6.0.2
WORKDIR /lab
COPY detector/ /lab/detector/
COPY traffic/ /lab/traffic/
COPY scorer/ /lab/scorer/
COPY spec/ /lab/spec/
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8 \
    E2E_SPEC=/lab/spec/dvra_openapi.json \
    E2E_BOLA_TARGETS="/orders/{order_id},/orders/status/{order_id}"
