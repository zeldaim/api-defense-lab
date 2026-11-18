#!/usr/bin/env python3
"""내 모델 학습 — 연습장 접속 로그에서 '정상'으로 라벨된 IP 의 창만 골라 IsolationForest 를 학습한다.

  docker compose run --rm traffic normal --users 30 --rounds 130      # 학습용 정상 트래픽 (약 1시간)
  docker compose run --rm trainer                                     # → model/mine/
  LAB_MODEL=/lab/model/mine docker compose up -d detector             # 내 모델로 바꿔 끼우기

동봉 모델(model/dvra_v1)도 같은 방법으로 만들었다: DVRA 정상 73분 · 창 365개 · 5분 창.
학습 규칙: 오류 비율 0.3 이상 · 요청 1500 이상(스캐너) 창과 명세 밖 호출이 있는 창(룰이 이미 잡음)은 뺀다.
임계값: 학습 창 점수의 0.5 백분위 = high, 2 백분위 = medium.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import features as F  # noqa: E402

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="/data/logs/access.log")
    ap.add_argument("--labels", default="/data/run/labels.jsonl")
    ap.add_argument("--out", default="/lab/model/mine")
    ap.add_argument("--window", type=int, default=5, help="창 (분) — detector 의 --window 와 같아야 한다")
    ap.add_argument("--contamination", type=float, default=0.01)
    ap.add_argument("--max-err", type=float, default=0.3)
    ap.add_argument("--max-req", type=int, default=1500)
    ap.add_argument("--min-windows", type=int, default=50)
    a = ap.parse_args()

    F.load_spec()
    normal = set()
    for l in open(a.labels, encoding="utf-8"):
        d = json.loads(l)
        if d["role"] == "normal":
            normal.add(d["ip"])
    rows = [r for r in F.parse(a.log) if r[0] in normal]
    wins = list(F.windows(rows, a.window, 5))
    keep = [ft for _, _, ft in wins if ft["err_ratio"] < a.max_err and ft["n_req"] < a.max_req and ft["offspec_ratio"] == 0]
    print(f"[train] 정상 IP {len(normal)} · 요청 {len(rows)} → 창 {len(wins)} → 학습 {len(keep)} (스캐너 · 명세 밖 창 제외)")
    if len(keep) < a.min_windows:
        sys.exit(f"학습 창이 {len(keep)}개뿐 — {a.min_windows}개 이상 필요 (정상 트래픽을 더 길게: traffic normal --rounds 130)")
    X = np.array([[ft[k] for k in F.FEATURES] for ft in keep])
    m = IsolationForest(n_estimators=300, contamination=a.contamination, random_state=42).fit(X)
    s = m.decision_function(X)
    os.makedirs(a.out, exist_ok=True)
    joblib.dump(m, os.path.join(a.out, "model.joblib"))
    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "sklearn IsolationForest(n_estimators=300, random_state=42)",
        "contamination": a.contamination, "source": f"api-defense-lab {a.log} (정상 라벨 IP {len(normal)}개)",
        "window_min": a.window, "n_windows": len(keep), "n_windows_total": len(wins),
        "features": F.FEATURES,
        "threshold_high": round(float(np.percentile(s, 0.5)), 5),
        "threshold_medium": round(float(np.percentile(s, 2.0)), 5),
        "train_p99": [round(float(v), 4) for v in np.percentile(X, 99, axis=0)],
        "feature_version": "2.1",
    }
    json.dump(meta, open(os.path.join(a.out, "model_meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"[train] 창 {len(keep)}개 학습 · high<{meta['threshold_high']} medium<{meta['threshold_medium']} → {a.out}")


if __name__ == "__main__":
    main()
