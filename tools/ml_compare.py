#!/usr/bin/env python3
"""ML 모델 비교 — 같은 학습 데이터 · 같은 평가 트래픽 · 같은 임계값 규칙 · 같은 차단 정책으로 여러 모델을 채점한다.

  python tools/ml_compare.py --train <정상 접속 로그> --eval <평가 폴더> --out <결과 폴더> [--save-models model/cmp]

평가 폴더: <이름>_access.log · <이름>_labels.jsonl 쌍 (차단을 끄고 돌린 연습장 실행 — 공격이 끝까지 기록됨).
이름이 slow 로 시작하면 '느린 BOLA' 실행으로 따로 묶는다.

live detector 흉내: detector 는 2초마다 '지금 진행 중인 5분 창'을 다시 채점한다. 여기서는 요청이 하나 올 때마다
그 창의 지금까지 요청으로 채점한다 (모든 모델에 같은 방식). 처음으로 'high 이고 그 창 요청 15건 이상'이 되는
순간 = 차단. 그 순간까지 받은 2xx(가입 · 로그인 제외) = 새어 나간 성공.

임계값: 모든 모델이 학습 창 점수의 0.5 백분위 = high, 2 백분위 = medium (detector/train.py 와 같은 규칙).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "detector"))
import features as F  # noqa: E402
import joblib  # noqa: E402
import numpy as np  # noqa: E402
from models_extra import make_models  # noqa: E402

WINDOW_MIN, MIN_REQ, BLOCK_MIN_REQ = 5, 5, 15
AUTH = {("POST", "/register"), ("POST", "/token")}


def train_windows(path, start_min=None, start_max=None):
    """start_min/max: 창 시작 시각(epoch) 범위 — dvra_v1 은 model_meta.json 의 train_window_start_min/max 범위만 썼다."""
    rows = F.parse(path)
    wins = [w for w in F.windows(rows, WINDOW_MIN, MIN_REQ)
            if (start_min is None or w[1] >= start_min) and (start_max is None or w[1] <= start_max)]
    keep = [ft for _, _, ft in wins if ft["err_ratio"] < 0.3 and ft["n_req"] < 1500 and ft["offspec_ratio"] == 0]
    return np.array([[ft[k] for k in F.FEATURES] for ft in keep]), len(wins)


def prefixes(reqs):
    """한 IP 요청 → (요청, 그 순간 진행 중인 창의 특징) 목록. 창에 요청이 MIN_REQ 미만이면 특징 없음."""
    out, cur, bucket = [], [], None
    for r in reqs:
        b = int(r[1] // (WINDOW_MIN * 60))
        if b != bucket:
            cur, bucket = [], b
        cur.append(r)
        out.append((r, F.featurize(list(cur)) if len(cur) >= MIN_REQ else None))
    return out


def load_run(access, labels):
    role, start = {}, {}
    for l in open(labels, encoding="utf-8"):
        d = json.loads(l)
        role[d["ip"]] = d["role"]
        start[d["ip"]] = min(start.get(d["ip"], d["start"]), d["start"])
    by_ip = defaultdict(list)
    for r in F.parse(access):
        if r[0] in role:
            by_ip[r[0]].append(r)
    return role, by_ip


def evaluate(model, hi, run):
    role, by_ip = run["role"], run["by_ip"]
    res = defaultdict(list)
    for ip, pref in run["prefixes"].items():
        idx = [i for i, (_, ft) in enumerate(pref) if ft is not None]
        block_i = None
        if idx:
            X = np.array([[pref[i][1][k] for k in F.FEATURES] for i in idx])
            s = model.decision_function(X)
            for j, i in enumerate(idx):
                if s[j] < hi and pref[i][1]["n_req"] >= BLOCK_MIN_REQ:
                    block_i = i
                    break
        reqs = by_ip[ip]
        upto = reqs if block_i is None else reqs[:block_i + 1]          # 차단을 부른 요청까지는 이미 응답됨
        leaked = sum(1 for r in upto if 200 <= r[4] < 300 and (r[2], r[3]) not in AUTH)
        res[role[ip]].append({"ip": ip, "blocked": block_i is not None,
                              "detect_s": round(reqs[block_i][1] - reqs[0][1], 1) if block_i is not None else None,
                              "leaked": leaked,
                              "total_ok": sum(1 for r in reqs if 200 <= r[4] < 300 and (r[2], r[3]) not in AUTH)})
    # 정상 사용자의 끝난 창 중 high 인 것 (채점표의 'ML high 창')
    normal_rows = [r for ip, rs in by_ip.items() if role[ip] == "normal" for r in rs]
    wins = list(F.windows(normal_rows, WINDOW_MIN, MIN_REQ))
    if wins:
        s = model.decision_function(np.array([[ft[k] for k in F.FEATURES] for _, _, ft in wins]))
        res["_normal_high_windows"] = int((s < hi).sum())
        res["_normal_windows"] = len(wins)
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train", required=True)
    ap.add_argument("--eval", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--save-models", help="모델별 폴더로 저장 (LAB_MODEL 로 바로 끼울 수 있게)")
    ap.add_argument("--block-min-req", type=int, default=15, help="차단 정책: 그 창 요청 몇 건 이상이어야 ML 로 차단 (detector 기본 15)")
    ap.add_argument("--like", help="이 model_meta.json 의 학습 창 범위를 그대로 (예: model/dvra_v1/model_meta.json)")
    a = ap.parse_args()
    global BLOCK_MIN_REQ
    BLOCK_MIN_REQ = a.block_min_req
    os.makedirs(a.out, exist_ok=True)
    F.load_spec()

    lo = hi_t = ref = None
    if a.like:
        ref = json.load(open(a.like, encoding="utf-8"))
        lo, hi_t = ref.get("train_window_start_min"), ref.get("train_window_start_max")
    X, n_total = train_windows(a.train, lo, hi_t)
    print(f"[학습] 창 {n_total} → {len(X)} (같은 거르기 규칙{' · 범위 ' + str(lo) + '~' + str(hi_t) if lo else ''})")
    if ref:
        print(f"[기준] {a.like}: 창 {ref.get('n_windows')} · high<{ref.get('threshold_high')} — IsolationForest 가 같게 나오면 같은 학습")

    runs = []
    for acc in sorted(glob.glob(os.path.join(a.eval, "*_access.log"))):
        name = os.path.basename(acc)[: -len("_access.log")]
        role, by_ip = load_run(acc, os.path.join(a.eval, f"{name}_labels.jsonl"))
        t0 = time.time()
        runs.append({"name": name, "slow": name.startswith("slow"), "role": role, "by_ip": by_ip,
                     "prefixes": {ip: prefixes(rs) for ip, rs in by_ip.items()}})
        print(f"[평가] {name}: IP {len(by_ip)} · 요청 {sum(map(len, by_ip.values()))} · 특징 {time.time() - t0:.1f}초")

    candidates = list(make_models().items())
    shipped = None
    if a.like and os.path.exists(os.path.join(os.path.dirname(a.like), "model.joblib")):
        # 지금 실제로 쓰는 모델 — 다시 학습하지 않고 파일 · 임계값 그대로
        shipped = "dvra_v1 (동봉 · 지금 쓰는 것)"
        candidates.insert(0, (shipped, joblib.load(os.path.join(os.path.dirname(a.like), "model.joblib"))))

    results = {}
    for name, model in candidates:
        t0 = time.time()
        if name != shipped:
            model.fit(X)
        fit_s = time.time() - t0
        s = model.decision_function(X)
        hi, md = float(np.percentile(s, 0.5)), float(np.percentile(s, 2.0))
        if name == shipped:
            hi, md = ref["threshold_high"], ref["threshold_medium"]
        t0 = time.time()
        per_run = {r["name"]: evaluate(model, hi, r) for r in runs}
        eval_s = time.time() - t0
        results[name] = {"threshold_high": round(hi, 5), "fit_s": round(fit_s, 2), "eval_s": round(eval_s, 2), "runs": per_run}
        if a.save_models and name != shipped:
            d = os.path.join(a.save_models, name.split(" ")[0].lower())
            os.makedirs(d, exist_ok=True)
            joblib.dump(model, os.path.join(d, "model.joblib"))
            json.dump({"algorithm": name, "features": F.FEATURES, "threshold_high": round(hi, 5),
                       "threshold_medium": round(md, 5), "n_windows": len(X), "feature_version": "2.1",
                       "source": "tools/ml_compare.py (dvra_v1 과 같은 학습 데이터)"},
                      open(os.path.join(d, "model_meta.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"[모델] {name}: 학습 {fit_s:.2f}초 · 평가 {eval_s:.1f}초 · high<{hi:.5f}")

    # ── 요약 ──────────────────────────────────────────
    def agg(name, slow):
        rs = [v for r in runs if r["slow"] == slow for v in results[name]["runs"][r["name"]].get("bola", [])]
        det = [x["detect_s"] for x in rs if x["blocked"]]
        return {"n": len(rs), "blocked": sum(x["blocked"] for x in rs),
                "detect_med_s": statistics.median(det) if det else None,
                "leaked": sum(x["leaked"] for x in rs), "leaked_max": sum(x["total_ok"] for x in rs)}

    summary = {}
    for name, R in results.items():
        normal = [v for r in runs for v in R["runs"][r["name"]].get("normal", [])]
        probe = [v for r in runs for v in R["runs"][r["name"]].get("probe", [])]
        summary[name] = {
            "fast_bola": agg(name, False), "slow_bola": agg(name, True),
            "probe_ml_blocked": f"{sum(x['blocked'] for x in probe)}/{len(probe)}",
            "normal_fp_blocked": f"{sum(x['blocked'] for x in normal)}/{len(normal)}",
            "normal_high_windows": f"{sum(R['runs'][r['name']].get('_normal_high_windows', 0) for r in runs)}"
                                   f"/{sum(R['runs'][r['name']].get('_normal_windows', 0) for r in runs)}",
            "threshold_high": R["threshold_high"], "fit_s": R["fit_s"],
        }
    json.dump({"summary": summary, "detail": results, "train_windows": len(X)},
              open(os.path.join(a.out, "ml_compare.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=str)

    hdr = ["모델", "빠른 BOLA 차단", "차단까지(중앙)", "새어 나감", "느린 BOLA 차단", "차단까지(중앙)", "새어 나감",
           "정상 오탐 차단", "정상 high 창", "학습"]
    lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
    for name, s in summary.items():
        f, sl = s["fast_bola"], s["slow_bola"]
        cell = lambda v: "-" if v is None else f"{v}초"
        lines.append(f"| {name} | {f['blocked']}/{f['n']} | {cell(f['detect_med_s'])} | {f['leaked']}/{f['leaked_max']} | "
                     f"{sl['blocked']}/{sl['n']} | {cell(sl['detect_med_s'])} | {sl['leaked']}/{sl['leaked_max']} | "
                     f"{s['normal_fp_blocked']} | {s['normal_high_windows']} | {s['fit_s']}초 |")
    table = "\n".join(lines)
    open(os.path.join(a.out, "ml_compare.md"), "w", encoding="utf-8").write(table + "\n")
    print("\n" + table)


if __name__ == "__main__":
    main()
