#!/usr/bin/env python3
"""룰 공장 결과 요약 — 조건별 비율에 95% 신뢰구간(Wilson)을 붙이고, CPU 와 GPU 의 같은 시드가 같은 룰을 내는지 비교한다. 표준 라이브러리만.

  python tools/rule_factory_summary.py docs/results/rule-factory_2026-11-26
폴더 안의 {cpu,gpu}_{main,noabstain}/{bola,probe}.jsonl 을 읽는다 (있는 것만).
n 이 작으면 구간이 넓다 — 그게 이 표의 요점이다. 비율은 추정값이고 모델 하나 · 합성 변종 · 시나리오 둘에 대한 것이다.
"""
import json
import math
import statistics
import sys
from pathlib import Path

ABSTAIN = "LLM 이 스스로 포기"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()] if p.exists() else []


def fmt(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({100 * k / n:.0f}%, 95%CI {100 * lo:.0f}–{100 * hi:.0f}%)" if n else "-"


def first_draft_key(r: dict):
    a = r["attempts"][0] if r["attempts"] else {}
    d = a.get("draft")
    if not d:
        return ("스키마 위반", a.get("error", "")[:30])
    return (d["can_propose"], tuple((s["field"], s["modifier"], s["value"]) for s in d["selections"]),
            d["correlation_timespan_seconds"], d["correlation_gte"])


def summarize(rs: list[dict]) -> dict:
    n = len(rs)
    first = [r["attempts"][0] for r in rs if r["attempts"]]
    return {"n": n,
            "abstain_first": sum(a.get("error") == ABSTAIN for a in first),
            "format_fail_first": sum(str(a.get("error", "")).startswith("출력이 스키마") for a in first),
            "valid_rule": sum(bool(r.get("valid_rule")) for r in rs),
            "train_pass": sum(bool(r.get("train_pass")) for r in rs),
            "heldA_pass": sum(bool(r.get("heldA_pass")) for r in rs),
            "heldB_pass": sum(bool(r.get("heldB_pass")) for r in rs),
            "accepted": sum(bool(r.get("accepted")) for r in rs),
            "memorized": sum(bool(r.get("train_pass")) and not r.get("heldB_pass") for r in rs),
            "mean_attempts": statistics.mean(len(r["attempts"]) for r in rs) if rs else 0,
            "median_seconds": statistics.median(r["seconds"] for r in rs) if rs else 0}


def main(folder: str):
    root = Path(folder)
    out = []
    conds = [("cpu_main", "CPU · 사전 지정(포기 가능)"), ("gpu_main", "GPU · 사전 지정(포기 가능)"),
             ("cpu_noabstain", "CPU · 사후 탐색(포기 불가)"), ("gpu_noabstain", "GPU · 사후 탐색(포기 불가)")]
    for sc in ("bola", "probe"):
        out.append(f"\n### 시나리오: {sc}\n")
        out.append("| 조건 | 실행 | 첫 시도 포기 | 유효한 룰 | 학습 통과 | 구간 A 통과 | 변종 B 통과 | **합격** | 학습만 통과(외움) | 평균 시도 | 중앙 소요 |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for key, label in conds:
            rs = load(root / key / f"{sc}.jsonl")
            if not rs:
                continue
            s = summarize(rs)
            n = s["n"]
            out.append(f"| {label} | {n} | {fmt(s['abstain_first'], n)} | {fmt(s['valid_rule'], n)} | {fmt(s['train_pass'], n)} | "
                       f"{fmt(s['heldA_pass'], n)} | {fmt(s['heldB_pass'], n)} | **{fmt(s['accepted'], n)}** | {s['memorized']}/{n} | {s['mean_attempts']:.1f} | {s['median_seconds']:.0f}s |")
    out.append("\n### CPU 와 GPU 의 같은 시드 비교 (시드 규칙이 같아 run 1~6 이 대응된다)\n")
    out.append("| 조건 · 시나리오 | 비교한 실행 | 첫 시도 룰이 완전히 같음 | 합격 여부가 같음 |")
    out.append("|---|---|---|---|")
    for cond in ("main", "noabstain"):
        for sc in ("bola", "probe"):
            c = {r["run"]: r for r in load(root / f"cpu_{cond}" / f"{sc}.jsonl")}
            g = {r["run"]: r for r in load(root / f"gpu_{cond}" / f"{sc}.jsonl")}
            common = sorted(set(c) & set(g))
            if not common:
                continue
            same_draft = sum(first_draft_key(c[i]) == first_draft_key(g[i]) for i in common)
            same_acc = sum(bool(c[i].get("accepted")) == bool(g[i].get("accepted")) for i in common)
            out.append(f"| {cond} · {sc} | {len(common)} | {same_draft}/{len(common)} | {same_acc}/{len(common)} |")
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1])
