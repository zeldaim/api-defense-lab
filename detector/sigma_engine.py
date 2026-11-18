#!/usr/bin/env python3
"""가벼운 판정기 — Wazuh 없이 rules/sigma/*.yml 을 접속 로그 한 줄마다 바로 적용한다 (lite 판에서 detector 가 쓴다).

범용 Sigma 엔진이 아니다. 이 연습장의 룰에 필요한 만큼만 지원한다:
  탐지: 필드 값(목록이면 OR) · 수정자 re / contains / startswith / endswith
        조건 and · or · not · 괄호 · `1 of x*` · `all of x*` · 선택 이름
  상관: type event_count · group-by · timespan(초 s · 분 m · 시 h) · condition gte / gt
        한 번 걸리면 같은 그룹은 IGNORE 초 동안 다시 내지 않는다 (Wazuh 룰의 ignore="60" 과 같게)
필드: c-ip · cs-method · cs-uri-stem · cs-uri-query · sc-status · cs-user-agent

판정은 Wazuh 경보와 같은 모양(rule.id · level · groups, data.srcip …)으로 돌려준다 → 차단 정책 · 채점이 그대로 쓴다.
기본 룰(shadow_api_*)은 Wazuh 룰과 같은 id · 레벨 · 그룹으로 낸다. 내 Sigma 룰은 id 110000 번대, 레벨은 Sigma level 로,
최상위에 `lab_block: true` 가 있으면 그룹 lab_block 이 붙어 자동 차단된다 (Sigma 는 모르는 필드를 그대로 둔다 — sigma check 통과).
"""
import fnmatch
import glob
import os
import re
from collections import defaultdict, deque

import yaml

IGNORE = 60
LEVEL = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}
BUILTIN = {   # 파일 이름 → (Wazuh 룰 id, 레벨, 그룹) — rules/wazuh/0915-shadow_api_rules.xml 과 같게
    "shadow_api_l1_recon": ("100510", 5, ["shadow_api", "shadow_api_recon"]),
    "shadow_api_l2_discovery": ("100511", 8, ["shadow_api", "shadow_api_discovery"]),
    "shadow_api_l3_exploit": ("100512", 12, ["shadow_api", "shadow_api_exploit"]),
    "shadow_api_l3e_error": ("100513", 10, ["shadow_api", "shadow_api_error"]),
    "shadow_api_f1_recon_burst": ("100520", 10, ["shadow_api", "shadow_api_recon_burst"]),
    "shadow_api_f2_mass_exfil": ("100521", 14, ["shadow_api", "shadow_api_mass_exfil"]),
}


def _match_value(mods, want, got):
    got = "" if got is None else str(got)
    want = str(want)
    if "re" in mods:
        return re.search(want, got) is not None
    if "contains" in mods:
        return want in got
    if "startswith" in mods:
        return got.startswith(want)
    if "endswith" in mods:
        return got.endswith(want)
    return got == want


def _match_map(sel, ev):
    if isinstance(sel, list):                       # 목록 = 맵들의 OR
        return any(_match_map(s, ev) for s in sel)
    for key, want in sel.items():
        field, *mods = key.split("|")
        wants = want if isinstance(want, list) else [want]
        ok = [_match_value(mods, w, ev.get(field)) for w in wants]
        if not (all(ok) if "all" in mods else any(ok)):
            return False
    return True


def _condition(text, names):
    """조건 문자열 → 함수(이름 → 참/거짓). 재귀 하강."""
    toks = re.findall(r"\(|\)|[^\s()]+", text)
    pos = [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def atom():
        t = peek()
        if t == "not":
            take()
            f = atom()
            return lambda r: not f(r)
        if t == "(":
            take()
            f = expr()
            take()
            return f
        if t in ("1", "all") and pos[0] + 1 < len(toks) and toks[pos[0] + 1].lower() == "of":
            quant, _, pat = take().lower(), take(), take()
            pat = "*" if pat == "them" else pat
            hit = [n for n in names if fnmatch.fnmatch(n, pat)]
            return (lambda r: any(r[n] for n in hit)) if quant == "1" else (lambda r: all(r[n] for n in hit))
        name = take()
        return lambda r: r[name]

    def term():
        f = atom()
        while peek() == "and":
            take()
            g, f0 = atom(), f
            f = lambda r, f0=f0, g=g: f0(r) and g(r)
        return f

    def expr():
        f = term()
        while peek() == "or":
            take()
            g, f0 = term(), f
            f = lambda r, f0=f0, g=g: f0(r) or g(r)
        return f

    return expr()


def _seconds(span):
    n, unit = int(span[:-1]), span[-1]
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


class Engine:
    def __init__(self, folder):
        self.rules, self.corrs, n = [], [], 0
        for p in sorted(glob.glob(os.path.join(folder, "*.yml")) + glob.glob(os.path.join(folder, "*.yaml"))):
            stem = os.path.splitext(os.path.basename(p))[0]
            for d in yaml.safe_load_all(open(p, encoding="utf-8")):
                if not isinstance(d, dict):
                    continue
                if stem in BUILTIN:
                    rid, lvl, groups = BUILTIN[stem]
                else:
                    n += 1
                    rid, lvl, groups = str(110000 + n), LEVEL.get(d.get("level"), 5), ["sigma", f"sigma_{stem}"]
                    if d.get("lab_block") is True:
                        groups.append("lab_block")
                meta = {"id": rid, "level": lvl, "groups": groups, "title": d.get("title", stem),
                        "sigma_id": str(d.get("id", "")), "name": d.get("name")}
                if "correlation" in d:
                    c = d["correlation"]
                    cond = c.get("condition") or {}
                    self.corrs.append({**meta, "rules": [str(x) for x in c.get("rules", [])],
                                       "group_by": c.get("group-by") or [], "span": _seconds(str(c["timespan"])),
                                       "gte": cond.get("gte", cond.get("gt", 0) + 1 if "gt" in cond else 1),
                                       "hits": defaultdict(deque), "quiet": {}})
                else:
                    det = dict(d["detection"])
                    cond = det.pop("condition")
                    cond = cond[0] if isinstance(cond, list) else cond
                    self.rules.append({**meta, "sel": det, "cond": _condition(cond, list(det))})
        print(f"[sigma] 판정 룰 {len(self.rules)} · 상관 룰 {len(self.corrs)} ({folder})", flush=True)

    def _alert(self, r, ev, t, text):
        return {"rule": {"id": r["id"], "level": r["level"], "groups": r["groups"], "description": text},
                "data": {"srcip": ev["c-ip"], "protocol": ev["cs-method"],
                         "url": ev["cs-uri-stem"] + ("?" + ev["cs-uri-query"] if ev.get("cs-uri-query") else ""),
                         "id": ev["sc-status"]},
                "_t": t}

    def evaluate(self, ev, t):
        """접속 로그 한 줄(ev: Sigma 필드 dict, t: epoch 초) → 경보 목록"""
        out = []
        for r in self.rules:
            res = {k: _match_map(v, ev) for k, v in r["sel"].items()}
            if not r["cond"](res):
                continue
            out.append(self._alert(r, ev, t, f"[Sigma] {r['title']}: {ev['c-ip']} {ev['cs-method']} {ev['cs-uri-stem']}"))
            for c in self.corrs:
                if r["sigma_id"] not in c["rules"] and r["name"] not in c["rules"]:
                    continue
                key = tuple(ev.get(g) for g in c["group_by"])
                q = c["hits"][key]
                q.append(t)
                while q and q[0] < t - c["span"]:
                    q.popleft()
                if len(q) >= c["gte"] and t >= c["quiet"].get(key, 0):
                    c["quiet"][key] = t + IGNORE
                    out.append(self._alert(c, ev, t, f"[Sigma] {c['title']}: {ev['c-ip']} {len(q)}회"))
        return out
