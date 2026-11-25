#!/usr/bin/env python3
"""tools/ai_rule_propose.py 의 검증 하네스 시험 — AI 호출 없이, 손으로 만든 초안 3개로 확인한다.
  (pyyaml · pydantic 필요: pip install pyyaml==6.0.2 pydantic==2.10.4)
  python tests/detection/test_ai_rule_propose.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from ai_rule_propose import RuleDraft, Selection, to_sigma_yaml, validate, propose_loop  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    return json.load(open(os.path.join(HERE, name), encoding="utf-8"))


def main():
    evading_toolua = load("cases_evading_toolua.json")
    evading_401 = load("cases_evading.json")
    normal = load("cases_normal_samples.json")
    fails = 0

    good = RuleDraft(can_propose=True, title="quickscan UA", description="test", level="high",
                     selections=[Selection(field="cs-user-agent", modifier="contains", value="quickscan/")])
    ok, msg = validate(to_sigma_yaml(good, "draft-smoke-good"), evading_toolua, normal)
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  식별되는 UA 초안 → 통과해야 함 ({msg})")

    bad = RuleDraft(can_propose=True, title="401 all", description="test", level="high",
                    selections=[Selection(field="sc-status", value="401")])
    ok, msg = validate(to_sigma_yaml(bad, "draft-smoke-bad"), evading_401, normal)
    fails += ok  # 통과하면 실패 — 오탐을 걸러내야 한다
    print(f"{'PASS' if not ok else 'FAIL'}  너무 넓은 초안(401 전부) → 정상 오탐으로 버려져야 함 ({msg})")

    sameua = RuleDraft(can_propose=True, title="ua401", description="test", level="high",
                       selections=[Selection(field="cs-user-agent", value="Mozilla/5.0 (api-defense-lab)"),
                                  Selection(field="sc-status", value="401")])
    ok, msg = validate(to_sigma_yaml(sameua, "draft-smoke-real"), evading_401, normal)
    fails += ok
    print(f"{'PASS' if not ok else 'FAIL'}  실제 회피 시나리오(같은 UA) → 단건 탐지로는 구분 불가해 버려져야 함 ({msg})")

    # 재시도 루프(자율 반복) — 1차 실패 이유를 2차 제안이 실제로 받아서 고치고, 통과하면 바로 멈추는지
    def fake_proposer(evading_events, normal_events, existing_titles, client=None, model=None, prior_attempts=None):
        if not prior_attempts:
            return RuleDraft(can_propose=True, title="1차", description="일부러 너무 넓음", level="high",
                            selections=[Selection(field="sc-status", value="200")])
        assert prior_attempts[0]["why_rejected"] is not None, "1차 실패 이유가 2차로 안 넘어감"
        return RuleDraft(can_propose=True, title="2차", description="피드백 반영", level="high",
                        selections=[Selection(field="cs-user-agent", modifier="contains", value="quickscan/")])

    draft, msg, attempts = propose_loop(evading_toolua, normal, [], max_attempts=3, proposer=fake_proposer)
    ok = draft is not None and draft.title == "2차" and len(attempts) == 2
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  재시도 루프 — 실패 이유를 받아 고치고 2번째에 통과 ({msg})")

    print(f"\n{'모두 통과' if not fails else f'실패 {fails}건'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
