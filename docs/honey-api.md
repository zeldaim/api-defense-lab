# Honey API — 미끼 경로로 느린 에이전트 잡기 (2026-11-25)

`agent` 시나리오([artex-fingerprint](https://github.com/zeldaim/artex-fingerprint) 정적 분석에서 뽑은 행위)에서 **느리게(variant `slow`, 경로마다 9초) 도는 에이전트는 401 순회 빈도 룰(60초에 8회)을 피해 나갔다** (알려진 한계, `tests/detection/test_sigma.py`에 기록됨 — 간격을 9초로 **고정**한 경우. 랜덤 6~12초 간격의 실측은 10회 중 9회 차단·1회 우회로 [README](../README.md#에이전트-시나리오-결과-traffic-attack-agent-2026-11-27)에 따로 적었다). UA·속도·요청 수에 기대지 않고 잡을 방법이 필요했다.

## 방법

화면 코드 번들(`/static/app.bundle.js`)에 실제로는 아무도 부르지 않는 가짜 내부 경로 3개를 심었다:

```js
_internal: {
  exportOrders: "/internal/v2/orders/export",
  debugConfig: "/internal/debug/config",
  adminUsers: "/internal/admin/users",
}
```

- **정상 클라이언트**는 번들을 받아도(브라우저가 다 받으니까) 이 키를 쓰는 코드가 없어 절대 호출하지 않는다.
- **번들에서 API 경로를 문자열로 긁어 전부 호출하는 자동 수집기**(ARTEX `harvest_static.py` 행위 — 정규식으로 경로 상수를 뽑아 하나씩 때림)는 이 미끼도 그대로 부른다.
- `rules/sigma/honey_api_touch.yml`: `/internal/` 접촉 **한 번**이 `lab_block` 그룹 · level `critical` — 빈도·UA와 무관하게 즉시 자동 차단된다.
- nginx(`nginx/nginx.conf`)는 `/internal/`을 진짜 보호 API처럼 `401`로 응답한다 (`200`이나 `404`로 티 내지 않는다).

## 트래픽 생성기

- `traffic normal --bundle`: 정상 사용자도 화면 번들을 받지만 미끼는 부르지 않는다 (오탐 시험용).
- `traffic attack agent --variant <var> --honey`: 번들을 받아 정규식으로 경로를 뽑고 **찾은 경로를 전부** 호출한다 (`/internal/...` 포함) — 정적 수집기 행위의 재현.

## 결과 (이 PC, 코어만, 2026-11-25)

| 시나리오 | 요청 | 탐지까지 | 비고 |
|---|---|---|---|
| `agent --variant ua-changed --honey` (1회차) | 34 | 12.3초 | 번들 호출 전 문서 수집 스레드가 먼저 돎 |
| `agent --variant ua-changed --honey` (2회차) | 34 | **1.8초** | `/internal/admin/users` 접촉 직후 차단 (detector 주기 2초 + nginx 재적용 1초 안) |
| `normal --bundle` 15명 + 기존 정상 31명 (합계 46명, 요청 1,542) | — | — | **오탐 차단 0 · 룰 경보 0** |

- 느린 변형(`slow`, 경로마다 6~12초)은 아직 별도로 측정하지 않았다 — 설계상 접촉 한 번으로 잡히므로 속도와 무관할 것으로 예상되지만, 엔진 단위 시험(`test_sigma.py`)으로만 확인했고 `docker compose`로 직접 돌려 보지는 않았다.
- `test_sigma.py`에 룰 단위 시험 2개 추가: 미끼 경로 한 번 → `lab_block`, 정상 보호 경로(`/profile`) 401 한 번 → `lab_block` 아님.

## 한계

- 번들에서 경로를 **긁어서** 부르는 수집기(정적 분석, A2 갈래)만 잡는다. ARTEX의 런타임 수집(A4, 헤드리스 브라우저로 화면을 실제로 돌며 API를 호출)은 번들을 안 읽고 화면에 실제로 그려진 링크만 따라갈 수 있어 — 미끼가 **화면에 노출되지 않으면** 못 잡을 수 있다. 확인 안 함.
- 미끼 경로를 아는 사람(개발자가 실수로 커밋에 남긴 문서 등)이 수동으로 접속해도 똑같이 차단된다 — `falsepositives`에 적어 둠.
- 미끼는 한 세트뿐이라, 공격 쪽이 이 레포를 읽고 미끼 경로를 가려내 피하면 무력화된다 (CTF형 환경의 공통 한계 — 공개 레포라 이 한계도 공개됨).
