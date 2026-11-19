# 모듈 `inventory` — 명세 없이 시작하기 (2026-11-19)

연습장의 Shadow 룰은 **공식 명세가 있고 맞다**는 가정에서 출발한다. 실제로는 명세가 없거나 낡은 경우가 많다.
이 모듈은 앞에 한 단계를 붙인다: **트래픽을 보고 실제로 쓰이는 API 목록을 만들고 → 공식 명세와 대조하고 → (원하면) 그 목록으로 룰을 만든다.**

```
traffic ──▶ inventory-proxy (mitmdump 역방향 프록시, 기록) ──▶ nginx ──▶ DVRA
                 │ /inv/flows.mitm                              (차단 · 접속 로그 · 정답지는 그대로)
                 ▼
            inventory (discover.py)
              ① 처리 증거만: 404 · 405 · 연습장 자동 차단 403 은 뺀다
              ② mitmproxy2swagger 두 번 → 관측 명세
              ③ 공식 명세와 (메서드, 경로) 대조
              ④ 숨은 API 정답 3개와 맞춰 보기 (채점에만)
              ⑤ --sigma: 관측 명세 → tools/gen_sigma.py → Sigma 룰
                 ▼
            reports/inventory/  inventory.md · inventory.json · observed_openapi.{yaml,json} · sigma/
```

## 실행

```bash
docker compose --profile inventory up -d --build                                   # 코어 + 프록시
docker compose --profile inventory run --rm inventory --reset                      # 기록 비우기
docker compose run --rm -e LAB_TARGET=http://inventory-proxy:8080 traffic demo     # 프록시를 거쳐 보낸다
docker compose --profile inventory run --rm inventory                              # 보고서
```

"명세 없이 시작" — **정상 트래픽만** 기록한 뒤 룰까지:

```bash
docker compose --profile inventory run --rm inventory --reset
docker compose run --rm -e LAB_TARGET=http://inventory-proxy:8080 traffic normal
docker compose --profile inventory run --rm inventory --sigma                      # → reports/inventory/sigma/*.yml
```

만든 룰을 쓰려면 `rules/sigma/` 에 복사하고 `docker compose restart detector`.

## 분류

| 분류 | 뜻 |
|---|---|
| **Shadow** | 트래픽에서 앱이 답했는데(2xx · 401 · 403 · 422 · 5xx) 공식 명세에 없는 (메서드, 경로) |
| 문서화됨 | 공식 명세에 있고 관측도 됨 |
| 명세 경로 + 잘못된 값 (422) | `/orders/export` 처럼 명세 경로 `/orders/{order_id}` 에 숫자 아닌 값을 넣어 422 만 받은 것 — 숨은 API 가 아니다 |
| 문서 화면 (예외) | `/docs` · `/openapi.json` 등 — `gen_sigma.py` 의 예외와 같다 |
| 명세에 있는데 관측 안 됨 | Zombie 후보. **관측 안 됨 ≠ 폐기** — 그 기록 동안 아무도 안 불렀을 뿐 |
| 차단돼서 확인 못 함 | 자동 차단 뒤의 요청은 nginx 가 답했다 → 경로가 있는지 모른다 |

## 결과 (2026-11-19, Windows 11 · Docker Desktop)

| 기록 | 숨은 API 3개 | 그 밖의 Shadow (오탐) | 비고 |
|---|---|---|---|
| 정상 4명 + 탐색(보통 IP) | **1/3** (`/debug`) — 나머지 2개는 "차단돼서 확인 못 함" | 0 | 탐색자가 `/debug` 200 에서 L3 로 **자동 차단**돼 그 뒤 요청은 앱까지 못 감 |
| 정상 4명 + 탐색(허용 목록 IP `10.1.0.1`) | **3/3** | **0** | `/orders/export` 422 는 '잘못된 값'으로 바르게 분류 |

**관측 명세로 만든 Sigma 룰 × 정답 사례 16 + 빈도 3** (정상 10명 · 20회만 기록): **18/19 통과**.
실패 1 = `PATCH /profile` (명세 안 · 정상) 이 L3 경보 — 정상 생성기가 프로필 수정을 한 번도 안 해서 관측 명세에 없다.
→ "명세 없이 시작"한 룰은 **기록 기간에 안 쓰인 정상 기능을 오탐한다.** 기록을 길게 · 다양하게 잡을수록 준다.

## 연습장에 주는 영향

- **코어에는 없다.** 프로필 `inventory` 를 켜지 않으면 서비스가 생기지 않는다 (`docker compose config --services` 에 안 나옴).
- 켜도 **프록시를 거쳐 보낸 트래픽만** 기록된다 (`LAB_TARGET`). 출발지는 `X-Client-IP` 헤더 그대로라 nginx 접속 로그 · 탐지 · 차단 · 채점은 같다. 프록시 한 단계가 늘어난 지연은 재지 않았다.
- **반대 방향의 영향은 있다:** 탐지기가 공격자를 빨리 막을수록 그 공격자가 찾던 숨은 API 는 기록에 안 남는다 (위 표 1/3). 실제 운영에서도 "차단"과 "발견"은 서로를 가린다 — 발견용 기록은 차단 전 단계(미러링 · 허용 목록 · 스테이징)에서 잡는다.

## 자동화한 손작업 — mitmproxy2swagger 를 그대로 쓰면 생기는 일

| 문제 | 증상 | 이 모듈의 처리 |
|---|---|---|
| 반자동 | 1차 실행은 경로 목록을 `ignore:` 로 막아서 내놓고 사람이 지운 뒤 2차 실행 | 스크립트가 지우고 2차 실행 |
| 탐욕 매칭 · 위가 먼저 | `/orders/{id}` 가 `/orders/export` 보다 위에 있으면 숨은 경로가 파라미터로 빨려 들어가 사라짐 | 숫자 아닌 고정 경로를 먼저, 템플릿을 나중에 |
| 숫자 경로 | `/orders/7` 같은 값이 경로로 남음 | 숫자 경로는 버리고 템플릿만 (`-s`) |
| 파라미터 형식 | 작업마다 경로 파라미터를 `string` 으로 넣음 → `gen_sigma.py` 가 `/orders/abc` 를 명세 안으로 오판 | 숫자에서 나온 템플릿이라 `integer` 로 바꿈 |
| 입력 형식 자동 감지 | mitmproxy 기록 파일을 HAR 로 잘못 읽어 `TypeError` | `-f flow` 로 고정 |
| 차단 · 없는 경로 | 연습장 차단 403 · 404 · 405 를 '있음'으로 셈 | 처리 증거만 남김 |

두 번째와 네 번째는 시험(`tests/inventory/test_inventory.py`)이 지킨다 — 처리를 되돌리면 실패하는 것까지 확인했다 (실패 2).

## 시험 (CI: `image-check`)

`tests/inventory/fixture.mitm` = 정상 3명 · 4회 + 허용 목록 IP 의 탐색 15곳 (토큰 · 가입 · 로그인 본문 · `/debug` 가 내놓는 컨테이너 환경 변수는 지움).
숨은 API 3/3 · 그 밖의 Shadow 0 · `/orders/export` 는 '잘못된 값' · 관측 명세 룰이 `/orders/abc` 를 명세 밖으로 · `/orders/12` 는 명세 안.

## 다른 방식과의 관계

이 모듈은 **프록시를 지나간 트래픽**으로 명세를 만든다. 트래픽 경로를 바꾸지 않는 **네트워크 미러링(tcpdump → Zeek)** 방식과
능동 스캔을 교차하는 판정기는 [zeldaim/shadow-api-lab](https://github.com/zeldaim/shadow-api-lab) (2026-11-01) 에,
선언 명세 · 설정 · 로그 · 블랙박스 스캔 4출처 인벤토리는 [api-security-supply-chain `standardize/inventory/`](https://github.com/zeldaim/api-security-supply-chain/tree/main/standardize/inventory) 에 있다.
세 방식을 같은 정답지로 비교하는 일은 벤치마크([#3](https://github.com/zeldaim/api-defense-lab/issues/3)) 다음 단계.

## 출처

- [mitmproxy2swagger](https://github.com/alufers/mitmproxy2swagger) (alufers, MIT) 0.15.0 · [mitmproxy](https://mitmproxy.org) 12.3.1 — 이미지에서 pip 로 설치, 코드는 이 레포에 없다
