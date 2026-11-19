# Detection-as-Code CI 구축 과정 (2026-11-19)

탐지 룰을 바꿀 때마다 GitHub Actions 가 자동으로 룰을 시험하게 만든 과정이다. 워크플로: [`.github/workflows/detection-ci.yml`](../.github/workflows/detection-ci.yml)

## 왜 하나

룰은 코드다. 고치면 깨질 수 있다. 사람이 매번 `wazuh-logtest` 에 로그를 붙여 넣어 확인하면 빠뜨린다.
이 연습장에는 같은 판정을 하는 룰이 **두 벌**(Sigma · Wazuh) 있어서, 한쪽만 고치면 둘이 어긋난다 — 그것도 잡아야 한다.

| 시험 | 잡는 것 |
|---|---|
| `sigma check` | Sigma 문법 · 규격 오류 |
| Lucene 변환 | SIEM 으로 옮길 수 없는 룰 |
| drift (명세에서 다시 만든 룰과 비교) | 룰을 손으로 고치고 생성기 · 명세는 안 고친 경우 |
| 정답 사례 × Sigma 엔진 | 판정 회귀 (경보가 사라지거나 · 오탐이 생김) |
| 정답 사례 × 실제 Wazuh (`wazuh-logtest`) | 같은 회귀 + Wazuh 룰 문법 오류 (오류면 Wazuh 가 시작조차 못 한다) |
| 빈도 룰 합성 묶음 | F1 · F2 문턱 · 시간 창 |

## 1단계 — 정답 사례 만들기 (`tests/detection/cases.json`)

로그 한 줄 + 기대 단계(`L1` · `L2` · `L3` · `L3E` · `none`) 16개. 정답은 **명세를 보고 사람이 정한다** — 룰을 돌려서 나온 값을 정답으로 적으면 시험이 의미 없다.

사례는 경계를 노린다:

| 종류 | 예 | 기대 |
|---|---|---|
| 숨은 API 성공 | `GET /debug 200`, 쿼리 붙은 `GET /delivery/orders?x=1 200` | L3 |
| 명세 형식 위반 | `GET /orders/abc 200` (명세는 정수 ID) | L3 |
| 없는 경로 · 없는 메서드 | `GET /admin 404`, `POST /menu 405` | L1 |
| 숨은 API 존재 확인 | `GET /admin/reset-chef-password 403` | L2 |
| 서버 오류 | `GET /internal/metrics 500` | L3E |
| 명세 안 정상 | `GET /menu`, `GET /orders/12`, `PATCH /profile` | none |
| 명세 안 BOLA | `GET /orders/status/99` — 룰이 아니라 ML 의 몫 | none |
| 예외 | `/docs`, `/openapi.json` (공개 문서 화면) | none |
| 범위 밖 | `/static/app.css` | none |
| 명세 안 경로의 오류 | `GET /orders/999999 404` | none |

## 2단계 — 시험 실행기 두 개

- `tests/detection/test_sigma.py` — `detector/sigma_engine.py` 로 각 사례를 판정. 사례마다 엔진을 새로 만들어 빈도 상태가 섞이지 않게 한다. 빈도 룰은 합성 묶음 3개(30초에 L1 25회 → F1 1번, 60초에 L3 12회 → F2 1번, 38초에 L1 19회 → F1 없음).
- `tests/detection/test_wazuh.py <컨테이너>` — 각 사례를 `wazuh-logtest` 에 넣고 Phase 3 의 마지막 룰 id 를 단계로 바꾼다 (100510 → L1 … 그 밖 → none).

```bash
# 로컬에서 (저장소 루트, Linux · macOS · WSL)
docker build -t lab-wazuh ./wazuh
docker run -d --name wz -v "$PWD/rules/wazuh:/lab/rules:ro" lab-wazuh
until docker exec wz test -S /var/ossec/queue/sockets/logtest; do sleep 3; done
python3 tests/detection/test_wazuh.py wz
python3 tests/detection/test_sigma.py          # pyyaml 필요
```

## 3단계 — 시험이 정말 잡는지 확인 (일부러 망가뜨리기)

통과만 보면 시험이 아무것도 안 보는 건지 알 수 없다. 룰 사본에서 **문서 경로 예외를 지우고** 돌렸다:

| | 원본 룰 | 예외 지운 룰 |
|---|---|---|
| Sigma 엔진 | 19/19 통과 | **실패 1** (`/docs` → L3) |
| Wazuh | 16/16 통과 | **실패 2** (`/docs` · `/openapi.json` → L3) |

(Sigma 사본은 `/docs` 만, Wazuh 사본은 네 경로를 다 지워서 수가 다르다.) `SIGMA_RULES=<폴더>` 로 Sigma 시험의 룰 위치를 바꿀 수 있다.

## 4단계 — 워크플로

- 언제: `rules/` · `spec/` · `wazuh/` · 생성기 · Sigma 엔진 · 시험 · 워크플로가 바뀐 push(main)와 PR, 그리고 손으로(`workflow_dispatch`).
- 권한: `contents: read` 하나 — 이 워크플로는 아무것도 쓰거나 올리지 않는다.
- 액션은 커밋 SHA 로 고정 (`actions/checkout`, `actions/setup-python`), 도구는 버전 고정 (`sigma-cli==3.1.0` …).
- 두 작업(sigma · wazuh)이 나란히 돈다. Wazuh 가 5분 안에 안 뜨면 로그를 남기고 실패 — 룰 문법 오류면 여기서 걸린다.
- 검사: `actionlint` (shellcheck 포함) 오류 0.

**GitHub 에 등록하는 법:** 따로 등록 절차는 없다. `.github/workflows/` 아래에 YAML 을 두고 push 하면 GitHub 가 알아서 읽어 조건이 맞을 때 실행한다. 결과는 저장소의 **Actions** 탭, PR 이면 PR 화면 아래 검사 칸에 나온다.

## 겪은 함정

| 증상 | 원인 | 조치 |
|---|---|---|
| Wazuh 시험이 10분째 멈춤 | Windows Git Bash 가 `docker exec … test -S /var/ossec/...` 의 경로를 Windows 경로로 바꿔 소켓 확인이 영원히 거짓 | 로컬은 `MSYS_NO_PATHCONV=1`. CI(Linux)는 해당 없음. 대기 반복에 상한(5분)을 둠 |
| 시험기가 `wazuh-logtest` 에서 멈춤 | `docker exec -i` 로 표준입력을 주면 Windows 에서 입력 끝(EOF)이 전달되지 않아 다음 줄을 계속 기다림 | 로그 줄을 환경변수로 넘겨 컨테이너 안에서 `printf | wazuh-logtest` |
| **경보 없음 사례가 전부 '통과', 경보 사례는 전부 실패** | `wazuh-logtest` 는 결과를 **stderr** 로 쓴다 — stdout 만 읽어 늘 빈 결과 → "경보 없음"으로 오판 | stdout + stderr 를 읽고, 디코딩(Phase 2) 흔적이 없으면 시험 자체를 실패로. **이걸 놓쳤으면 CI 가 절반을 검사하지 않고 초록불을 냈다** |
| 망가뜨린 룰 시험이 그대로 통과 | `sed` 가 Wazuh 정규식의 `\-` 이스케이프를 못 맞춰 아무것도 안 지움 | 파이썬으로 정확한 문자열을 바꾸고, 바뀌었는지 확인한 뒤 시험 |
| 워크플로 YAML 앵커(`&paths`) | GitHub 지원이 최근이라 도구 · 버전마다 다를 수 있다 | 경로 목록을 두 번 씀 |
| actionlint: `SC2034 i appears unused` | 대기 반복 변수 | `_` 로 |
| CI 첫 실행: Sigma 작업이 도구 설치에서 실패 (`ResolutionImpossible`) | `pysigma 1.5.1` 이 요구하는 pyyaml 과 고정한 `pyyaml==6.0.2`(도구 이미지 버전을 그대로 씀)가 충돌 — 로컬은 컨테이너 안에서 pip 가 알아서 6.0.3 을 골라 드러나지 않았다 | `pyyaml==6.0.3` 으로 고정 (pysigma 가 실제로 고르는 버전을 확인해서) |

## 결과

- 로컬: Sigma 엔진 19/19 (사례 16 + 빈도 3) · Wazuh 16/16 · drift 없음 · `sigma check` 오류 0 · actionlint 0
- GitHub Actions: 첫 실행은 Sigma 작업이 도구 설치에서 실패(위 함정 표) → 고친 뒤 [두 작업 모두 통과](https://github.com/zeldaim/api-defense-lab/actions/runs/44453398381) — wazuh 53초(16/16) · sigma 16초(19/19 · `sigma check` 오류 0 · drift 없음)
