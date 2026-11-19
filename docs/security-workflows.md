# 보안 워크플로 구축 과정 (2026-11-19)

이 저장소의 GitHub Actions 7개와 Dependabot 을 왜 · 어떻게 붙였는지, 그리고 붙이면서 실제로 잡힌 것.
룰 시험(Detection-as-Code)은 따로: [`detection-ci.md`](detection-ci.md)

## GitHub Actions 한 장 요약

"**무슨 일이 생기면(on) → GitHub 이 빌려주는 임시 리눅스 컴퓨터(runs-on)에서 → 적어 둔 명령(steps)을 대신 실행**".
`.github/workflows/` 아래 YAML 파일이 곧 등록이다 — push 하면 GitHub 가 읽는다. 결과는 저장소 **Actions** 탭, PR 이면 PR 화면 아래 검사 칸.

## 전체

| 워크플로 | 언제 | 하는 일 | 권한 |
|---|---|---|---|
| `detection-ci` | 룰 · 명세 · 시험 변경, PR | Sigma 검사 · 변환 · drift · 정답 사례를 Sigma 엔진과 실제 Wazuh 로 | `contents: read` |
| `image-check` | PR (Dockerfile · 코드 · 모델 변경) | 도구 이미지 빌드 · 모델 불러 채점 · 이미지 안 Sigma 시험 | `contents: read` |
| `release-image` | main 의 코드 변경 | 이미지 빌드 → GHCR → cosign keyless 서명 · SBOM 증명 · SLSA 출처 | 작업에 4개 |
| `codeql` | push · PR · 매주 | 정적 분석 — Python 코드 + 워크플로(actions) | `security-events: write` 외 읽기 |
| `gitleaks` | push · PR | 비밀값 유출 — 커밋 이력 전체 | `contents: read` |
| `zizmor` | 워크플로 변경 | 워크플로 자체의 보안 결함 (중간 이상이면 실패) | `security-events: write` 외 읽기 |
| `scorecard` | push · 매주 | OpenSSF Scorecard 점수 → Security 탭 + 공개 점수 | `security-events` · `id-token` |
| Dependabot | 매주 | 고정한 액션 · 기반 이미지의 업데이트 PR | — |

## 모든 워크플로에 공통으로 지킨 것

| 원칙 | 방법 | 왜 |
|---|---|---|
| 최소 권한 | 맨 위 `permissions: {}` 또는 `contents: read`, 작업마다 필요한 것만 | 워크플로가 뚫려도 할 수 있는 일을 줄인다 |
| 액션 고정 | `uses: owner/action@<커밋 SHA> # vX.Y.Z` (릴리스 태그가 가리키는 커밋을 `gh api` 로 조회) | 태그는 옮길 수 있다 — 2025년 tj-actions/changed-files 사건처럼 |
| 고정 + 갱신 | Dependabot 이 SHA · digest 를 매주 갱신 PR | 고정만 하면 낡아서 보안 패치를 놓친다 |
| 기반 이미지 고정 | `FROM python:3.12-slim@sha256:…`, `FROM wazuh/wazuh-manager:4.14.9@sha256:…` | 태그가 옮겨져도 같은 이미지 |
| 도구 버전 고정 | `pip install sigma-cli==3.1.0 …`, gitleaks 이미지는 digest | CI 결과가 날마다 달라지지 않게 |
| 자격 증명 남기지 않기 | `actions/checkout` 에 `persist-credentials: false` | 다음 단계가 토큰을 훔쳐 쓰지 못하게 |
| 템플릿 직접 펼치지 않기 | `run:` 안에 `${{ }}` 대신 `env:` 로 넘김 | 셸 코드 주입 (zizmor `template-injection`) |
| 검사 | `actionlint`(shellcheck 포함) · `zizmor` 로컬에서 먼저 | 올리기 전에 오류 0 |

## 붙이면서 실제로 잡힌 것

| 무엇 | 어떻게 잡혔나 | 조치 |
|---|---|---|
| `release-image.yml` 의 `run:` 안 `${{ steps.build.outputs.digest }}` | zizmor (informational — 값이 digest 라 실제 위험은 낮음) | `env:` 로 넘김 |
| **Dependabot PR #1: Python 3.12 → 3.15** | 다른 검사(CodeQL · gitleaks)는 모두 초록불 — 하지만 로컬에서 빌드해 보니 **실패** (모델 파일용으로 고정한 scikit-learn 1.5.2 가 3.15 에 설치되지 않음). **초록불 = 안전이 아니었다** | `image-check` 를 새로 만들고 PR 을 다시 돌려 **빨간불로 잡히는 것 확인** → PR 닫음 → Dependabot 이 python minor/major 를 무시하게 설정 |
| Dependabot PR #2: Wazuh 4.14.6 → 4.14.9 | `detection-ci` 가 **새 Wazuh 로 정답 사례 16개 통과** | 합침 → compose 이미지 이름 · README 의 버전도 맞춤 (Dependabot 은 Dockerfile 만 바꾼다) |
| `pysigma 1.5.1` 과 `pyyaml==6.0.2` 충돌 | `detection-ci` 첫 실행 실패 | pysigma 가 실제로 고르는 6.0.3 으로 고정 |
| CodeQL 의 "최신 릴리스" 가 액션 버전이 아님 | `releases/latest` 가 `codeql-bundle-…` (분석 엔진 번들) | 태그 목록에서 `v4.x.y` 를 골라 SHA 조회 |

## Scorecard 점수 (첫 게시 5.9 / 10) — 무엇을 올리고 무엇은 안 올리나

| 항목 | 점수 | 처리 |
|---|---|---|
| Dangerous-Workflow · Token-Permissions · SAST · Dependency-Update-Tool · CI-Tests · Vulnerabilities · License · Binary-Artifacts · Packaging | 10 | — |
| Security-Policy | 0 → | `SECURITY.md` + GitHub 비공개 취약점 신고 켬. 일부러 취약한 앱이 든 저장소라 "무엇을 · 어디로 알리나"가 실제로 필요하다 |
| Pinned-Dependencies | 5 → | 기반 이미지를 digest 로 고정. 남은 감점: 워크플로 · Dockerfile 의 `pip install` 이 해시 고정이 아님 (버전 고정까지만) |
| Code-Review · Branch-Protection | 0 | **점수 때문에 켜지 않는다.** 혼자 쓰는 저장소에서 리뷰 필수를 켜면 직접 push 할 수 없다. 기여자가 생기면 켠다 |
| Maintained | 0 | 저장소가 생긴 지 90일이 안 됨 — 시간이 해결 |
| Fuzzing · CII-Best-Practices · Signed-Releases · Contributors | 0 / – | 이 연습장 범위 밖 (이미지는 서명하지만 GitHub Release 는 없다) |

공개 점수: https://scorecard.dev/viewer/?uri=github.com/zeldaim/api-defense-lab
