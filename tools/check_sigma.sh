#!/usr/bin/env bash
# Sigma 룰 검사 + 변환 확인 (Docker 만 있으면 된다). Git Bash 에서는 MSYS_NO_PATHCONV=1 이 필요하다 (스크립트가 건다).
#   bash tools/check_sigma.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1
DIR="$(cd "$(dirname "$0")/.." && pwd)/rules/sigma"
command -v cygpath >/dev/null && DIR="$(cygpath -m "$DIR")"
docker run --rm -v "$DIR:/r:ro" python:3.12-slim sh -c '
  pip install -q --root-user-action=ignore --disable-pip-version-check \
      sigma-cli==3.1.0 pysigma==1.5.1 pysigma-backend-elasticsearch==2.1.1 pysigma-backend-splunk==2.1.0
  sigma check /r
  for f in /r/shadow_api_l*.yml; do
    echo "=== $(basename $f) → Lucene"; sigma convert -t lucene --without-pipeline "$f" | tail -1
  done'
