#!/usr/bin/env python3
"""로컬 LLM(Ollama) 호출 — 표준 라이브러리만, 외부 네트워크 호출 없음. JSON 스키마를 주면 그 모양으로만 출력하게 강제한다.

  OLLAMA_URL (기본 http://127.0.0.1:11434) · OLLAMA_MODEL (기본 qwen2.5:7b-instruct)

스키마 강제(구조화 출력)는 '문법'만 보장한다. 값이 말이 되는지(탐지 조건이 맞는지)는 보장하지 않는다 — 그건 채점기가 잰다.
"""
import json
import os
import time
import urllib.error
import urllib.request


def chat(messages: list[dict], schema: dict | None = None, options: dict | None = None,
         base_url: str | None = None, model: str | None = None, timeout: int = 600) -> str:
    base = (base_url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
    payload = {"model": model or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b-instruct"), "messages": messages, "stream": False}
    if schema:
        payload["format"] = schema
    if options:
        payload["options"] = options
    req = urllib.request.Request(base + "/api/chat", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    for attempt in range(4):   # 두 모델을 번갈아 올리다 메모리가 빠듯하면 잠깐 5xx 를 낸다 — 5xx 만 재시도
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read()).get("message", {}).get("content", "")
        except urllib.error.HTTPError as e:
            if e.code >= 500 and attempt < 3:
                time.sleep(15)
                continue
            raise RuntimeError(f"로컬 LLM 오류 HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise RuntimeError(f"로컬 LLM({base}) 연결 실패: {e}") from e
    raise RuntimeError("로컬 LLM 재시도 소진")
