"""LLM egress 동의: 코드 스니펫이 외부 LLM으로 나가기 전 1회 동의 게이트 (U3, TEAM_CONTRACT §3A-10).

동의 여부는 in-memory 플래그가 아니라 파일 존재로 판단한다 — `core/kill_switch.py`와 같은
이유다: MCP 서버 프로세스가 재시작되거나 다른 프로세스에서 동의를 기록해도 durable해야 한다.

전송 범위는 §3A-10에 적힌 그대로다: rerank 스니펫(≈21줄 × 최대 10개) + 패치 대상 파일. 그
외 evidence·DB·로그는 로컬을 벗어나지 않는다. redaction(`core/redaction.py`)은 이미 두
경로(rerank/synth) 모두에 걸려 있다(`repair/llm_synth.py`) — 여기서 다시 만들지 않는다.
이 모듈은 "보내도 되는가"만 판정하고 "무엇을 보낼지 걸러내는 것"은 건드리지 않는다.

동의가 없을 때 LLM 경로를 예외로 막지 않고 **엔드포인트가 죽은 것과 동일하게 조용히
degrade**시키는 게 호출측 계약이다(`mcp_server/tools_repair.py::_get_llm_client`,
`mcp_server/tools_analysis.py::_rerank_hook_from_env` 둘 다 이미 "엔드포인트 없음 → None →
heuristic/template" 폴백을 갖고 있었다) — 동의 전에도 앱은 정상 동작해야 하고(안전 불변식
3, "판정에 LLM 없음"과 같은 정신), 동의는 최적화 여부를 결정할 뿐 기능을 잠그지 않는다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from core.db import DATA_DIR

CONSENT_FILE = DATA_DIR / "EGRESS_CONSENT"


def has_consented() -> bool:
    return CONSENT_FILE.exists()


def consent_record() -> dict | None:
    """동의 안 했으면 `None`, 했으면 `{granted_at, actor}` 기록."""
    if not CONSENT_FILE.exists():
        return None
    try:
        data = json.loads(CONSENT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def grant_consent(*, actor: str = "mcp_host") -> dict:
    """동의를 durable하게 기록한다(멱등).

    이미 동의한 상태에서 다시 호출해도 **최초 동의 시각을 덮어쓰지 않는다** — "언제 동의했는가"가
    감사 질문의 핵심이라, 재확인 호출로 슬쩍 갱신되면 안 된다.
    """
    existing = consent_record()
    if existing is not None:
        return existing
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {"granted_at": datetime.now(timezone.utc).isoformat(), "actor": actor}
    CONSENT_FILE.write_text(json.dumps(record), encoding="utf-8")
    return record


def revoke_consent() -> None:
    """동의를 철회한다(멱등 — 이미 철회 상태면 아무 것도 하지 않는다)."""
    CONSENT_FILE.unlink(missing_ok=True)
