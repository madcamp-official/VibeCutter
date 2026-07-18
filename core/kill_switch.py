"""Kill switch: global pause file로 모든 tool 호출을 즉시 중단시킨다 (10.2절).

pause 여부는 in-memory 플래그가 아니라 파일 존재로 판단한다 — MCP 서버 프로세스가
재시작되거나 다른 프로세스에서 pause를 걸어도 살아남는 durable state가 필요해서다
(`core/audit_log.py`/`core/evidence_store.py`가 이미 `.vibecutter/`를 durable state로
쓰는 것과 같은 패턴).

`check_not_paused()`는 상태를 바꾸거나 실제 target/verifier를 건드리는 모든 tool
진입점(verify/scan 배선, repair/mutation/judge tool)이 가장 먼저 호출한다. `vc_pause`/
`vc_resume`(mcp_server 신규) 자체는 이 가드를 타지 않는다 — kill switch가 걸린 상태에서
kill switch를 풀 수 없으면 정작 멈춰야 할 때 못 멈추는 역설이 생긴다.
"""

from __future__ import annotations

from core.db import DATA_DIR

PAUSE_FILE = DATA_DIR / "PAUSE"


class KillSwitchEngaged(PermissionError):
    """pause file이 설정된 동안 모든 tool 호출이 이 예외로 거부된다."""


def is_paused() -> bool:
    return PAUSE_FILE.exists()


def pause_reason() -> str | None:
    """pause 중이 아니면 None, pause 중이면 `request_pause()`에 남긴 이유(빈 문자열이면 None)."""
    if not PAUSE_FILE.exists():
        return None
    return PAUSE_FILE.read_text(encoding="utf-8").strip() or None


def request_pause(reason: str) -> None:
    """global pause를 켠다. 이미 켜져 있으면 이유를 덮어쓴다(멱등)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PAUSE_FILE.write_text(reason, encoding="utf-8")


def clear_pause() -> None:
    """pause를 해제한다. 이미 꺼져 있으면 아무 것도 하지 않는다(멱등)."""
    PAUSE_FILE.unlink(missing_ok=True)


def check_not_paused() -> None:
    """paused 상태면 `KillSwitchEngaged`를 던진다."""
    reason = pause_reason()
    if reason is not None:
        raise KillSwitchEngaged(f"kill switch engaged: {reason}")
