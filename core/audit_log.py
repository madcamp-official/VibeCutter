"""Audit log 골격.

cowork_rule.md 4절 "tool call, 정책 거부, 파일 변경, validation verdict를 audit trail에
남긴다"를 만족시키는 최소 구현. 기록 필드: tool 이름, args hash, actor, target, time,
result, changed_files.

FastMCP는 tool 호출 전체를 가로챌 수 있는 미들웨어 훅이 없고(`_setup_handlers()`가
`__init__` 시점에 `self.call_tool`을 low-level server에 등록해버려 이후 몬키패치로는
가로챌 수 없다), 그래서 `audited_tool()`을 `@mcp.tool()` 대신 각 tool 함수에 직접
씌우는 방식을 쓴다 — 오늘부터 모든 tool 등록(`mcp_server/tools_*.py`)이 이 데코레이터를
거친다.

policy_engine의 거부(PolicyViolation)도 여기로 흘러들어와 result="error"로 기록된다 —
"정책 거부"를 audit trail에 남기라는 요구사항을 tool 경로에서 자동으로 만족한다.
"""

from __future__ import annotations

import functools
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sqlmodel import JSON, Column, Field, Session, SQLModel, create_engine, select

_DATA_DIR = Path(__file__).resolve().parent.parent / ".vibecutter"
_DB_PATH = _DATA_DIR / "evidence.db"  # evidence_store와 같은 SQLite 파일을 공유한다


class AuditEntry(SQLModel, table=True):
    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    tool: str
    args_hash: str
    actor: str
    target: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    result: str  # "ok" | "error"
    error: str | None = None
    changed_files: list[str] = Field(default_factory=list, sa_column=Column(JSON))


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{_DB_PATH}")
        SQLModel.metadata.create_all(_engine)
    return _engine


def _hash_args(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _guess_target(arguments: dict[str, Any]) -> str | None:
    for key in ("target_id", "run_id", "finding_id", "patch_id", "candidate_id"):
        if key in arguments:
            return str(arguments[key])
    return None


def record(
    *,
    tool: str,
    arguments: dict[str, Any],
    result: str,
    error: str | None = None,
    changed_files: list[str] | None = None,
    actor: str = "mcp_host",
) -> AuditEntry:
    """actor는 아직 고정값이다 — stdio MCP에는 사용자별 인증이 없어 Day1엔 구분하지 않는다."""
    entry = AuditEntry(
        tool=tool,
        args_hash=_hash_args(arguments),
        actor=actor,
        target=_guess_target(arguments),
        result=result,
        error=error,
        changed_files=changed_files or [],
    )
    with Session(get_engine()) as session:
        session.add(entry)
        session.commit()
        session.refresh(entry)
    return entry


def list_entries(limit: int = 100) -> list[AuditEntry]:
    with Session(get_engine()) as session:
        rows = session.exec(
            select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit)
        ).all()
        return list(rows)


def audited(fn: Callable) -> Callable:
    """tool 함수를 감싸 호출 성공/실패를 audit log에 자동 기록한다.

    `mcp_server/tools_*.py`에서 `@mcp.tool()`과 같이 쓴다:

        @mcp.tool()
        @audited
        def vc_generate_patch(finding_id: str) -> Patch: ...

    FastMCP는 항상 keyword argument로 tool 함수를 호출하므로(`fn(**arguments_parsed_dict)`),
    이 wrapper도 `**kwargs`만 받으면 충분하다. `functools.wraps`가 `__wrapped__`를 남겨
    FastMCP의 시그니처 검사(inputSchema/outputSchema 생성)는 원본 함수 그대로 본다.
    """

    @functools.wraps(fn)
    def wrapper(**kwargs: Any):
        try:
            output = fn(**kwargs)
        except Exception as exc:
            record(tool=fn.__name__, arguments=kwargs, result="error", error=str(exc))
            raise
        record(tool=fn.__name__, arguments=kwargs, result="ok")
        return output

    return wrapper
