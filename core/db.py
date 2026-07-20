"""공유 SQLite 엔진.

`evidence_store.py`와 `audit_log.py`가 같은 `.vibecutter/evidence.db` 파일에 각자 별도
엔진을 만들던 걸 하나로 합친 것 — 경로/엔진 설정이 두 군데서 따로 관리되며 드리프트되는
것을 막고, 별도 커넥션 풀 2개가 같은 SQLite 파일에 동시에 쓰다 생길 수 있는 "database is
locked" 위험을 줄인다.

`get_engine()`은 호출할 때마다 `create_all`을 다시 실행한다 — 어떤 모듈이 먼저 import
되어 어떤 테이블이 먼저 SQLModel.metadata에 등록되든, 이후 호출 시점까지 등록된 테이블은
전부 생성되어 있음을 보장한다. SQLite에서 `create_all`은 `CREATE TABLE IF NOT EXISTS`와
동등해 반복 호출해도 안전하다.

`create_all`은 **기존 테이블에 컬럼을 추가하지 않는다** — 그래서 additive 컬럼(예:
`candidate.origin_candidate_id`, Extra Day 1B-1)을 스키마에 넣으면 예전 `.vibecutter/
evidence.db`가 있는 팀원은 `no such column`으로 깨진다(D5-P2.md가 실제로 겪음). 팀 전원이
DB를 지우게 하는 대신, `_apply_additive_migrations()`가 알려진 nullable 컬럼을 PRAGMA로
확인해 없으면 `ALTER TABLE ADD COLUMN`으로 채운다(idempotent). SQLite `ADD COLUMN`은
nullable/default 컬럼만 안전하게 추가할 수 있어 additive 계약과 정확히 일치한다. 파괴적
스키마 변경(컬럼 rename/타입 변경)은 여전히 DB 재생성이 필요하다.
"""

from __future__ import annotations

from pathlib import Path

from sqlmodel import SQLModel, create_engine

DATA_DIR = Path(__file__).resolve().parent.parent / ".vibecutter"
DB_PATH = DATA_DIR / "evidence.db"

# 기존 DB에 뒤늦게 추가된 nullable 컬럼: {table_name: [(column_name, sqlite_type), ...]}.
# create_all이 못 만드는 것만 여기 등록한다. 새 additive 컬럼을 스키마에 넣을 때 함께 추가.
_ADDITIVE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "candidate": [("origin_candidate_id", "VARCHAR")],
}

_engine = None


def _apply_additive_migrations(engine) -> None:
    """등록된 additive 컬럼이 기존 테이블에 없으면 ALTER TABLE로 추가한다(idempotent)."""
    with engine.begin() as conn:
        for table, columns in _ADDITIVE_COLUMNS.items():
            info = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            if not info:
                continue  # 테이블 자체가 아직 없으면 create_all이 최신 스키마로 만든다.
            existing = {row[1] for row in info}  # PRAGMA table_info: (cid, name, type, ...)
            for name, sqltype in columns:
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")


def get_engine():
    global _engine
    if _engine is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{DB_PATH}")
    SQLModel.metadata.create_all(_engine)
    _apply_additive_migrations(_engine)
    return _engine
