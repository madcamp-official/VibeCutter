"""공유 SQLite 엔진.

`evidence_store.py`와 `audit_log.py`가 같은 `.vibecutter/evidence.db` 파일에 각자 별도
엔진을 만들던 걸 하나로 합친 것 — 경로/엔진 설정이 두 군데서 따로 관리되며 드리프트되는
것을 막고, 별도 커넥션 풀 2개가 같은 SQLite 파일에 동시에 쓰다 생길 수 있는 "database is
locked" 위험을 줄인다.

`get_engine()`은 호출할 때마다 `create_all`을 다시 실행한다 — 어떤 모듈이 먼저 import
되어 어떤 테이블이 먼저 SQLModel.metadata에 등록되든, 이후 호출 시점까지 등록된 테이블은
전부 생성되어 있음을 보장한다. SQLite에서 `create_all`은 `CREATE TABLE IF NOT EXISTS`와
동등해 반복 호출해도 안전하다.
"""

from __future__ import annotations

from pathlib import Path

from sqlmodel import SQLModel, create_engine

DATA_DIR = Path(__file__).resolve().parent.parent / ".vibecutter"
DB_PATH = DATA_DIR / "evidence.db"

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{DB_PATH}")
    SQLModel.metadata.create_all(_engine)
    return _engine
