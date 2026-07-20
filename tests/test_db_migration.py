"""core.db additive auto-migration 테스트 (Extra Day, D5-P2.md 대응).

`Candidate.origin_candidate_id`(1B-1)를 스키마에 추가하자, 예전 `.vibecutter/evidence.db`가
있는 팀원의 worker-run 테스트가 `no such column`으로 깨졌다(P2 보고). `create_all()`은 기존
테이블에 컬럼을 추가하지 않으므로, `_apply_additive_migrations()`가 nullable 컬럼을 ALTER
TABLE로 채운다 — DB를 폐기하지 않고 기존 데이터를 보존한다.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import create_engine

from core.db import _apply_additive_migrations


class AdditiveMigrationTests(unittest.TestCase):
    def test_adds_missing_column_and_preserves_existing_rows(self) -> None:
        with TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'old.db'}")
            # origin_candidate_id 없는 예전 candidate 테이블 + 기존 데이터.
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    "CREATE TABLE candidate (id VARCHAR PRIMARY KEY, run_id VARCHAR, cwe VARCHAR)"
                )
                conn.exec_driver_sql(
                    "INSERT INTO candidate (id, run_id, cwe) VALUES ('old-cand', 'old-run', 'CWE-639')"
                )

            _apply_additive_migrations(engine)

            with engine.begin() as conn:
                cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(candidate)")}
                rows = conn.exec_driver_sql(
                    "SELECT id, origin_candidate_id FROM candidate"
                ).fetchall()

        self.assertIn("origin_candidate_id", cols)
        self.assertEqual(rows, [("old-cand", None)])  # 기존 데이터 보존 + 새 컬럼 NULL

    def test_is_idempotent_when_column_already_exists(self) -> None:
        with TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'db.db'}")
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    "CREATE TABLE candidate (id VARCHAR PRIMARY KEY, origin_candidate_id VARCHAR)"
                )
            # 이미 컬럼이 있어도 두 번 호출해서 에러가 없어야 한다.
            _apply_additive_migrations(engine)
            _apply_additive_migrations(engine)

            with engine.begin() as conn:
                cols = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(candidate)")]
        # 컬럼이 중복 추가되지 않는다.
        self.assertEqual(cols.count("origin_candidate_id"), 1)

    def test_adds_audit_log_run_id_column(self) -> None:
        # D5-P2: audit_log에도 뒤늦게 추가된 run_id 컬럼을 기존 DB에 채운다.
        with TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'old.db'}")
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, tool VARCHAR, result VARCHAR)"
                )
                conn.exec_driver_sql("INSERT INTO audit_log (tool, result) VALUES ('vc_ping', 'ok')")

            _apply_additive_migrations(engine)

            with engine.begin() as conn:
                cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(audit_log)")}
                rows = conn.exec_driver_sql("SELECT tool, run_id FROM audit_log").fetchall()
        self.assertIn("run_id", cols)
        self.assertEqual(rows, [("vc_ping", None)])

    def test_skips_table_that_does_not_exist_yet(self) -> None:
        # 테이블이 아직 없으면(=fresh DB) create_all이 최신 스키마로 만들므로 migration은 no-op.
        with TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'fresh.db'}")
            _apply_additive_migrations(engine)  # 예외 없이 통과해야 한다.


if __name__ == "__main__":
    unittest.main()
