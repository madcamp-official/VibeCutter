"""vibecutter://findings/{finding_id} resource 테스트 (Day2 섹션 4).

evidence_store에 저장된 실제 Finding을 돌려주는지, 없는 finding_id는 에러가 나는지 확인한다.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from uuid import uuid4

from contracts.schemas import Finding, FindingStatus, Observation, Run, RunState
from core.evidence_store import save, update_finding_status, write_artifact

REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _read_resource(uri: str) -> str:
    from mcp_server.server import mcp

    async def _read():
        result = await mcp.read_resource(uri)
        return result[0].content

    return asyncio.run(_read())


def _read_finding_resource(finding_id: str) -> dict:
    return json.loads(_read_resource(f"vibecutter://findings/{finding_id}"))


class FindingResourceTests(unittest.TestCase):
    def test_returns_real_finding_from_evidence_store(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="resource test", cwe="CWE-639"
        )
        save(finding)
        obs = write_artifact(run_id, observation_type="http_exchange", producer="test", data=b"x")
        update_finding_status(finding.id, FindingStatus.VERIFIED, evidence_ids=[obs.id])

        body = _read_finding_resource(finding.id)
        self.assertEqual(body["id"], finding.id)
        self.assertEqual(body["verification_state"], "verified")
        self.assertIn(obs.id, body["evidence_ids"])

    def test_missing_finding_raises(self) -> None:
        with self.assertRaises(Exception):
            _read_finding_resource("finding-does-not-exist")


class RunStateResourceTests(unittest.TestCase):
    """2-1: run state/evidence를 더미가 아니라 실제 evidence_store에서 조회한다."""

    def test_run_state_reflects_actual_status(self) -> None:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id=REGISTERED_TARGET_ID, status=RunState.VERIFIED)
        save(run)
        body = json.loads(_read_resource(f"vibecutter://runs/{run.id}/state"))
        self.assertEqual(body["id"], run.id)
        self.assertEqual(body["status"], "VERIFIED")  # 예전엔 항상 REGISTERED 더미였다

    def test_missing_run_raises(self) -> None:
        with self.assertRaises(Exception):
            _read_resource(f"vibecutter://runs/run-{uuid4().hex[:12]}-nope/state")

    def test_run_evidence_lists_real_observations(self) -> None:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id=REGISTERED_TARGET_ID)
        save(run)
        obs = write_artifact(run.id, observation_type="http_exchange", producer="verifier", data=b"x")
        body = json.loads(_read_resource(f"vibecutter://runs/{run.id}/evidence"))
        self.assertEqual([o["id"] for o in body], [obs.id])

    def test_run_evidence_empty_for_run_without_observations(self) -> None:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id=REGISTERED_TARGET_ID)
        save(run)
        body = json.loads(_read_resource(f"vibecutter://runs/{run.id}/evidence"))
        self.assertEqual(body, [])


class TargetResourceTests(unittest.TestCase):
    """2-1: targets/manifest를 P2 catalog 실데이터로 조회한다."""

    def test_targets_lists_checked_in_catalog(self) -> None:
        body = json.loads(_read_resource("vibecutter://targets"))
        ids = {t["id"] for t in body}
        self.assertIn(REGISTERED_TARGET_ID, ids)  # checked-in manifest가 목록에 있다

    def test_manifest_returns_real_catalog_manifest(self) -> None:
        body = json.loads(_read_resource(f"vibecutter://targets/{REGISTERED_TARGET_ID}/manifest"))
        self.assertEqual(body["id"], REGISTERED_TARGET_ID)

    def test_missing_target_manifest_raises(self) -> None:
        with self.assertRaises(Exception):
            _read_resource("vibecutter://targets/not-a-real-target/manifest")


if __name__ == "__main__":
    unittest.main()
