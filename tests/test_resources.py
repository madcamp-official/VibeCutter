"""vibecutter://findings/{finding_id} resource 테스트 (Day2 섹션 4).

evidence_store에 저장된 실제 Finding을 돌려주는지, 없는 finding_id는 에러가 나는지 확인한다.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from uuid import uuid4

from contracts.schemas import Finding, FindingStatus
from core.evidence_store import save, update_finding_status, write_artifact


def _read_finding_resource(finding_id: str) -> dict:
    from mcp_server.server import mcp

    async def _read():
        result = await mcp.read_resource(f"vibecutter://findings/{finding_id}")
        return result[0].content

    return json.loads(asyncio.run(_read()))


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


if __name__ == "__main__":
    unittest.main()
