"""U3 egress 동의(`core/egress_consent.py`, TEAM_CONTRACT §3A-10) 테스트.

`core/kill_switch.py`/`tests/test_kill_switch.py`와 같은 패턴: durable marker는 실제
repo-local `.vibecutter/`에 쓰고, 각 테스트가 끝나면 `revoke_consent()`로 정리한다
(monkeypatch로 경로를 바꾸지 않는다 — 기존 kill switch 테스트 관례를 그대로 따른다).

핵심 완료 판정(U3): 동의 표시·기록이 남고, 동의 없이는 LLM 합성 경로로 넘어가지 않는다.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from core.egress_consent import consent_record, grant_consent, has_consented, revoke_consent


class EgressConsentCoreTests(unittest.TestCase):
    def tearDown(self) -> None:
        revoke_consent()

    def test_not_consented_by_default(self) -> None:
        self.assertFalse(has_consented())
        self.assertIsNone(consent_record())

    def test_grant_consent_records_actor_and_timestamp(self) -> None:
        record = grant_consent(actor="test-actor")
        self.assertTrue(has_consented())
        self.assertEqual(record["actor"], "test-actor")
        self.assertIn("granted_at", record)
        self.assertEqual(consent_record(), record)

    def test_grant_consent_is_idempotent_and_preserves_first_timestamp(self) -> None:
        first = grant_consent(actor="a")
        second = grant_consent(actor="b")  # 이미 동의한 상태 — 재호출은 최초 기록을 지키지 않음
        self.assertEqual(first, second)
        self.assertEqual(second["actor"], "a")

    def test_revoke_consent_is_idempotent(self) -> None:
        revoke_consent()  # 이미 꺼진 상태에서 호출해도 에러 없음
        grant_consent()
        revoke_consent()
        revoke_consent()
        self.assertFalse(has_consented())


class LlmClientGateTests(unittest.TestCase):
    """동의 없이는 vc_generate_patch의 LLM 클라이언트가 만들어지지 않는다."""

    def tearDown(self) -> None:
        from mcp_server.tools_repair import _reset_llm_client_cache

        revoke_consent()
        _reset_llm_client_cache()

    def setUp(self) -> None:
        from mcp_server.tools_repair import _reset_llm_client_cache

        revoke_consent()
        _reset_llm_client_cache()

    def test_no_consent_never_probes_endpoint(self) -> None:
        from mcp_server.tools_repair import _get_llm_client

        with patch("mcp_server.tools_repair.build_patch_model_client") as mock_build:
            client = _get_llm_client()
        self.assertIsNone(client)
        mock_build.assert_not_called()  # 동의 없으면 endpoint probe 자체를 안 한다

    def test_consent_granted_builds_client(self) -> None:
        from mcp_server.tools_repair import _get_llm_client

        grant_consent()
        sentinel = object()
        with patch("mcp_server.tools_repair.build_patch_model_client", return_value=sentinel) as mock_build:
            client = _get_llm_client()
        self.assertIs(client, sentinel)
        mock_build.assert_called_once()

    def test_revoking_consent_resets_cache_to_none(self) -> None:
        from mcp_server.tools_repair import _get_llm_client
        from core.egress_consent import revoke_consent as _revoke

        grant_consent()
        with patch("mcp_server.tools_repair.build_patch_model_client", return_value=object()):
            self.assertIsNotNone(_get_llm_client())

        _revoke()
        from mcp_server.tools_repair import _reset_llm_client_cache

        _reset_llm_client_cache()  # vc_consent_llm_egress(granted=False)가 하는 것과 동일
        with patch("mcp_server.tools_repair.build_patch_model_client") as mock_build:
            self.assertIsNone(_get_llm_client())
        mock_build.assert_not_called()


class RerankHookGateTests(unittest.TestCase):
    """동의 없이는 rerank용 코드 스니펫이 LLM으로 나가지 않는다."""

    def tearDown(self) -> None:
        revoke_consent()

    def test_no_consent_never_probes_endpoint(self) -> None:
        from mcp_server.tools_analysis import _rerank_hook_from_env

        with patch("model.endpoints.observed_chat_fn_from_env") as mock_observed:
            rerank_fn, outcome_fn = _rerank_hook_from_env()

        self.assertIsNone(rerank_fn)
        self.assertFalse(outcome_fn().llm_used)
        mock_observed.assert_not_called()

    def test_consent_granted_still_degrades_safely_when_endpoint_down(self) -> None:
        """동의는 '허용'일 뿐 endpoint 보장은 아니다 — 미설정 endpoint는 여전히 휴리스틱으로."""
        from mcp_server.tools_analysis import _rerank_hook_from_env

        grant_consent()
        rerank_fn, outcome_fn = _rerank_hook_from_env()
        self.assertIsNone(rerank_fn)
        self.assertFalse(outcome_fn().llm_used)


class ConsentToolAndResourceTests(unittest.TestCase):
    """vc_consent_llm_egress tool + vibecutter://consent/llm_egress resource 배선 확인."""

    def tearDown(self) -> None:
        from mcp_server.tools_repair import _reset_llm_client_cache

        revoke_consent()
        _reset_llm_client_cache()

    def _call(self, tool: str, args: dict):
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool(tool, args))

    def _read_resource(self, uri: str) -> dict:
        from mcp_server.server import mcp

        async def _read():
            result = await mcp.read_resource(uri)
            return result[0].content

        return json.loads(asyncio.run(_read()))

    def test_grant_then_revoke_round_trip(self) -> None:
        _, granted = self._call("vc_consent_llm_egress", {"granted": True})
        self.assertTrue(granted["granted"])
        self.assertIsNotNone(granted["granted_at"])
        self.assertTrue(has_consented())

        _, revoked = self._call("vc_consent_llm_egress", {"granted": False})
        self.assertFalse(revoked["granted"])
        self.assertFalse(has_consented())

    def test_resource_reflects_current_status(self) -> None:
        body = self._read_resource("vibecutter://consent/llm_egress")
        self.assertFalse(body["granted"])

        self._call("vc_consent_llm_egress", {"granted": True})
        body = self._read_resource("vibecutter://consent/llm_egress")
        self.assertTrue(body["granted"])
        self.assertIsNotNone(body["granted_at"])


if __name__ == "__main__":
    unittest.main()
