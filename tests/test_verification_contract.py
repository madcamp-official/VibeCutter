from __future__ import annotations

import asyncio
import unittest

from contracts.schemas import VerificationResult
from verifiers.types import VerifierOutput


class VerificationResultUnificationTests(unittest.TestCase):
    """D1-P3.md 지적: mcp_server.VerifyResult와 verifiers.types.VerifierOutput 중복 제거 회귀."""

    def test_verifier_output_is_the_shared_contract_type(self) -> None:
        self.assertIs(VerifierOutput, VerificationResult)


class MaxRequestsSchemaTests(unittest.TestCase):
    """D1-P3.md 구멍 ③: max_requests가 실제 inputSchema에 ge=1,le=20으로 반영되는지 확인."""

    def test_vc_verify_access_control_max_requests_is_bounded(self) -> None:
        from mcp_server.server import mcp

        tools = asyncio.run(mcp.list_tools())
        tool = next(t for t in tools if t.name == "vc_verify_access_control")
        schema = tool.inputSchema["properties"]["max_requests"]
        self.assertEqual(schema["minimum"], 1)
        self.assertEqual(schema["maximum"], 20)
        self.assertEqual(schema["default"], 10)

    def test_all_three_verify_tools_share_the_bound(self) -> None:
        from mcp_server.server import mcp

        tools = asyncio.run(mcp.list_tools())
        for name in ("vc_verify_access_control", "vc_verify_injection", "vc_verify_xss"):
            tool = next(t for t in tools if t.name == name)
            schema = tool.inputSchema["properties"]["max_requests"]
            self.assertEqual((schema["minimum"], schema["maximum"]), (1, 20), msg=name)


if __name__ == "__main__":
    unittest.main()
