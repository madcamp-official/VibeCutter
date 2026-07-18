"""`audit_local_target` MCP Prompt(6.5절, Day4) 등록 테스트.

Prompt는 파이프라인을 실행하는 코드가 아니라 Host에게 주는 안내 텍스트이므로, 여기서는
"등록돼 있고, target_id를 반영하고, 승인/재시도 상한/kill switch 규칙을 언급하는지"만
확인한다. 실제 안전 강제는 각 tool(vc_apply_patch/vc_generate_patch/vc_pause)이
별도로 테스트한다.
"""

from __future__ import annotations

import asyncio
import unittest


class AuditLocalTargetPromptTests(unittest.TestCase):
    def _get(self, target_id: str):
        from mcp_server.server import mcp

        return asyncio.run(mcp.get_prompt("audit_local_target", {"target_id": target_id}))

    def test_registered_and_lists_key_tools(self) -> None:
        result = self._get("26s-w1-c2-04")
        text = " ".join(m.content.text for m in result.messages)

        self.assertIn("26s-w1-c2-04", text)
        for tool_name in (
            "vc_scan_access_control",
            "vc_verify_access_control",
            "vc_apply_patch",
            "vc_generate_patch",
            "vc_pause",
        ):
            self.assertIn(tool_name, text)

    def test_mentions_approval_and_retry_cap(self) -> None:
        result = self._get("some-target")
        text = " ".join(m.content.text for m in result.messages)

        self.assertIn("승인", text)
        self.assertIn("3", text)  # 재시도 상한 3회 언급


if __name__ == "__main__":
    unittest.main()
