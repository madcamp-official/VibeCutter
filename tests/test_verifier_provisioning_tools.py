from __future__ import annotations

import asyncio
import unittest

from mcp_server.server import mcp


class VerifierProvisioningToolContractTests(unittest.TestCase):
    def test_provisioning_tools_are_registered_with_explicit_approval_field(self) -> None:
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        self.assertIn("vc_get_verifier_provisioning", tools)
        self.assertIn("vc_prepare_verifier_fixture", tools)
        prepare_schema = tools["vc_prepare_verifier_fixture"].inputSchema
        self.assertIn("approved", prepare_schema["properties"])
        self.assertIn("approved", prepare_schema["required"])
