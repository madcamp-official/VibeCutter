from mcp.server.fastmcp import FastMCP

from core.audit_log import audited
from mcp_server import resources, tools_analysis, tools_inventory, tools_repair

mcp = FastMCP("vibecutter")


@mcp.tool()
@audited
def vc_ping() -> str:
    """stdio 연결 스모크 테스트용."""
    return "pong"


resources.register(mcp)
tools_inventory.register(mcp)
tools_analysis.register(mcp)
tools_repair.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
