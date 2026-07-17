from mcp.server.fastmcp import FastMCP

from mcp_server import tools_analysis, tools_inventory, tools_repair

mcp = FastMCP("vibecutter")


@mcp.resource("vibecutter://targets")
def list_targets() -> str:
    return "[]"  # 더미 — item 7(MCP Resources 뼈대 구현)에서 resources.py로 옮길 예정


@mcp.tool()
def vc_ping() -> str:
    """stdio 연결 스모크 테스트용."""
    return "pong"


tools_inventory.register(mcp)
tools_analysis.register(mcp)
tools_repair.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
