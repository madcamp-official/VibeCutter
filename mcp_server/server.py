from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vibecutter")

@mcp.resource("vibecutter://targets")
def list_targets() -> str:
    return "[]"  # 더미

@mcp.tool()
def vc_ping() -> str:
    return "pong"

if __name__ == "__main__":
    mcp.run(transport="stdio")