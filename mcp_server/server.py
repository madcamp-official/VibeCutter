import sys
from pathlib import Path

# `python mcp_server/server.py`로 직접 실행하면 Python이 이 파일의 디렉터리(mcp_server/)만
# sys.path에 넣고 저장소 루트는 넣지 않아 `core`/`contracts` import가 깨진다. MCP Host가
# 보통 이 파일을 `python mcp_server/server.py` 형태로 subprocess 실행하므로, 여기서 저장소
# 루트를 명시적으로 추가해 `python -m mcp_server.server`로 실행하지 않아도 항상 동작하게 한다.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from core.audit_log import audited  # noqa: E402
from mcp_server import resources, tools_analysis, tools_control, tools_inventory, tools_repair  # noqa: E402

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
tools_control.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
