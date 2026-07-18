"""소스 기반 route 추출 → vc_map_routes(7.1절) + locator 근본원인 위치(7.4절).

Spring(`@*Mapping`) 외에 **FastAPI 데코레이터·Express 라우터·Django urls**를 추출한다 —
locator가 비-Spring 타깃(FastAPI/Node/Django)에서도 endpoint→handler 파일을 짚어, 저신뢰
code_index 추측(프론트엔드 오탐)으로 떨어지지 않게 한다(D4 P1 요청: 5개 중 4개가 비-Spring).

스택별 추출:
  - Java(Spring)   : `@GetMapping/...` + 클래스 `@RequestMapping` prefix. (기존, 무변경)
  - Python(FastAPI): `@app|router.<method>("path")` + `APIRouter(prefix=...)` + 같은 파일 handler `def`.
  - Node(Express)  : `<router>.<method>("path", ..., handler)` + `app.use("/prefix", router)` 마운트
                     + `router.use("/sub", ...)` 서브prefix (2-pass).
  - Python(Django) : `urls.py`의 `path("route", view)` — best-effort(클래스뷰 미해결, 로컬 미검증).

`node_modules/dist/build/.next` 등 빌드·프론트엔드 산출물 디렉터리는 스캔에서 제외한다.

Day2 초안은 정규식 파서다(기획서 11.1절의 tree-sitter는 정확도가 더 필요해지면 교체).
현재 파서의 한계는 KNOWN_LIMITATIONS 참고.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from pydantic import BaseModel

# ── 공통 ─────────────────────────────────────────────────────────────────────────

# 스캔 제외: 의존성·빌드 산출물·VCS. 프론트엔드 소스 자체(.tsx 등)는 파서가 자연히 안 잡지만,
# code_index 폴백 오탐은 locator의 프론트엔드 가드가 별도로 막는다.
_SKIP_DIRS = frozenset({
    "node_modules", "dist", "build", ".next", ".git", "__pycache__", ".venv", "venv",
    "coverage", ".turbo", "out", ".cache", ".pytest_cache", "migrations",
})


def _skip(p: Path, root: Path) -> bool:
    return any(part in _SKIP_DIRS for part in p.relative_to(root).parts[:-1])


class Route(BaseModel):
    """하나의 endpoint. Endpoint ↔ Source Symbol 관계의 최소 단위(7.1절)."""

    http_method: str  # GET/POST/PUT/DELETE/PATCH/ANY
    path: str  # (마운트/클래스 prefix 결합한) 전체 경로
    handler: str  # "Symbol.method" 또는 handler 이름
    source: str  # "상대경로:line"
    stack: str = "spring"  # spring | fastapi | express | django


def _join(prefix: str, sub: str) -> str:
    """prefix 와 sub 경로를 URL 경로로 합친다."""
    parts = [p.strip("/") for p in (prefix, sub) if p and p.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


# ══ Java / Spring (기존 로직 — 무변경) ══════════════════════════════════════════════

_MAPPING_METHOD = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT",
    "DeleteMapping": "DELETE", "PatchMapping": "PATCH",
}
_MAPPING_ANNOTATION = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b(?:\s*\(([^)]*)\))?", re.DOTALL
)
_PATH_IN_ARGS = re.compile(r'(?:value|path)\s*=\s*"([^"]*)"|"([^"]*)"')
_METHOD_IN_REQUESTMAPPING = re.compile(r"method\s*=\s*(?:RequestMethod\.)?(\w+)")
_HANDLER = re.compile(r"\b(\w+)\s*\(")
_JAVA_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "new"})
_CLASS_DECL = re.compile(r"\b(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)")

KNOWN_LIMITATIONS = (
    "Spring 다중 path는 첫 번째만/상수 path는 빈 문자열; FastAPI/Express는 정규식이라 "
    "다중 데코레이터·동적 prefix·인라인 arrow handler는 근사치; Django 클래스뷰 미지원."
)


def _find_handler(after: str) -> str:
    for line in after.splitlines():
        s = line.strip()
        if not s or s.startswith("@"):
            continue
        m = _HANDLER.search(s)
        if m and m.group(1) not in _JAVA_KEYWORDS:
            return m.group(1)
    return "?"


def _extract_path(args: str) -> str:
    m = _PATH_IN_ARGS.search(args or "")
    return (m.group(1) or m.group(2) or "") if m else ""


def _class_prefix_and_name(text: str) -> tuple[str, str]:
    cls = _CLASS_DECL.search(text)
    class_name = cls.group(1) if cls else "?"
    prefix = ""
    if cls:
        head = text[: cls.start()]
        for m in _MAPPING_ANNOTATION.finditer(head):
            if m.group(1) == "Request":
                prefix = _extract_path(m.group(2) or "")
    return prefix, class_name


def _extract_java_routes(text: str, rel: str) -> list[Route]:
    routes: list[Route] = []
    prefix, class_name = _class_prefix_and_name(text)
    for m in _MAPPING_ANNOTATION.finditer(text):
        kind, args = m.group(1), m.group(2) or ""
        if kind == "Request" and not _PATH_IN_ARGS.search(args):
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        if kind == "Request":
            mm = _METHOD_IN_REQUESTMAPPING.search(args)
            http_method = mm.group(1).upper() if mm else "ANY"
        else:
            http_method = _MAPPING_METHOD[kind + "Mapping"]
        sub = _extract_path(args)
        handler_name = _find_handler(text[m.end() : m.end() + 400])
        routes.append(Route(
            http_method=http_method, path=_join(prefix, sub),
            handler=f"{class_name}.{handler_name}", source=f"{rel}:{line_no}", stack="spring",
        ))
    return routes


# ══ Python / FastAPI ════════════════════════════════════════════════════════════════

_PY_ROUTE = re.compile(r"@(\w+)\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE)
_PY_APIROUTER_PREFIX = re.compile(r"APIRouter\((?:[^)]*?)prefix\s*=\s*[\"']([^\"']*)[\"']", re.DOTALL)
_PY_FIRST_STR = re.compile(r"[\"']([^\"']*)[\"']")
_PY_DEF = re.compile(r"(?:async\s+)?def\s+(\w+)\s*\(")


def _extract_fastapi_routes(text: str, rel: str) -> list[Route]:
    pm = _PY_APIROUTER_PREFIX.search(text)
    prefix = pm.group(1) if pm else ""
    module = Path(rel).stem
    routes: list[Route] = []
    for m in _PY_ROUTE.finditer(text):
        method = m.group(2).upper()
        sm = _PY_FIRST_STR.search(text, m.end(), m.end() + 300)  # 데코레이터 첫 문자열 = path
        path = sm.group(1) if sm else ""
        dm = _PY_DEF.search(text, m.end())  # 데코레이터 뒤 첫 def = handler
        handler = dm.group(1) if dm else "?"
        line_no = text.count("\n", 0, m.start()) + 1
        routes.append(Route(
            http_method=method, path=_join(prefix, path),
            handler=f"{module}.{handler}", source=f"{rel}:{line_no}", stack="fastapi",
        ))
    return routes


# ══ Python / Django (best-effort) ═══════════════════════════════════════════════════

_DJANGO_PATH = re.compile(r"\b(?:re_path|path)\s*\(\s*[\"']([^\"']*)[\"']\s*,\s*([\w.]+)")


def _extract_django_routes(text: str, rel: str) -> list[Route]:
    routes: list[Route] = []
    for m in _DJANGO_PATH.finditer(text):
        path, view = m.group(1), m.group(2)
        line_no = text.count("\n", 0, m.start()) + 1
        routes.append(Route(
            http_method="ANY", path=_join("", path), handler=view,
            source=f"{rel}:{line_no}", stack="django",
        ))
    return routes


# ══ Node / Express (2-pass: 라우터 마운트/서브prefix 해석) ════════════════════════════

_JS_METHOD_CALL = re.compile(r"\b(\w+)\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE)
_JS_MOUNT = re.compile(r"\b(\w+)\.use\s*\(\s*[\"'`]([^\"'`]+)[\"'`]\s*,\s*(\w+)\s*\)")  # app.use("/api", router)
_JS_ROUTER_DECL = re.compile(r"\b(\w+)\s*=\s*(?:\w+\.)?Router\s*\(\s*\)")  # x = Router() / express.Router()
_JS_APP_DECL = re.compile(r"\b(\w+)\s*=\s*express\s*\(\s*\)")  # app = express()
_JS_FIRST_STR = re.compile(r"[\"'`]([^\"'`]*)[\"'`]")
_JS_IDENT = re.compile(r"\b([A-Za-z_]\w*)\b")


class _ExpressCtx(BaseModel):
    router_vars: set[str] = set()       # Router()/express()로 선언된 변수만 — axios/api.get 오탐 방지
    app_like: set[str] = set()          # express() 앱 + 라우터를 마운트하는 변수. 라우트 path 그대로.
    mount_prefix: dict[str, str] = {}   # routerVar → app.use("/prefix", router) 마운트 prefix


def _collect_express_context(texts: list[str]) -> _ExpressCtx:
    ctx = _ExpressCtx()
    for text in texts:  # router는 실제 Router()/express() 선언만 인정(프론트 axios.get 등 배제)
        for m in _JS_APP_DECL.finditer(text):
            ctx.router_vars.add(m.group(1))
            ctx.app_like.add(m.group(1))
        for m in _JS_ROUTER_DECL.finditer(text):
            ctx.router_vars.add(m.group(1))
    for text in texts:  # app.use("/api", router) 마운트만 prefix로 취급.
        for m in _JS_MOUNT.finditer(text):  # router.use("/x", 미들웨어)는 미들웨어 스코프라 경로 prefix 아님 → 무시
            var, prefix, mounted = m.group(1), m.group(2), m.group(3)
            if mounted in ctx.router_vars:
                ctx.mount_prefix[mounted] = prefix
                ctx.app_like.add(var)
    return ctx


def _extract_express_routes(text: str, rel: str, ctx: _ExpressCtx) -> list[Route]:
    routes: list[Route] = []
    for m in _JS_METHOD_CALL.finditer(text):
        var, method = m.group(1), m.group(2).upper()
        if var not in ctx.router_vars:
            continue
        sm = _JS_FIRST_STR.search(text, m.end(), m.end() + 200)
        path = sm.group(1) if sm else ""
        # app-level 라우트는 전체 경로, 마운트된 라우터는 마운트 prefix + 라우트 경로.
        prefix = "" if var in ctx.app_like else ctx.mount_prefix.get(var, "")
        full = _join(prefix, path)
        tail = text[m.end() : m.end() + 300]
        cut = tail.find(")")
        idents = _JS_IDENT.findall(tail[:cut] if cut >= 0 else tail)
        handler = idents[-1] if idents else "?"  # 마지막 인자=컨트롤러(path 속 단어는 중간이라 제외)
        line_no = text.count("\n", 0, m.start()) + 1
        routes.append(Route(
            http_method=method, path=full, handler=handler, source=f"{rel}:{line_no}", stack="express",
        ))
    return routes


# ══ 진입점 ══════════════════════════════════════════════════════════════════════════


def _read(f: Path) -> str:
    return f.read_text(encoding="utf-8", errors="replace")


def extract_routes(source_root: Path | str) -> list[Route]:
    """source_root 아래 Spring/FastAPI/Express/Django route 를 모두 뽑는다."""
    root = Path(source_root)
    routes: list[Route] = []

    for java in sorted(root.rglob("*.java")):
        if _skip(java, root):
            continue
        text = _read(java)
        if "Mapping" in text:
            routes += _extract_java_routes(text, str(java.relative_to(root)))

    for py in sorted(root.rglob("*.py")):
        if _skip(py, root):
            continue
        text = _read(py)
        rel = str(py.relative_to(root))
        if _PY_ROUTE.search(text):
            routes += _extract_fastapi_routes(text, rel)
        if py.name == "urls.py":
            routes += _extract_django_routes(text, rel)

    js_files = [
        f for f in sorted([*root.rglob("*.ts"), *root.rglob("*.js")])
        if not _skip(f, root) and not f.name.endswith(".d.ts")
    ]
    js_texts = {f: _read(f) for f in js_files}
    ctx = _collect_express_context(list(js_texts.values()))
    for f, text in js_texts.items():
        if _JS_METHOD_CALL.search(text):
            routes += _extract_express_routes(text, str(f.relative_to(root)), ctx)

    return routes


if __name__ == "__main__":
    root = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path.cwd()
    found = extract_routes(root)
    for r in found:
        print(f"{r.stack:8} {r.http_method:6} {r.path:45} {r.handler:35} {r.source}")
    print(f"\n총 {len(found)}개 route @ {root}")
