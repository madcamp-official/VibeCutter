"""소스 기반 route 추출 → vc_map_routes (7.1절). Day2.

7.1절 소스 기반 신호 중 "Controller/route decorator"를 뽑는다. Spring Boot의
`@GetMapping`/`@PostMapping`/... 어노테이션에서 (HTTP method, path, handler)를 추출해
`Endpoint ↔ Source Symbol` 관계를 만든다 — 이게 surface/graph.py의 최종 그래프와
IDOR 후보의 출발점이 된다.

**P2의 target이 뜨지 않아도 소스만 있으면 동작한다.** Day2 오전에 아무에게도 안 막히는
작업이 이것이다.

Day2 초안은 정규식 파서다. 기획서 11.1절이 권하는 tree-sitter/ripgrep은 다중 path,
상수 참조 path(`@GetMapping(PATH_CONST)`), 메타 어노테이션 등을 정확히 다루기 위한
것이고, Day3+에 정확도가 필요해지면 교체한다. 현재 파서의 한계는 아래 KNOWN_LIMITATIONS
참고.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from pydantic import BaseModel

# @GetMapping 류 → HTTP method. @RequestMapping은 method= 속성에서 따로 뽑는다.
_MAPPING_METHOD = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}
_MAPPING_ANNOTATION = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b(?:\s*\(([^)]*)\))?", re.DOTALL
)
# 어노테이션 인자에서 경로 문자열을 뽑는다: value= / path= / 직접 리터럴 모두 커버.
_PATH_IN_ARGS = re.compile(r'(?:value|path)\s*=\s*"([^"]*)"|"([^"]*)"')
_METHOD_IN_REQUESTMAPPING = re.compile(r"method\s*=\s*(?:RequestMethod\.)?(\w+)")
# 어노테이션 아래에서 handler 메서드 이름을 찾는다(수식어/제네릭 리턴타입 뒤의 `name(`).
_HANDLER = re.compile(r"\b(\w+)\s*\(")
# 매핑 어노테이션과 실제 메서드 선언 사이에 낀 다른 어노테이션(@ResponseBody 등)을
# handler 로 오인하지 않도록, 이들을 건너뛴 첫 코드 줄에서 메서드 이름을 찾는다.
_JAVA_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "return", "new"})
_CLASS_DECL = re.compile(r"\b(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)")

KNOWN_LIMITATIONS = (
    "다중 path(@GetMapping({\"/a\",\"/b\"}))는 첫 번째만, "
    "상수/변수 path(@GetMapping(PATH))는 빈 문자열로, "
    "클래스 레벨 @RequestMapping은 파일당 1개로 가정."
)


class Route(BaseModel):
    """하나의 endpoint. Endpoint ↔ Source Symbol 관계의 최소 단위(7.1절)."""

    http_method: str  # GET/POST/PUT/DELETE/PATCH/ANY
    path: str  # 클래스 prefix + 메서드 path 를 합친 전체 경로
    handler: str  # "ClassName.methodName"
    source: str  # "상대경로.java:line"


def _find_handler(after: str) -> str:
    """매핑 어노테이션 뒤에서 실제 handler 메서드 이름을 찾는다.

    어노테이션 라인(@로 시작)과 빈 줄을 건너뛰고, 처음 나오는 코드 줄의 `name(` 을
    handler 로 본다 — `@ResponseStatus(...)` 같은 어노테이션이 사이에 껴도 그걸 handler
    로 오인하지 않는다.
    """
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
    if not m:
        return ""
    return m.group(1) or m.group(2) or ""


def _join(prefix: str, sub: str) -> str:
    """클래스 레벨 prefix 와 메서드 레벨 path 를 URL 경로로 합친다."""
    parts = [p.strip("/") for p in (prefix, sub) if p.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


def _class_prefix_and_name(text: str) -> tuple[str, str]:
    """파일에서 클래스 이름과, 클래스에 붙은 @RequestMapping prefix 를 찾는다.

    클래스 선언 직전 텍스트 안의 @RequestMapping 만 클래스 prefix 로 본다 — 메서드에
    붙은 @RequestMapping 을 클래스 prefix 로 오인하지 않도록.
    """
    cls = _CLASS_DECL.search(text)
    class_name = cls.group(1) if cls else "?"
    prefix = ""
    if cls:
        head = text[: cls.start()]
        for m in _MAPPING_ANNOTATION.finditer(head):
            if m.group(1) == "Request":
                prefix = _extract_path(m.group(2) or "")
    return prefix, class_name


def extract_routes(source_root: Path) -> list[Route]:
    """source_root 아래 모든 .java 컨트롤러에서 Route 목록을 뽑는다."""
    routes: list[Route] = []
    for java in sorted(source_root.rglob("*.java")):
        text = java.read_text(encoding="utf-8", errors="replace")
        if "Mapping" not in text:
            continue
        prefix, class_name = _class_prefix_and_name(text)
        rel = java.relative_to(source_root)

        for m in _MAPPING_ANNOTATION.finditer(text):
            kind, args = m.group(1), m.group(2) or ""
            if kind == "Request" and not _PATH_IN_ARGS.search(args):
                continue  # 클래스 prefix 용 @RequestMapping 은 endpoint 가 아니다
            line_no = text.count("\n", 0, m.start()) + 1

            if kind == "Request":
                mm = _METHOD_IN_REQUESTMAPPING.search(args)
                http_method = mm.group(1).upper() if mm else "ANY"
            else:
                http_method = _MAPPING_METHOD[kind + "Mapping"]

            sub = _extract_path(args)
            handler_name = _find_handler(text[m.end() : m.end() + 400])

            routes.append(
                Route(
                    http_method=http_method,
                    path=_join(prefix, sub),
                    handler=f"{class_name}.{handler_name}",
                    source=f"{rel}:{line_no}",
                )
            )
    return routes


if __name__ == "__main__":
    root = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path.cwd()
    found = extract_routes(root)
    for r in found:
        print(f"{r.http_method:6} {r.path:45} {r.handler:40} {r.source}")
    print(f"\n총 {len(found)}개 route @ {root}")
