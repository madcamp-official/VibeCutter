"""IDOR attack-surface 프리필터 — Day1 'endpoint↔role graph'의 실용판 (7.1절).

소스에서 handler를 훑어 **"id-addressable(자원 id로 접근) + handler가 현재 사용자 미참조 +
id가 실제 조회/호출에 쓰임"**인 것을 IDOR 후보로 랭킹한다. batch/P4가 "어느 앱·어느 엔드포인트를
verify할지"를 감이 아니라 데이터로 고르게 하는 candidate 생성기(= 내가 손으로 하던 발견의 자동화).

프리필터라 recall 우선 — 최종 verified는 verifier의 evidence 게이트가 판정한다.

정밀도 개선(v2):
  1) handler 본문을 정확히 추출 — Python 들여쓰기 블록 / Java·Node 중괄호 매칭(고정 window 폐기).
  2) Node/Express: route가 참조하는 controller 정의를 찾아 그 본문에서 현재사용자 참조 확인.
  3) "id가 실제로 조회/호출에 쓰이나"까지 확인 → 단순 echo stub(예: FastAPI 튜토리얼 `/items/{id}`) 제외.
  4) admin 경로(/admin, adminMiddleware)는 per-user 인가 모델이 아니라 별도 → IDOR 후보에서 제외.

지원 스택: Java(Spring `@*Mapping`), Python(FastAPI/Flask/Django decorator), Node(Express router).
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from pydantic import BaseModel

from surface.roles import references_current_user
from surface.routes import _class_prefix_and_name, _join

# --- 경로/시그니처의 자원 id 신호 ---
_ID_IN_PATH = re.compile(r"\{[^}]*id[^}]*\}|:[A-Za-z_]*id\w*|<[^>]*id[^>]*>", re.IGNORECASE)
_ID_NAME_IN_PATH = re.compile(r"[{:<]\s*(?:int:|str:|uuid:|path:)?(\w*id\w*)", re.IGNORECASE)
# 시그니처의 id 파라미터. 'valid'/'invalid' 오탐을 피하려 Id는 대문자 I만, 나머지는 _id/standalone id.
_ID_IN_SIG = re.compile(r"@PathVariable|@RequestParam|req\.params|request\.args|\b\w+_id\b|\b[a-z]\w*Id\b|\bid\b")

# 사용자 소유 자원이 아닌 경로(인증/유틸) — 프리필터에서 제외
_NON_RESOURCE_PATH = re.compile(
    r"/(?:login|signup|sign-up|register|logout|refresh|token|health|time|kakao|callback|csrf|docs|openapi|ping)\b",
    re.IGNORECASE,
)
# admin 경로/미들웨어 — per-user IDOR이 아니라 권한(privilege) 모델이라 별도로 뺀다
_ADMIN = re.compile(r"/admin\b|admin[_-]?middleware|requireAdmin|isAdmin|adminMiddleware|@PreAuthorize\([^)]*ADMIN", re.IGNORECASE)

# id가 '사용'된 정황: 함수 호출 word( / 쿼리·비교 연산. (단순 return-dict echo는 여기 안 걸림)
_CALL_OR_QUERY = re.compile(
    r"[A-Za-z_]\w*\s*\(|filter|where|==|===|!=|findBy|findUnique|findFirst|findById|\.find\b|\.get\(|query|repository|service|\.objects|select",
    re.IGNORECASE,
)

_SKIP_DIRS = ("node_modules", "/test", "/tests", "/dist", "/build", "/migrations", "/__pycache__", "/.next")

_JAVA_MARK = re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\((?:[^)]*?\"([^\"]*)\")?", re.DOTALL)
_PY_MARK = re.compile(r"@\w+\.(?:get|post|put|patch|delete|route)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_NODE_CALL = re.compile(r"\.\s*(?:get|post|put|patch|delete)\s*\(", re.IGNORECASE)
_NODE_DECL = re.compile(r"(?:export\s+)?(?:const|let|var|function)\s+(\w+)")
# 라우트에 **인라인**으로 박힌 핸들러: `(req,res)=>{`, `req=>{`, `function(req,res){`. 심볼 참조가
# 아니라 본문이 라우트 콜 안에 직접 있어 심볼 인덱스로는 못 잡는다(Express에서 매우 흔함).
_NODE_INLINE_FN = re.compile(
    r"(?:async\s+)?(?:\([^)]*\)|\w+)\s*=>\s*\{"      # (req,res)=>{ / req=>{
    r"|(?:async\s+)?function\s*\*?\s*\w*\s*\([^)]*\)\s*\{",  # function (req,res){
    re.IGNORECASE,
)

KNOWN_LIMITATIONS = (
    "휴리스틱 프리필터다(정밀 인가분석 아님). 인증된 route에서 handler가 현재사용자를 '참조는 하되 "
    "스코프엔 안 쓰는' 미묘한 IDOR은 놓칠 수 있다(그 경우 verifier가 잡는다). 클래스 기반 Django view 미지원."
)


class IdorSuspect(BaseModel):
    """IDOR 의심 endpoint 하나 (프리필터 산출)."""

    file: str
    endpoint: str
    handler: str = ""
    id_param: str = ""
    id_signal: str  # "path" | "signature"
    score: float
    reason: str


# ── 본문 추출 유틸 ──────────────────────────────────────────────────────────────────


def _brace_body(text: str, open_idx: int) -> str:
    """`{`(open_idx)부터 매칭되는 `}`까지. 문자열 내 중괄호는 근사적으로 무시하지 않음(휴리스틱)."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1]
    return text[open_idx : open_idx + 2000]


def _paren_args(text: str, open_idx: int) -> str:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
    return text[open_idx + 1 : open_idx + 600]


def _iter_sources(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in (".java", ".py", ".ts", ".js"):
            continue
        s = str(p)
        if any(d in s for d in _SKIP_DIRS) or s.endswith((".d.ts", ".test.ts", ".spec.ts", ".test.js")):
            continue
        yield p


# ── 스택별 handler 추출: (path, name, signature, body) ────────────────────────────────


def _java_handlers(text: str):
    prefix, _cls = _class_prefix_and_name(text)  # 클래스 레벨 @RequestMapping prefix 결합
    for m in _JAVA_MARK.finditer(text):
        path = m.group(1) or ""
        after = text[m.end() :]
        sm = re.search(r"([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*(?:throws [\w., ]+)?\{", after, re.DOTALL)
        if not sm:
            continue
        brace = after.index("{", sm.end() - 1)
        yield _join(prefix, path), sm.group(1), sm.group(2), _brace_body(after, brace)


def _python_handlers(text: str):
    """멀티라인 데코레이터/시그니처를 모두 처리한다 — finditer(전체 텍스트) + 괄호 균형으로
    시그니처 끝(`):`)을 찾고, 그 뒤부터 def 들여쓰기 아래까지를 본문으로 잡는다."""
    lines = text.splitlines()
    starts, off = [], 0
    for ln in lines:
        starts.append(off)
        off += len(ln) + 1

    seen: set[int] = set()
    for m in _PY_MARK.finditer(text):  # 데코레이터가 여러 줄이어도 path를 잡는다
        li = bisect.bisect_right(starts, m.start()) - 1
        j = li
        while j < len(lines) and not re.match(r"\s*(?:async\s+)?def\s+\w+", lines[j]):
            if j - li > 10:
                break
            j += 1
        dm = re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[j]) if j < len(lines) else None
        if not dm or j in seen:
            continue
        seen.add(j)

        base = len(lines[j]) - len(lines[j].lstrip())
        depth, sig_end = 0, j
        for k in range(j, len(lines)):  # 괄호 균형으로 시그니처 끝('):') 찾기
            depth += lines[k].count("(") - lines[k].count(")")
            if depth <= 0 and lines[k].rstrip().endswith(":"):
                sig_end = k
                break
        signature = "\n".join(lines[j : sig_end + 1])

        body: list[str] = []
        for k in range(sig_end + 1, len(lines)):
            ln = lines[k]
            if ln.strip() == "":
                body.append(ln)
                continue
            if (len(ln) - len(ln.lstrip())) <= base:
                break
            body.append(ln)
        yield m.group(1), dm.group(1), signature, "\n".join(body)


def _node_symbol_index(root: Path) -> dict[str, str]:
    """Node 심볼 이름 → 정의 본문(가까운 중괄호 블록). controller 해석용."""
    index: dict[str, str] = {}
    for p in _iter_sources(root):
        if p.suffix not in (".ts", ".js"):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in _NODE_DECL.finditer(text):
            brace = text.find("{", m.end())
            if brace == -1 or brace - m.end() > 200:
                continue
            index.setdefault(m.group(1), _brace_body(text, brace))
    return index


def _node_handlers(text: str, index: dict[str, str]):
    for m in _NODE_CALL.finditer(text):
        args = _paren_args(text, m.end() - 1)
        pm = re.search(r"[\"']([^\"']+)[\"']", args)
        if not pm:
            continue
        path, rest = pm.group(1), args[pm.end() :]
        # 인라인 arrow/function 핸들러: 심볼 참조가 아니라 본문이 라우트에 직접 있음 → 본문을 바로 추출.
        im = _NODE_INLINE_FN.search(rest)
        if im:
            brace = rest.find("{", im.end() - 1)
            if brace != -1:
                yield path, "", im.group(0), _brace_body(rest, brace)
                continue
        # 이름붙은 심볼 핸들러: 심볼 인덱스에서 본문을 찾는다(다른 파일 컨트롤러 포함).
        handler, body = "", ""
        for nm in reversed(re.findall(r"\b(\w+)\b", rest)):
            if nm in index:
                handler, body = nm, index[nm]
                break
        yield path, handler, rest, body


# ── id 신호 / 사용 여부 ─────────────────────────────────────────────────────────────


def _id_name(path: str, signature: str) -> str | None:
    mp = _ID_NAME_IN_PATH.search(path)
    if mp:
        return mp.group(1)
    ms = re.search(r"\b(\w+_id|\w*[a-z]Id|id)\b", signature)
    return ms.group(1) if ms else None


def _id_used(id_name: str, body: str) -> bool:
    """id 파라미터가 본문에서 호출/쿼리에 실제로 쓰이면 True. 단순 echo(return dict)면 False."""
    pat = re.compile(rf"\b{re.escape(id_name)}\b")
    for ln in body.splitlines():
        if pat.search(ln) and _CALL_OR_QUERY.search(ln):
            return True
    return False


def _analyze(path, name, signature, body, *, stack, file_rel) -> IdorSuspect | None:
    if _NON_RESOURCE_PATH.search(path or ""):
        return None
    if _ADMIN.search(path or "") or _ADMIN.search(signature or ""):
        return None

    id_from_path = bool(_ID_IN_PATH.search(path or ""))
    id_addr = id_from_path or bool(_ID_IN_SIG.search(signature or ""))
    if not id_addr:
        return None

    # 현재 사용자를 참조하면 소유권 스코프 가능 → 의심 아님
    if references_current_user(f"{signature}\n{body}"):
        return None

    id_param = _id_name(path or "", signature or "") or ""

    # 정밀도: Java/Python은 id가 실제 조회/호출에 쓰이는지 확인(echo stub 제외).
    # Node는 route가 controller만 참조해 id가 리네임되므로(request.params.id→지역변수) 이 검사를 건너뛴다.
    if stack in ("java", "python") and id_param and not _id_used(id_param, body):
        return None

    return IdorSuspect(
        file=file_rel,
        endpoint=path or "(path 불명)",
        handler=name or "",
        id_param=id_param,
        id_signal="path" if id_from_path else "signature",
        score=1.0 if id_from_path else 0.6,
        reason="id로 자원에 접근·사용하지만 handler가 현재 인증 사용자를 참조하지 않음 → 소유권 검사 불가 의심",
    )


def find_idor_suspects(source_root: str | Path) -> list[IdorSuspect]:
    """source_root에서 IDOR 의심 endpoint를 score 내림차순으로 반환."""
    root = Path(source_root)
    suspects: list[IdorSuspect] = []
    node_index: dict[str, str] | None = None

    for p in _iter_sources(root):
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

        if p.suffix == ".java":
            handlers = ((pa, nm, sg, bd, "java") for pa, nm, sg, bd in _java_handlers(text))
        elif p.suffix == ".py":
            handlers = ((pa, nm, sg, bd, "python") for pa, nm, sg, bd in _python_handlers(text))
        else:
            if node_index is None:
                node_index = _node_symbol_index(root)
            handlers = ((pa, nm, sg, bd, "node") for pa, nm, sg, bd in _node_handlers(text, node_index))

        for path, name, sig, body, stack in handlers:
            s = _analyze(path, name, sig, body, stack=stack, file_rel=rel)
            if s:
                suspects.append(s)

    suspects.sort(key=lambda s: s.score, reverse=True)
    return suspects


def summarize(source_root: str | Path) -> dict:
    sus = find_idor_suspects(source_root)
    return {"root": str(source_root), "idor_suspects": len(sus), "top": sus[:10]}


if __name__ == "__main__":
    import sys

    root = sys.argv[1] if len(sys.argv) > 1 else "."
    found = find_idor_suspects(root)
    for s in found:
        print(f"  [{s.score:.1f}] {s.endpoint:40} {s.handler:28} {s.file}")
    print(f"\n총 {len(found)} IDOR 의심 @ {root}")
