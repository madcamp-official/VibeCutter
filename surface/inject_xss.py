"""XSS·Injection attack-surface 프리필터 — IDOR `find_idor_suspects`(graph.py)의 짝 (7.1절).

IDOR 프리필터가 "id-addressable + 현재사용자 미참조" handler를 찾듯, 여기선 소스에서
  - **Injection**: 원시 SQL 문장이 **동적으로 결합**되고(`f-string {}`/템플릿 `${}`/`+` concat/`.format`/`%`)
    **실행 지점(execute/query/createQuery/raw/cursor)**에 걸리는 라인을 찾는다. 파라미터화(ORM
    `.filter(x==v)`, prepared `?`/`$1`/`:param`, `execute(sql, params)`)는 문자열에 SQL이 있어도
    동적 결합이 아니라 걸리지 않는다 → 안전 코드는 flag 안 함(precision).
  - **XSS**: 위험 sink(`dangerouslySetInnerHTML`/`v-html`/`.innerHTML=`/`document.write`/jQuery `.html()`/
    서버 `HTMLResponse` f-string)에 **동적 값**이 들어갈 때를 찾는다. 상수 리터럴·인코딩/살균 통과 값은 제외.

배치/P4가 "어느 앱·어느 지점을 XSS/Injection으로 verify할지"를 감이 아니라 데이터로 고르게 하는 candidate
발견 자동화 — 그동안 손으로 하던 endpoint 선정(D4-P3-verifier-validation.md)을 대체한다.

프리필터라 precision을 우선(오탐이 verified 남발로 이어지지 않게) — 최종 verified는 verifier가 판정한다.
알려진 한계: 정밀 taint 분석이 아니라 패턴 매칭이다. inject_param은 결합 변수명(HTTP 파라미터명과 다를
수 있음). SQL을 한 줄에서 만들고 **다른 줄에서 실행**하면 놓칠 수 있다(실행 인접 요구 — recall 대신
precision 택함). 서버 템플릿 엔진(Jinja `|safe`, Thymeleaf `th:utext`)은 후속.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel

from surface.graph import _SKIP_DIRS, _iter_sources

# ── Injection 신호 ────────────────────────────────────────────────────────────────────
# 강한 SQL 문장 형태만(영어 'from'/'where' 단독은 오탐이라 제외). select...from / insert into / …
_SQL_STMT = re.compile(
    r"\bselect\b[\s\S]{0,240}?\bfrom\b|\binsert\s+into\b|\bupdate\b[\s\S]{0,120}?\bset\b|\bdelete\s+from\b",
    re.I,
)
# 동적 결합(파라미터화 아님). 따옴표는 종류별로 다뤄 SQL 안의 반대 따옴표('...')에서 안 끊기게.
_DYN = re.compile(
    r'f"[^"]*\{[^}]+\}'                 # f"...{x}..."  (SQL 안의 ' 허용)
    r"|f'[^']*\{[^}]+\}"               # f'...{x}...'
    r'|`[^`]*\$\{[^}]+\}'              # `...${x}...`
    r'|"[^"]*"\s*\+\s*[A-Za-z_]'       # "..." + x
    r"|'[^']*'\s*\+\s*[A-Za-z_]"       # '...' + x
    r'|[A-Za-z_]\w*\s*\+\s*["\']'      # x + "..."
    r'|\.format\s*\('                  # "...".format(
    r'|"[^"]*"\s*%\s*[\(A-Za-z_]'      # "..." % x
    r"|'[^']*'\s*%\s*[\(A-Za-z_]",     # '...' % x
    re.I,
)
# 실행 지점(원시 SQL이 실제 DB로 감). ORM `.query(Model)`은 SQL 문자열이 없어 _SQL_STMT에서 이미 걸러짐.
_EXEC = re.compile(r"execute|executeQuery|createQuery|createNativeQuery|\.raw\s*\(|\.query\s*\(|cursor|prepareStatement|db\.exec", re.I)
# 로깅/출력 라인은 쿼리가 아니다 → 제외.
_LOG_LINE = re.compile(r"console\.(?:log|info|warn|error|debug)|logger?\.|logging\.|System\.out|\bprintln?\s*\(", re.I)
# 변수 대입 LHS(줄 넘는 sink용): `sql = ` / `String q += ` / `const s = `. `==`는 제외.
_SQL_ASSIGN = re.compile(r"^\s*(?:[\w.<>\[\]]+\s+)*?(\w+)\s*\+?=(?!=)")
_EXEC_WINDOW = 6  # 동적 SQL 문자열 대입 후 이 줄 수 안에서 실행되면 같은 sink으로 본다

# ── XSS 신호: 위험 sink + 동적 값 ─────────────────────────────────────────────────────
# 클라이언트 DOM sink + 서버 템플릿(escape를 명시적으로 끄는 지점). jQuery `.append/.prepend`류는
# 파이썬 list.append 등과 구분이 안 돼 오탐이 커서 제외한다(`.html(`만 유지).
_XSS_SINKS: list[tuple[str, re.Pattern]] = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{[^}]*__html\s*:\s*([^}]+)\}")),
    ("v-html", re.compile(r'v-html\s*=\s*["\']([^"\']+)["\']')),
    ("innerHTML", re.compile(r"\.innerHTML\s*=(?!=)\s*(.+)")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=(?!=)\s*(.+)")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(\s*[^,]+,\s*([^)]+)")),  # 2번째 인자=HTML
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(\s*([^)]+)")),
    ("jquery.html", re.compile(r"\.html\s*\(\s*([^)]+)\)")),
    ("HTMLResponse", re.compile(r'HTMLResponse\s*\(\s*(f["\'][^"\']*\{[^}]+\}[^"\']*["\']|[^)]*\+[^)]*)')),
    # ── 서버 템플릿: 출력 인코딩을 명시적으로 끄는 지점(입력이 동적이면 XSS) ──
    ("django.mark_safe", re.compile(r"\bmark_safe\s*\(\s*([^)]+)")),
    ("flask.render_template_string", re.compile(r"\brender_template_string\s*\(\s*([^),]+)")),
    ("markupsafe.Markup", re.compile(r"\bMarkup\s*\(\s*([^)]+)")),
    ("jinja.safe", re.compile(r"\{\{\s*([^}|]+?)\s*\|\s*safe\b")),          # {{ x|safe }}
    ("thymeleaf.utext", re.compile(r'th:utext\s*=\s*["\']([^"\']+)["\']')),  # th:utext="${x}"
]
# 프레임워크가 escape를 명시적으로 끄는 sink → 높음(0.9~1.0). 나머지 DOM sink는 0.7.
_STRONG_SINKS = frozenset({
    "dangerouslySetInnerHTML", "v-html", "HTMLResponse",
    "django.mark_safe", "flask.render_template_string", "markupsafe.Markup",
    "jinja.safe", "thymeleaf.utext",
})
_LITERAL = re.compile(r"""^\s*(["'])(?:\\.|(?!\1).)*\1\s*$""")  # 순수 문자열 리터럴(무해)
# 인코딩/살균을 거친 값은 안전 → 제외.
_SANITIZED = re.compile(r"encode|escape|sanitiz|dompurify|purif|striptags|\.textContent|xss[_-]?clean", re.I)

_FRONT_SUFFIX = (".tsx", ".jsx", ".vue", ".ts", ".js", ".html", ".py")
# 앱 로직이 아닌 벤더/디자인툴/생성물 — XSS 스캔 제외.
_FRONT_SKIP = ("/_ds/", "-design-system", "/storybook", "/.storybook", "/vendor/", "/public/vendor", "/coverage/")


class InjectionSuspect(BaseModel):
    """원시 SQL 동적 결합 의심 지점 (프리필터 산출)."""

    file: str
    line: int
    stack: str
    inject_param: str = ""
    snippet: str
    score: float
    reason: str


class XssSuspect(BaseModel):
    """위험 HTML sink에 동적 값이 들어가는 의심 지점 (프리필터 산출)."""

    file: str
    line: int
    sink: str
    snippet: str
    score: float
    reason: str


def _interp_var(snippet: str) -> str:
    """동적 결합에 쓰인 변수명(best-effort). ${x}/{x}/`+ x` 중 첫 식별자."""
    m = re.search(r"\$\{\s*([A-Za-z_]\w*)|\{\s*([A-Za-z_]\w*)|\+\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*\+", snippet)
    return next((g for g in m.groups() if g), "") if m else ""


def _assigned_var(line: str) -> str:
    """`sql = ...` / `String q += ...` / `const s = ...`의 LHS 변수명. 없으면 ""."""
    m = _SQL_ASSIGN.match(line)
    return m.group(1) if m else ""


def _is_dynamic(value: str) -> bool:
    """XSS sink 값이 동적(변수/식)이고 살균을 안 거쳤는가. 리터럴·인코딩된 값이면 무해."""
    v = value.strip().rstrip(",);")
    if not v or _LITERAL.match(v) or _SANITIZED.search(v):
        return False
    return bool(re.search(r"[A-Za-z_]\w*", v))


def _iter_frontend(root: Path):
    for p in root.rglob("*"):
        if p.suffix not in _FRONT_SUFFIX:
            continue
        s = str(p)
        if any(d in s for d in _SKIP_DIRS) or any(d in s for d in _FRONT_SKIP):
            continue
        if s.endswith((".d.ts", ".test.ts", ".spec.ts", ".test.js", ".min.js")):
            continue
        yield p


def _stack_of(suffix: str) -> str:
    return {".java": "java", ".py": "python"}.get(suffix, "node")


def find_injection_suspects(source_root: str | Path) -> list[InjectionSuspect]:
    """source_root에서 원시 SQL 동적 결합+실행 의심 라인을 반환.

    두 형태를 잡는다:
      (A) **한 줄**에 SQL 문장 + 동적 결합 + 실행 (`cursor.execute(f"SELECT ... {x}")`).
      (B) **줄 넘는** sink — 동적 SQL 문자열을 변수에 대입한 뒤 몇 줄 안에서 그 변수를 실행
          (`sql = f"SELECT ... {x}"` … `cursor.execute(sql)`). 실행 전 안전한 값으로 재대입되면 해제.
    로그 라인은 제외. 줄 넘는 건은 대입 라인(문자열이 만들어지는 곳=고칠 지점)을 sink으로 보고한다.
    """
    root = Path(source_root)
    out: list[InjectionSuspect] = []
    seen: set[tuple[str, int]] = set()

    def _emit(line_no: int, rel: str, stack: str, snippet: str, score: float, reason: str) -> None:
        key = (rel, line_no)
        if key in seen:
            return
        seen.add(key)
        out.append(InjectionSuspect(
            file=rel, line=line_no, stack=stack, inject_param=_interp_var(snippet),
            snippet=snippet.strip()[:160], score=score, reason=reason,
        ))

    for p in _iter_sources(root):  # .java/.py/.ts/.js, tests/dist/node_modules 제외
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        stack = _stack_of(p.suffix)
        pending: dict[str, tuple[int, str]] = {}  # 동적 SQL 대입 변수 → (줄번호, 라인)
        for i, line in enumerate(text.splitlines(), 1):
            if _LOG_LINE.search(line):
                continue
            has_sql = bool(_SQL_STMT.search(line))
            has_dyn = bool(_DYN.search(line))
            has_exec = bool(_EXEC.search(line))
            # (A) 한 줄에 전부 — 확정.
            if has_sql and has_dyn and has_exec:
                _emit(i, rel, stack, line, 1.0,
                      "원시 SQL 문장이 변수와 동적 결합돼 실행됨(파라미터화 아님) → SQL Injection 의심")
                continue
            # (B-1) 동적 SQL 문자열이 변수에 대입 — 실행을 기다린다.
            if has_sql and has_dyn:
                var = _assigned_var(line)
                if var:
                    pending[var] = (i, line)
            # (B-2) 같은 변수를 안전한 값(동적 아님)으로 재대입 → 오염 해제(precision).
            avar = _assigned_var(line)
            if avar and avar in pending and not (has_sql and has_dyn):
                del pending[avar]
            # (B-3) 실행 라인이 대기 중 동적 SQL 변수를 참조 → 대입 라인을 sink으로 flag.
            if has_exec:
                for var, (aline, atext) in list(pending.items()):
                    if 0 <= i - aline <= _EXEC_WINDOW and re.search(rf"\b{re.escape(var)}\b", line):
                        _emit(aline, rel, stack, atext, 0.9,
                              f"동적 결합된 SQL 문자열이 {i - aline}줄 뒤 실행됨(줄 넘는 sink, "
                              "파라미터화 아님) → SQL Injection 의심")
                        del pending[var]
    return out


def find_xss_suspects(source_root: str | Path) -> list[XssSuspect]:
    """source_root에서 동적 값이 들어가는 위험 HTML sink를 score 내림차순으로 반환."""
    root = Path(source_root)
    out: list[XssSuspect] = []
    seen: set[tuple[str, int, str]] = set()
    for p in _iter_frontend(root):
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        for i, line in enumerate(text.splitlines(), 1):
            for sink_name, rx in _XSS_SINKS:
                m = rx.search(line)
                if not m or not _is_dynamic(m.group(1)):
                    continue
                key = (rel, i, sink_name)
                if key in seen:
                    continue
                seen.add(key)
                # 프레임워크가 명시적으로 살균을 끄는 지점(서버 템플릿 포함) → 높음
                strong = sink_name in _STRONG_SINKS
                out.append(XssSuspect(
                    file=rel, line=i, sink=sink_name, snippet=line.strip()[:160],
                    score=1.0 if strong else 0.7,
                    reason=f"위험 sink {sink_name}에 동적 값이 들어감(출력 인코딩 우회 가능) → XSS 의심",
                ))
    out.sort(key=lambda s: s.score, reverse=True)
    return out


def summarize(source_root: str | Path) -> dict:
    inj = find_injection_suspects(source_root)
    xss = find_xss_suspects(source_root)
    return {"root": str(source_root), "injection_suspects": len(inj), "xss_suspects": len(xss),
            "top_injection": inj[:10], "top_xss": xss[:10]}


if __name__ == "__main__":
    import sys

    root = sys.argv[1] if len(sys.argv) > 1 else "."
    inj = find_injection_suspects(root)
    xss = find_xss_suspects(root)
    print(f"=== Injection 의심 {len(inj)} @ {root} ===")
    for s in inj:
        print(f"  [{s.score:.1f}] {s.file}:{s.line}  ({s.inject_param})  {s.snippet[:80]}")
    print(f"=== XSS 의심 {len(xss)} @ {root} ===")
    for s in xss:
        print(f"  [{s.score:.1f}] {s.sink:24} {s.file}:{s.line}  {s.snippet[:70]}")
