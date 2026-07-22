"""Root-cause locator → vc_localize_root_cause (7.4절). Day3.

"문이 뚫린 건 증명했다(verified Finding). 이제 코드의 '어디'가 뚫렸나?" — verified Finding을
`RootCause`(고칠 파일·심볼·이유)로 바꾼다. patcher(다음 단계)가 이 RootCause를 받아 패치를 만든다.

신호를 세 겹으로 쓴다(7.4절 "동적 실행 경로 symbol 우선 + SAST taint path 교차 검증"):
  1) 동적(가장 신뢰): 실제로 뚫린 endpoint를 처리하는 handler를 `surface.routes`로 소스에서 찾는다.
     — 공격이 실제로 이 경로로 도달했으므로 "reachable"이 증명된 위치다.
  2) SAST 교차검증: Finding.source_symbols(P4 Semgrep의 "파일:줄")와 파일이 일치하면 확신을 높인다.
  3) code_index 폴백: route 매핑이 실패하면(routes.py가 못 뽑는 스택/동적 라우팅) P4 `model.code_index`로
     endpoint 토큰을 검색해 후보 파일을 찾는다. **프론트엔드 파일은 제외**하고 백엔드 후보만 채택한다
     (D4 P1 요청: 비-Spring 타깃에서 프론트엔드 파일 오탐 방지).

수정 위치 계층(controller hotfix / service policy / shared middleware)은 심볼/경로로 분류해
rationale에 담는다 — RootCause 스키마에 layer 필드가 없어서다(D1-P3.md 이견 4, 확장은 P1과 협의).

이 모듈은 상태를 바꾸지 않는다. finding을 읽어 RootCause를 만들 뿐, apply/전이는 하지 않는다.
"""

from __future__ import annotations

import re
from pathlib import Path

from contracts.schemas import Finding, RootCause
from surface.routes import Route, extract_routes

# 수정 위치 계층 분류 힌트. 위에서부터 먼저 매치되는 것을 채택한다(middleware가 가장 구체적).
_LAYER_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("shared_middleware", ("filter", "interceptor", "middleware", "guard", "aspect", "security")),
    ("service_policy", ("service", "usecase", "manager", "policy", "domain", "repository")),
    ("controller_hotfix", ("controller", "resource", "handler", "endpoint", "route", "api")),
)


def _normalize_path(path: str | None) -> str:
    """경로 파라미터를 통일해 비교 가능하게 만든다.

    `/IDOR/profile/{userId}`, `/IDOR/profile/{id}`, `/IDOR/profile/:id`를 전부
    `/IDOR/profile/{}`로 맞춘다 — endpoint 표기가 앱/도구마다 달라도 같은 route로 매칭되도록.
    """
    p = re.sub(r"\{[^}]*\}", "{}", path or "")  # {userId} → {}
    p = re.sub(r":[^/]+", "{}", p)  # :id → {}
    return "/" + p.strip("/")


def _split_method_path(endpoint: str | None) -> tuple[str | None, str]:
    """"GET /a/{id}" 또는 "/a/{id}" 둘 다 받아 (method, path)로 나눈다."""
    parts = (endpoint or "").split()
    if len(parts) == 2 and parts[0].isalpha():
        return parts[0].upper(), parts[1]
    return None, endpoint or ""


def _match_route(routes: list[Route], method: str | None, path: str) -> Route | None:
    """endpoint(method+path)를 소스 route 목록에서 찾는다. 정확 매치 우선."""
    target = _normalize_path(path)
    for r in routes:
        if _normalize_path(r.path) != target:
            continue
        if method and r.http_method not in (method, "ANY"):
            continue
        return r
    return None


def _classify_layer(symbol: str, file: str) -> str:
    """심볼/파일 이름으로 수정 위치 계층을 추정한다."""
    hay = f"{symbol} {file}".lower()
    for layer, keywords in _LAYER_HINTS:
        if any(k in hay for k in keywords):
            return layer
    return "controller_hotfix"  # 못 고르면 요청이 처음 닿는 곳(controller)을 기본으로


def _cwe_num(cwe: str | None) -> str:
    """"CWE-639" → "639". 숫자가 없으면 ""."""
    m = re.search(r"\d+", cwe or "")
    return m.group() if m else ""


# sink형 취약점: 고칠 곳이 요청 진입 handler가 아니라 sink(XSS=출력 렌더, SQLi=쿼리 조립)다.
# route-first locator는 handler를 앵커로 주므로, 이 클래스에선 SAST가 짚은 sink 위치를 rationale에
# 실어 LLM이 진짜 취약 지점을 향하게 한다(D6 LLM-patch 확장). 확장 시 78/90/91/94 등 추가.
_SINK_TYPE_CWES = frozenset({"79", "89"})


def _root_cause_reason(cwe: str | None) -> str:
    """CWE(취약점 클래스)별 근본 원인 서술.

    LLM 합성기(`repair/llm_synth`)가 이 rationale을 "근거"로 모델에 그대로 전달하므로,
    클래스별로 정확한 진단을 줘야 옳은 패치가 나온다(진단이 다르면 패치도 다르다):
    IDOR=소유권 가드 / XSS=출력 인코딩 / SQLi=쿼리 파라미터화. IDOR 전용 문구를 3군 전체에
    쓰면 XSS/SQLi에서 모델이 소유권 가드를 만들어 attack 게이트가 계속 reject한다.
    """
    code = _cwe_num(cwe)
    if code == "79":  # XSS
        return "사용자 입력이 출력 시 이스케이프/인코딩 없이 렌더돼 스크립트로 실행되는 것"
    if code == "89":  # SQL Injection
        return "사용자 입력이 파라미터 바인딩 없이 쿼리 문자열에 직접 이어붙는 것"
    # CWE-639 등 IDOR/접근제어(및 미상): 요청자 소유권/권한 검사 누락(기본).
    return "이 handler가 요청자 소유권/권한 검사를 하지 않는 것"


def _xss_fix_hint(cwe: str | None, file: str) -> str:
    """CWE-79 XSS의 **프레임워크별 올바른 수정 방향**(출력 인코딩/정화). rationale에 실어 235B가
    접근제어 가드 같은 엉뚱한 패치가 아니라 컨텍스트에 맞는 이스케이프/정화를 하게 한다. 비-XSS면 "".
    파일 확장자로 프레임워크를 추정한다(프로젝트 내 프레임워크는 대체로 일관)."""
    if _cwe_num(cwe) != "79":
        return ""
    low = (file or "").lower()
    if low.endswith((".tsx", ".jsx")):
        return (" 수정 방향(React): dangerouslySetInnerHTML를 없애고 값을 JSX로 그대로 렌더(자동 "
                "이스케이프)하거나, HTML이 꼭 필요하면 DOMPurify.sanitize()로 정화하라.")
    if low.endswith(".vue"):
        return " 수정 방향(Vue): v-html 대신 텍스트 보간({{ }})을 쓰거나 필요 시 DOMPurify로 정화하라."
    if low.endswith(".py"):
        return (" 수정 방향(Python/템플릿): mark_safe·render_template_string으로 원시 HTML을 반환하지 말고, "
                "템플릿 autoescape를 켜거나 markupsafe.escape()로 값을 이스케이프하라.")
    if low.endswith((".ts", ".js")):
        return (" 수정 방향(JS/Express): element.innerHTML 대신 textContent를 쓰거나(HTML 불필요), res.send로 "
                "반사하는 값은 escape-html/sanitize-html로 인코딩하라.")
    if low.endswith((".html", ".ejs", ".hbs")):
        return (" 수정 방향(템플릿): |safe·th:utext·<%- %>·{{{ }}} 같은 비이스케이프 출력을 기본 이스케이프 "
                "출력으로 바꿔라.")
    return " 수정 방향: 출력 컨텍스트에 맞는 이스케이프/인코딩을 적용하고, HTML이 불필요하면 텍스트로 렌더하라."


def _sqli_fix_hint(cwe: str | None, file: str) -> str:
    """CWE-89 SQLi의 **프레임워크별 파라미터화 수정 방향**. rationale에 실어 235B가 문자열 결합을
    그대로 두거나 접근제어 가드를 만드는 대신 정확한 파라미터 바인딩을 하게 한다(X6의 injection 짝).
    비-SQLi면 "". 파일 확장자로 프레임워크 추정."""
    if _cwe_num(cwe) != "89":
        return ""
    low = (file or "").lower()
    if low.endswith((".ts", ".js")):
        return (" 수정 방향(Node): 문자열 결합·템플릿 리터럴 대신 파라미터 바인딩을 써라 — "
                "Sequelize `sequelize.query(sql, { replacements: { k: v } })`(또는 `:k` bind), knex는 `?` "
                "바인딩, node-postgres는 `$1` placeholder + values 배열.")
    if low.endswith(".py"):
        return (" 수정 방향(Python): `cursor.execute(sql, params)`처럼 파라미터화(`%s`/`?` placeholder + "
                "튜플)하거나, SQLAlchemy는 `text(sql).bindparams(...)` 또는 ORM `filter(Model.col == v)`를 써라. "
                "f-string/`+`/`.format`으로 값을 잇지 마라.")
    if low.endswith(".java"):
        return (" 수정 방향(Java): 문자열 결합 대신 `PreparedStatement` + `setString`/`setInt` 바인딩, JPA는 "
                "named/positional 파라미터(`:name`)를 써라.")
    return (" 수정 방향: 사용자 입력을 쿼리 문자열에 잇지 말고 prepared statement/파라미터 바인딩으로 "
            "값을 전달하라(식별자가 꼭 동적이면 화이트리스트 검증).")


def _sast_files(finding: Finding) -> set[str]:
    """Finding.source_symbols("파일:줄")에서 파일 경로만 뽑는다(SAST 교차검증용)."""
    return {s.split(":")[0] for s in finding.source_symbols if ":" in s}


def _files_agree(route_file: str, sast_files: set[str]) -> bool:
    """route가 지목한 파일과 SAST가 지목한 파일이 같은 파일을 가리키는지(접미 일치 허용)."""
    return any(
        route_file == f or route_file.endswith(f) or f.endswith(route_file) for f in sast_files
    )


def _sast_sink_locations(finding: Finding, *, limit: int = 3) -> list[str]:
    """Finding.source_symbols에서 SAST가 짚은 'file:line' 위치를 순서·중복제거로 뽑는다(sink 후보)."""
    seen: list[str] = []
    for s in finding.source_symbols:
        if ":" in s and s not in seen:
            seen.append(s)
    return seen[:limit]


# 프론트엔드/빌드 산출물 시그니처 — code_index 폴백이 이런 파일을 근본 원인으로 짚지 않게 한다.
_FRONTEND_SUFFIXES = (".jsx", ".tsx", ".vue", ".svelte", ".css", ".scss", ".sass", ".less", ".html")
_FRONTEND_DIR_PARTS = ("frontend", "client", "static", "public", "assets", "node_modules", "dist", "build", ".next")


def _is_frontend_file(file: str) -> bool:
    """파일 경로가 프론트엔드/빌드 산출물로 보이는지(백엔드 패치 대상이 아님)."""
    low = file.replace("\\", "/").lower()
    if low.endswith(_FRONTEND_SUFFIXES):
        return True
    return any(f"/{part}/" in f"/{low}" for part in _FRONTEND_DIR_PARTS)


# 비실행 '참고/decoy' 소스: 같은 취약 패턴이 코드-고치기 챌린지·문서·정적 참고용으로 복제된 사본
# (예: Juice Shop `data/static/codefixes/*.ts` — 서버가 실행하지 않고 `fs.readFileSync`로 텍스트로만
# 읽어 UI에 보여줌). 실행 핸들러 디렉터리(`routes/`·`controllers/`…)는 실제 라이브 sink이므로 앞으로 당긴다.
# J-3 라이브 발견(P1): locator가 실행 안 되는 codefixes decoy를 root cause로 짚어 attack replay가 실패.
_REFERENCE_DIR_PARTS = ("codefixes", "static", "snippets", "examples", "samples", "vendor",
                        "node_modules", "dist", "build")
_HANDLER_DIR_PARTS = ("routes", "route", "controllers", "controller", "handlers", "handler",
                      "api", "endpoints", "resources")


def _sink_file_priority(file: str) -> int:
    """sink 파일 우선순위(작을수록 우선): 실행 핸들러(0) < 일반(1) < 비실행 참고/decoy 사본(2).

    같은 취약 패턴이 실행 핸들러와 참고 사본에 중복될 때 실제로 도는 코드를 짚게 한다.
    """
    seg = "/" + file.replace("\\", "/").lower().strip("/") + "/"
    if any(f"/{p}/" in seg for p in _REFERENCE_DIR_PARTS):
        return 2  # 비실행 참고/decoy — 가장 뒤로
    if any(f"/{p}/" in seg for p in _HANDLER_DIR_PARTS):
        return 0  # 실제 실행 핸들러 — 우선
    return 1


def _rank_sinks(sinks: list[str]) -> list[str]:
    """sink 'file:line' 목록을 실행 우선순위로 안정 정렬한다(동순위는 SAST 보고 순 유지 — I5)."""
    return sorted(sinks, key=lambda s: _sink_file_priority(s.split(":")[0]))


def _locate_by_code_index(source_root: Path, endpoint: str, cwe: str | None = None) -> RootCause | None:
    """route/SAST가 모두 실패했을 때 P4 code_index로 폴백 검색한다.

    model.code_index가 없거나(선택적 의존) 백엔드 히트가 없으면 None. **프론트엔드 파일은 건너뛰고**
    백엔드 후보만 채택한다 — 비-Spring 타깃에서 route 매핑이 실패해도 프론트엔드 파일을 근본 원인으로
    지목하지 않는다(D4 P1 요청). locator가 P4 인덱스를 소비하는 지점(D1-P4.md).
    """
    try:
        from model.code_index import CodeIndex
    except Exception:
        return None

    index = CodeIndex.build(source_root)
    query = " ".join(t for t in re.split(r"[/{}:]+", endpoint or "") if t)
    for hit in index.search(query, k=5):
        file = getattr(hit.chunk, "file", None) or getattr(hit.chunk, "path", None) or str(hit.chunk)
        if _is_frontend_file(file):
            continue
        return RootCause(
            file=file,
            symbol=None,
            rationale=(
                f"소스 route 매핑에서 endpoint {endpoint!r}를 못 찾아, code_index 검색 상위(프론트엔드 제외) "
                f"백엔드 후보를 근본 원인으로 채택했다(신뢰 낮음, 수동 확인 권장). "
                f"의심 원인: {_root_cause_reason(cwe)}."
            ),
        )
    return None  # 백엔드 후보가 없으면(전부 프론트엔드/무결과) 추측하지 않는다


def localize(finding: Finding, *, source_root: str | Path) -> RootCause:
    """verified Finding → RootCause. `vc_localize_root_cause`(P1 tool)가 호출.

    입력: verified `Finding`(affected_endpoint/source_symbols/cwe 사용), 대상 소스 루트.
    출력: `RootCause(file, symbol, rationale)`.
    실패: 세 신호 모두 위치를 못 찾으면 `ValueError`(추측으로 지어내지 않는다).
    """
    source_root = Path(source_root)
    endpoint = finding.affected_endpoint
    method, path = _split_method_path(endpoint)
    sast = _sast_files(finding)

    # 1) 동적 신호: 뚫린 endpoint의 handler를 소스 route에서 찾는다.
    routes = extract_routes(source_root)
    route = _match_route(routes, method, path)
    if route is not None:
        file = route.source.split(":")[0]
        symbol = route.handler
        layer = _classify_layer(symbol, file)
        agree = _files_agree(file, sast)
        # sink형(XSS/SQLi)은 고칠 곳이 진입 handler가 아니라 sink다. SAST가 sink 위치를 짚었으면
        # rationale에 실어 LLM/사람이 그쪽을 향하게 한다(앵커 file/symbol은 도달 증명된 handler로 유지).
        sink_note = ""
        hint_file = file  # XSS 수정 힌트는 sink 파일 기준(프레임워크 추정). sink 미상이면 handler 파일.
        if _cwe_num(finding.cwe) in _SINK_TYPE_CWES:
            sinks = _rank_sinks(_sast_sink_locations(finding))  # 실행 핸들러 우선, decoy/참고 사본 후순위
            if sinks:
                hint_file = sinks[0].split(":")[0]
                sink_note = (
                    f" 단, 실제 취약 지점(sink)은 SAST 기준 {', '.join(sinks)}일 수 있다 — "
                    f"이 handler와 다른 파일/메서드면 거기를 우선 수정하라."
                )
        rationale = (
            f"검증된 endpoint {endpoint!r}를 처리하는 handler가 여기다({route.source}). "
            f"공격이 실제로 이 경로로 도달했다"
            f"{' — SAST 지목 위치와도 일치' if agree else ''}. "
            f"{finding.cwe or 'IDOR'}의 원인은 {_root_cause_reason(finding.cwe)}.{sink_note} "
            f"권장 수정 계층: {layer}.{_xss_fix_hint(finding.cwe, hint_file)}{_sqli_fix_hint(finding.cwe, hint_file)}"
        )
        return RootCause(file=file, symbol=symbol, rationale=rationale)

    # 2) SAST 폴백: route 매칭 실패 시 SAST가 지목한 파일을 채택.
    if sast:
        file = sorted(sast)[0]  # 기본: 결정적(알파벳) — IDOR 등은 handler 파일 아무거나로 충분
        sink_note = ""
        if _cwe_num(finding.cwe) in _SINK_TYPE_CWES:
            # sink형(XSS/SQLi)은 알파벳 첫 파일이 진짜 sink가 아닐 수 있다. sink 후보를 **실행 우선순위**로
            # 정렬해 채택한다: 실행 핸들러(routes/…) > 일반 > 비실행 참고/decoy 사본(codefixes/·static/…).
            # ① cross-file(쿼리 조립≠실행, I5)과 ② 같은 취약 SQL이 코드-고치기 챌린지용으로 여러 파일에
            # 복제된 decoy(Juice Shop, J-3 라이브 발견) 둘 다 잡는다. 동순위는 SAST 보고 순 유지.
            sinks = _rank_sinks(_sast_sink_locations(finding))
            if sinks:
                file = sinks[0].split(":")[0]
                if len(sinks) > 1:
                    sink_note = (
                        f" SAST가 짚은 sink 후보(실행부 우선): {', '.join(sinks)} — 쿼리 조립·실행이 "
                        f"다른 파일이거나 비실행 참고 사본(codefixes/·static/)이 섞였으면 실제 라이브 핸들러를 고쳐라."
                    )
        return RootCause(
            file=file,
            symbol=None,
            rationale=(
                f"소스 route 매핑에서 endpoint {endpoint!r}를 못 찾아(비-Spring이거나 파서 한계), "
                f"SAST가 지목한 위치를 근본 원인 후보로 채택했다. "
                f"{finding.cwe or '취약점'}의 원인은 {_root_cause_reason(finding.cwe)}. "
                f"수정 계층은 파일 확인 후 결정 권장.{sink_note}"
                f"{_xss_fix_hint(finding.cwe, file)}{_sqli_fix_hint(finding.cwe, file)}"
            ),
        )

    # 3) code_index 폴백.
    fallback = _locate_by_code_index(source_root, endpoint or "", finding.cwe)
    if fallback is not None:
        return fallback

    raise ValueError(
        f"endpoint {endpoint!r}에 대한 코드 위치를 찾지 못했다 "
        f"(route/SAST/code_index 모두 실패) — 근본 원인을 추측으로 지어내지 않는다."
    )
