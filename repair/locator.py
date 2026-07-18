"""Root-cause locator → vc_localize_root_cause (7.4절). Day3.

"문이 뚫린 건 증명했다(verified Finding). 이제 코드의 '어디'가 뚫렸나?" — verified Finding을
`RootCause`(고칠 파일·심볼·이유)로 바꾼다. patcher(다음 단계)가 이 RootCause를 받아 패치를 만든다.

신호를 세 겹으로 쓴다(7.4절 "동적 실행 경로 symbol 우선 + SAST taint path 교차 검증"):
  1) 동적(가장 신뢰): 실제로 뚫린 endpoint를 처리하는 handler를 `surface.routes`로 소스에서 찾는다.
     — 공격이 실제로 이 경로로 도달했으므로 "reachable"이 증명된 위치다.
  2) SAST 교차검증: Finding.source_symbols(P4 Semgrep의 "파일:줄")와 파일이 일치하면 확신을 높인다.
  3) code_index 폴백: route 매핑이 실패하면(routes.py는 현재 Spring 전용) P4 `model.code_index`로
     endpoint 토큰을 검색해 후보 파일을 찾는다.

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


def _sast_files(finding: Finding) -> set[str]:
    """Finding.source_symbols("파일:줄")에서 파일 경로만 뽑는다(SAST 교차검증용)."""
    return {s.split(":")[0] for s in finding.source_symbols if ":" in s}


def _files_agree(route_file: str, sast_files: set[str]) -> bool:
    """route가 지목한 파일과 SAST가 지목한 파일이 같은 파일을 가리키는지(접미 일치 허용)."""
    return any(
        route_file == f or route_file.endswith(f) or f.endswith(route_file) for f in sast_files
    )


def _locate_by_code_index(source_root: Path, endpoint: str) -> RootCause | None:
    """route/SAST가 모두 실패했을 때 P4 code_index로 폴백 검색한다.

    model.code_index가 없거나(선택적 의존) 히트가 없으면 None. locator가 P4 인덱스를 소비하는
    지점(D1-P4.md: "root-cause locator는 model.code_index 소비")이다.
    """
    try:
        from model.code_index import CodeIndex
    except Exception:
        return None

    index = CodeIndex.build(source_root)
    query = " ".join(t for t in re.split(r"[/{}:]+", endpoint or "") if t)
    hits = index.search(query, k=1)
    if not hits:
        return None
    hit = hits[0]
    file = getattr(hit.chunk, "file", None) or getattr(hit.chunk, "path", None) or str(hit.chunk)
    return RootCause(
        file=file,
        symbol=None,
        rationale=(
            f"소스 route 매핑에서 endpoint {endpoint!r}를 못 찾아, code_index 검색 상위 결과를 "
            f"근본 원인 후보로 채택했다(신뢰 낮음, 수동 확인 권장)."
        ),
    )


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
        rationale = (
            f"검증된 endpoint {endpoint!r}를 처리하는 handler가 여기다({route.source}). "
            f"공격이 실제로 이 경로로 도달했다"
            f"{' — SAST 지목 위치와도 일치' if agree else ''}. "
            f"{finding.cwe or 'IDOR'}의 원인은 이 handler가 요청자 소유권/권한 검사를 하지 않는 것. "
            f"권장 수정 계층: {layer}."
        )
        return RootCause(file=file, symbol=symbol, rationale=rationale)

    # 2) SAST 폴백: route 매칭 실패 시 SAST가 지목한 파일을 채택.
    if sast:
        file = sorted(sast)[0]
        return RootCause(
            file=file,
            symbol=None,
            rationale=(
                f"소스 route 매핑에서 endpoint {endpoint!r}를 못 찾아(비-Spring이거나 파서 한계), "
                f"SAST가 지목한 위치를 근본 원인 후보로 채택했다. 수정 계층은 파일 확인 후 결정 권장."
            ),
        )

    # 3) code_index 폴백.
    fallback = _locate_by_code_index(source_root, endpoint or "")
    if fallback is not None:
        return fallback

    raise ValueError(
        f"endpoint {endpoint!r}에 대한 코드 위치를 찾지 못했다 "
        f"(route/SAST/code_index 모두 실패) — 근본 원인을 추측으로 지어내지 않는다."
    )
