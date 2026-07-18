"""Repair agent → vc_generate_patch (7.5절). Day3. **원본 미변경(generate만, apply 아님).**

locator가 짚은 `RootCause`를 받아 실제 수정 `diff`를 만들고, 여러 후보 중 하나를 랭킹으로
골라 `Patch(approval=PENDING)`로 반환한다. 실제 적용은 이 모듈이 하지 않는다 — `vc_apply_patch`
(사용자 승인 + run별 git worktree)가 별도로 한다. generate/apply 분리는 절대 원칙(10.1절).

랭킹 공식(7.5절):
    score = security_correctness + regression_safety + architectural_fit
            - patch_size 페널티 - unrelated_changes 페널티 - new_dependency_risk

diff 합성(synthesis)은 두 경로다:
  - `synthesize_fn`(LLM 훅): 모델이 컨트롤러/서비스/미들웨어 대안을 여러 개 만들 수 있다(P4 모델
    endpoint 확보 후). 없으면 사용 안 함.
  - 템플릿 합성(기본, 오프라인): Spring IDOR handler에 "요청자가 자원 소유자인가" 가드를 삽입하는
    결정적 diff를 만든다. GPU 없이 closed-loop을 돌리기 위한 것.

**패치가 완벽할 필요는 없다**: build/attack/positive/regression 게이트가 나쁜 패치를 걸러내고,
실패 시 planner가 RETRY(다음 attempt_no) → 3회 실패 시 HUMAN_REVIEW로 보낸다. patcher는 "가장
그럴듯한 후보"를 낼 뿐, 최종 판정은 judge가 한다.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from contracts.schemas import ApprovalStatus, Finding, Patch, RootCause
from repair.locator import _classify_layer

PRODUCER = "vc_generate_patch"

# 계층별 기본 점수 (security_correctness, regression_safety, architectural_fit). 7.5절 랭킹 입력.
#  - controller_hotfix : 한 handler에만 국소적 → 회귀 안전 높음, 구조 적합성은 중간(정책이 컨트롤러로 샘)
#  - service_policy    : 도메인 규칙을 도메인에 → 구조 적합성 높음, 그 서비스 호출자 전부 영향(회귀 위험↑)
#  - shared_middleware : 모든 route에 광범위 → 회귀 위험 가장 큼, 자원별 세부 정책은 놓칠 수 있음
_LAYER_PROFILE: dict[str, tuple[float, float, float]] = {
    "controller_hotfix": (0.80, 0.90, 0.60),
    "service_policy": (0.90, 0.70, 0.90),
    "shared_middleware": (0.70, 0.50, 0.70),
}

_W_SIZE = 0.02  # 변경 줄당 페널티
_W_UNRELATED = 0.15  # root_cause 파일 밖 변경 줄당 페널티(무관한 변경 억제)


class PatchCandidate(BaseModel):
    """패치 후보 하나 + 랭킹 입력값."""

    layer: str  # controller_hotfix | service_policy | shared_middleware
    diff: str
    files: list[str]
    rationale: str
    security_correctness: float
    regression_safety: float
    architectural_fit: float
    patch_size: int
    unrelated_changes: int
    new_dependency_risk: float

    @property
    def score(self) -> float:
        return (
            self.security_correctness
            + self.regression_safety
            + self.architectural_fit
            - _W_SIZE * self.patch_size
            - _W_UNRELATED * self.unrelated_changes
            - self.new_dependency_risk
        )


# ── diff 유틸 ────────────────────────────────────────────────────────────────────────


def _count_changed_lines(diff: str) -> int:
    """unified diff에서 실제 추가/삭제 줄 수(헤더 제외)."""
    n = 0
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            n += 1
    return n


def _unified(rel: str, original: str, modified: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


# ── Java 메서드 위치 찾기 (템플릿 합성용) ──────────────────────────────────────────────


def _find_method_span(text: str, method_name: str) -> tuple[int, int, int] | None:
    """`method_name(...) {`의 (파라미터 여는 '(' 위치, 닫는 ')' 위치, 여는 '{' 위치)를 찾는다.

    파라미터 안의 `)`(예: `@RequestParam(defaultValue="x")`)에 속지 않도록 괄호 depth로 매칭한다.
    """
    for m in re.finditer(rf"\b{re.escape(method_name)}\s*\(", text):
        paren_open = m.end() - 1
        depth = 0
        i = paren_open
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        paren_close = i
        brace_open = text.find("{", paren_close)
        if brace_open == -1:
            continue
        # ')'와 '{' 사이에 다른 '(' 없어야(선언부가 맞는지) — throws 절 등은 허용
        return paren_open, paren_close, brace_open
    return None


def _extract_owner_key(param_list: str) -> str | None:
    """핸들러 파라미터에서 자원 소유자 식별자(@PathVariable 우선, 없으면 첫 파라미터 이름)."""
    m = re.search(r"@PathVariable(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\]]+\s+(\w+)", param_list)
    if m:
        return m.group(1)
    m = re.search(r"@RequestParam(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w.<>\[\]]+\s+(\w+)", param_list)
    if m:
        return m.group(1)
    m = re.search(r"[\w.<>\[\]]+\s+(\w+)\s*(?:,|$)", param_list.strip())
    return m.group(1) if m else None


def _line_indent(text: str, index: int) -> str:
    """index가 속한 줄의 앞쪽 공백."""
    line_start = text.rfind("\n", 0, index) + 1
    stripped = text[line_start:index]
    return stripped[: len(stripped) - len(stripped.lstrip())]


def template_synthesize(
    finding: Finding, root_cause: RootCause, source_root: Path
) -> PatchCandidate | None:
    """Spring handler에 IDOR 소유권 가드를 삽입하는 결정적 diff를 만든다(오프라인 기본 합성기).

    표준 Spring만 사용(FQN으로 참조 → import 추가 불필요 → new_dependency_risk=0). 메서드/소유자
    식별자를 못 찾으면 `None`(추측으로 지어내지 않는다 — LLM 합성기가 맡을 몫).
    """
    if not root_cause.symbol:
        return None
    file_path = source_root / root_cause.file
    if file_path.suffix != ".java" or not file_path.is_file():
        return None

    text = file_path.read_text(encoding="utf-8", errors="replace")
    method_name = root_cause.symbol.split(".")[-1]
    span = _find_method_span(text, method_name)
    if span is None:
        return None
    paren_open, paren_close, brace_open = span

    param_list = text[paren_open + 1 : paren_close]
    owner_key = _extract_owner_key(param_list)
    if owner_key is None:
        return None

    # 1) 현재 사용자를 얻을 Principal 파라미터 추가(없을 때만).
    new_param_list = param_list
    if "Principal" not in param_list:
        sep = ", " if param_list.strip() else ""
        new_param_list = f"{param_list}{sep}java.security.Principal principal"

    # 2) 메서드 본문 첫 줄에 소유권 가드 삽입.
    indent = _line_indent(text, brace_open) + "    "
    guard = (
        f"\n{indent}// [VibeCutter] IDOR guard ({finding.cwe or 'CWE-639'}): 요청자가 자원 소유자인지 확인\n"
        f"{indent}if (principal == null || !String.valueOf({owner_key}).equals(principal.getName())) {{\n"
        f'{indent}    throw new org.springframework.web.server.ResponseStatusException(\n'
        f'{indent}        org.springframework.http.HttpStatus.FORBIDDEN, "not resource owner");\n'
        f"{indent}}}\n"
    )

    modified = (
        text[: paren_open + 1]
        + new_param_list
        + text[paren_close : brace_open + 1]
        + guard
        + text[brace_open + 1 :]
    )
    diff = _unified(root_cause.file, text, modified)

    layer = _classify_layer(root_cause.symbol, root_cause.file)
    sec, reg, arch = _LAYER_PROFILE.get(layer, _LAYER_PROFILE["controller_hotfix"])
    return PatchCandidate(
        layer=layer,
        diff=diff,
        files=[root_cause.file],
        rationale=(
            f"{root_cause.symbol}에 소유권 가드를 삽입 — 요청자({{principal}})가 자원 소유자"
            f"({owner_key})가 아니면 403. 표준 Spring만 사용해 새 의존성 없음."
        ),
        security_correctness=sec,
        regression_safety=reg,
        architectural_fit=arch,
        patch_size=_count_changed_lines(diff),
        unrelated_changes=0,  # 단일 파일·단일 메서드만 변경
        new_dependency_risk=0.0,  # FQN 사용, import/라이브러리 추가 없음
    )


# ── 랭킹 + 조립 ──────────────────────────────────────────────────────────────────────


def rank(candidates: list[PatchCandidate]) -> PatchCandidate:
    """7.5절 점수가 가장 높은 후보를 고른다(동점이면 먼저 온 것)."""
    return max(candidates, key=lambda c: c.score)


def generate_patch(
    run_id: str,
    finding: Finding,
    root_cause: RootCause,
    *,
    source_root: str | Path,
    synthesize_fn: Callable[[Finding, RootCause, Path], list[PatchCandidate]] | None = None,
    attempt_no: int = 1,
) -> Patch:
    """RootCause → 최적 패치 후보 → `Patch(approval=PENDING)`. `vc_generate_patch`가 호출.

    입력: `finding`(cwe 등), `root_cause`(locator 산출), 대상 `source_root`. 선택적으로 LLM
    합성기 `synthesize_fn`(대안 후보 리스트 추가). `attempt_no`는 RETRY 재시도 회차.
    출력: `Patch`(diff/files/rationale/approval=PENDING/attempt_no). **적용하지 않는다.**
    실패: 후보를 하나도 합성 못 하면 `ValueError`(빈 패치를 지어내지 않는다).
    """
    source_root = Path(source_root)

    candidates: list[PatchCandidate] = []
    if synthesize_fn is not None:  # LLM 경로: 여러 계층 대안
        candidates.extend(synthesize_fn(finding, root_cause, source_root) or [])
    template = template_synthesize(finding, root_cause, source_root)  # 결정적 후보
    if template is not None:
        candidates.append(template)

    if not candidates:
        raise ValueError(
            f"패치 후보를 합성하지 못했다(root_cause={root_cause.file}:{root_cause.symbol}). "
            f"템플릿이 처리 못 하는 스택이면 LLM 합성기(synthesize_fn)가 필요하다."
        )

    best = rank(candidates)
    others = [c for c in candidates if c is not best]
    ranking_note = (
        f" [랭킹 score={best.score:.2f} — {best.layer} 채택"
        + (
            "; 대안: " + ", ".join(f"{c.layer}({c.score:.2f})" for c in others)
            if others
            else "; 단일 후보"
        )
        + f"; 시도 #{attempt_no}]"
    )

    return Patch(
        id=f"patch-{uuid4().hex[:12]}",
        finding_id=finding.id,
        run_id=run_id,
        diff=best.diff,
        files=best.files,
        rationale=best.rationale + ranking_note,
        approval=ApprovalStatus.PENDING,
        attempt_no=attempt_no,
    )
