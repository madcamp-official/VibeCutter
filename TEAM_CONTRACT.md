# TEAM_CONTRACT — 2일 최종 스프린트 공통 계약

**이 문서가 P1~P4 계획의 상위 문서다.** 개인 계획(`P*_new_plan.md`)과 충돌하면 이 문서가 이긴다.

---

## 0. 최종 목표 (2026-07-23 발표)

> **사용자가 자기 컴퓨터의 localhost 서비스를 MCP로 등록하고, 보안 검사하고, 패치받는다.**

데모 시나리오 2개(확정):
1. **사용자 프로젝트 등록 → 검사** — 제품 비전 증명
2. **Juice Shop SQLi → LLM 패치** — template 밖 일반화 증명

**fallback (반드시 살려둘 것)**: `c1-05` gold (`run-897ad65c686f`, IDOR → FIXED, 6게이트 전부 True).
현재 **유일하게 증명된 완주 경로**다. 위 둘이 무너져도 이건 돌아야 한다. 아무도 이 경로를 깨는 변경을 하지 않는다.

---

## 1. 이번에 왜 엇나갔는가 — 재발 방지 규칙

D5에 P2는 `main`을, P1은 `rag` 브랜치를, P3는 `security/agent`를 보고 서로 "미구현"이라고 판단했다.
같은 코드를 안 보고 있었다. 아래는 **예외 없는 규칙**이다.

### 규칙 1 — `main`이 유일한 진실
"구현됐다 / 안 됐다"는 **모든 주장은 `main` 기준**이다.
다른 브랜치 얘기를 할 때는 **반드시 브랜치명과 커밋 해시를 함께 적는다.**
❌ "RAG 연결했음" → ✅ "RAG 연결함 (`origin/rag` c8e48f8, main 미반영)"

### 규칙 2 — 하루 2회 main 통합 (고정 시각)
- **10:00** 과 **18:00**. P1이 병합을 집행한다.
- 그 시각 전까지 자기 브랜치를 push 해둔다. 늦으면 다음 슬롯.
- 병합 후 P1이 Discord에 **main 커밋 해시 + 전체 테스트 결과**를 공지한다.

### 규칙 3 — Discord 보고 형식 고정
```
[P?] <한 줄 요약>
브랜치: <name> @ <commit>
테스트: <통과/전체> (<명령>)
main 반영: 예 / 아니오
영향받는 사람: @… (없으면 "없음")
```
이 형식이 아니면 **다른 사람은 그 주장을 근거로 쓰지 않는다.**

### 규칙 4 — 파일 소유권 (아래 2절). 남의 파일은 고치지 않는다
필요하면 Discord로 요청하고 **소유자가 고친다**. 급해도 직접 고치지 않는다.

### 규칙 5 — 인터페이스 먼저, 구현 나중
아래 3절의 시그니처는 **D1 오전에 확정**한다. 확정 후에는 2일간 바꾸지 않는다.
바꿔야 하면 Discord에 올리고 **영향받는 사람 전원의 확인**을 받는다.

### 규칙 6 — 검증 없는 "완료" 금지
`cowork_rule.md` §98. 테스트·dry-run·실제 산출물 중 하나가 있어야 완료다.
**과거 handoff 문서를 근거로 현재 상태를 주장하지 않는다** (D5에 실제로 발생: 이미 해소된 "RAG 3건 실패"를 재실행 없이 인용).

---

## 2. 파일 소유권 — 배타적

| 소유자 | 파일 |
|---|---|
| **P1** | `mcp_server/**`, `core/policy_engine.py`, `core/report.py`, `core/orchestrator.py`, `core/state_machine.py` |
| **P2** | `runtime/**`, `targets/**`, `policies/**`, Cloudflare/VM 인프라 |
| **P3** | `verifiers/**`, `repair/**`, `core/judge.py` |
| **P4** | `model/**`, `scanners/**`, `eval/**` |
| 공용 | `contracts/schemas.py` — **D1 오전 이후 변경 금지(freeze)**. 정말 필요하면 전원 합의 |

테스트 파일은 대상 모듈 소유자를 따른다. `tests/`는 P1.

---

## 3. 인터페이스 계약 (D1 오전 확정, 이후 불변)

### 3.1 로컬 승인 레지스트리 — P2 제공 / P1 소비

```python
# runtime/registry.py  (P2 신규)
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

TargetKind = Literal["compose_project", "running_local"]

@dataclass(frozen=True)
class ApprovedTarget:
    target_id: str
    kind: TargetKind
    base_url: str              # loopback 검증 통과 보장 (http + localhost/127.0.0.1/::1 + 명시 port)
    allowed_hosts: list[str]
    source_path: Path          # 사용자 프로젝트 절대경로 (repo 밖 허용)
    manifest_sha256: str       # 승인 시점 manifest 내용 고정
    commands_sha256: str       # 승인 시점 argv 집합 고정  ★ 변경 시 재승인 강제
    approved_at: datetime

class LocalRegistry:
    DEFAULT_ROOT = Path.home() / ".vibecutter" / "registry"   # repo의 .vibecutter/ 와 분리

    @classmethod
    def load(cls, root: Optional[Path] = None) -> "LocalRegistry": ...
    def get(self, target_id: str) -> Optional[ApprovedTarget]: ...
    def list_ids(self) -> tuple[str, ...]: ...
    def approve(self, manifest, *, source_path: Path) -> ApprovedTarget: ...
    def revoke(self, target_id: str) -> None: ...
```

**불변식** (P2가 `approve()` 안에서 강제, P1은 신뢰):
- `base_url`은 loopback만 — `TargetManifest` 검증기를 통과해야만 저장된다
- `approve()`는 **승인 여부를 판단하지 않는다**. 사용자 승인은 P1의 tool 계층이 받고, P2는 기록만 한다
- 저장 경로는 `~/.vibecutter/registry/` — **repo의 `.vibecutter/`(evidence.db)와 섞지 않는다**

### 3.1.1 ⚠️ 사용자 프로젝트는 **git 저장소여야 한다** (코드 훑기에서 발견)

`runtime/worktree.py:43` `create()`가 대상 소스 저장소에 `git worktree add`를 한다
(`catalog.py:234` — *"Create run worktrees from the target app repository, not VibeCutter itself"*).
**패치 apply·6게이트 전체가 이 worktree 위에서 돈다.** 따라서:

- 등록 시 `source_path`가 git 저장소인지 검사하고, 아니면 **명확한 사유로 거부**한다(추측으로 진행하지 않는다)
- 커밋되지 않은 변경이 있으면 경고한다 — worktree는 커밋된 상태를 기준으로 만들어진다
- `git init`만 하면 되므로 안내 문구를 준다

이건 완화 대상이 아니다. "원본을 절대 건드리지 않는다"(기획서 10.1)가 worktree로 구현돼 있다.

### 3.2 정책 조회 — P1 소유

```python
# core/policy_engine.py
def require_target_allowed(target_id: str, *, registry=None) -> dict:
    """built-in demo target(policies/scope.yaml) 또는 사용자 레지스트리에 있으면 통과."""
```
**이중 출처**다. 기존 20개는 `scope.yaml`에 남고, 사용자 target은 레지스트리에서 온다.
→ **c1-05 gold 경로가 안 깨진다** (규칙: fallback 보존).

### 3.3 패치 합성 클라이언트 — P4 제공 / P3 어댑터가 소비

```python
# repair/llm_synth.py (P3, 이미 존재: origin/security/agent a189c17)
class PatchModelClient(Protocol):
    def synthesize_patch(self, prompt: str) -> str: ...

def make_llm_synthesizer(client: Optional[PatchModelClient]) -> synthesize_fn
# client=None이면 no-op → template-only로 안전 degrade
```

```python
# model/patch_client.py (P4 신규)
def build_patch_model_client() -> Optional[PatchModelClient]:
    """model.endpoints.chat_fn_from_env() 위 얇은 래퍼. endpoint 불가 시 None."""
```

### 3.4 코드 컨텍스트 — P4 제공 / P3·P4 공유

```python
# scanners/rag_enrich.py (P4, origin/rag 277b956)
def code_context(candidates, index, *, radius: int = 10) -> dict[str, str]
# {candidate_id: 줄번호 붙은 스니펫}
```
프롬프트에 싣는 코드는 **`model.serving.build_rerank_messages`의 egress 경계에서 `redact()`를 통과**한다.
P3의 `llm_synth.build_prompt`도 같은 규칙을 따른다(자체 redaction 유지해도 무해 — idempotent).

---

## 4. 안전 불변식 — 누구도 깨지 않는다

이 4개는 제품 주장의 근거다. 어떤 작업도 이것을 약화시키지 않는다.

1. **loopback 외 주소는 표현 불가능** — `TargetManifest.base_url_must_be_loopback_http` (`runtime/manifest.py:154`). **삭제·완화 금지.**
2. **승인되지 않은 argv는 실행 불가** — 등록 시 사용자가 **argv 전문**을 보고 `confirmed=True`. `commands_sha256`로 고정. argv가 바뀌면 재승인.
3. **판정에 LLM 없음** — `core/judge.py` 6게이트 + evidence 기반 `update_finding_status()`. LLM은 **후보 재랭킹과 패치 합성에만**.
4. **apply 전 사용자 승인** — diff를 보여주고 `confirmed=True`. 자동 batch는 별도 모드로 분리하고 audit log에 명시.

### Cloudflare Tunnel — 판단 (2026-07-21 확정)

**로컬에서 도는 것**: MCP 서버, 대상 Docker, `.vibecutter/evidence.db`, git worktree, 스캐너, verifier, 6게이트.
**나가는 것**: `POST /v1/chat/completions` **하나뿐**. 실린 내용은 rerank 스니펫(≈21줄 × 최대 10개)과 패치 대상 파일. secret은 `redact()`가 제거.

CF 엣지가 TLS를 종단하므로 그 스니펫은 Cloudflare를 통과한다. **실질 위험은 낮다고 판단하고 그대로 간다.**
다만 **문구는 사실에 맞춘다** (P1 문서 반영):

> ~~"모델·소스·취약점 데이터가 외부로 나가지 않는다"~~
> → "**제3자 LLM API를 쓰지 않는다.** 모델은 자체 서빙이며, 분석·evidence·패치는 전부 사용자 머신에서 처리된다. LLM 질의에 한해 코드 일부가 전송되며 secret은 redaction된다."

**Cloudflare Access는 여전히 건다** — 데이터가 아니라 **자원 문제**다. 토큰 하나가 유일 방어면 새는 순간 누구나 우리 GPU를 쓴다. (P2 P1 항목)

---

## 5. 타임라인

| 시각 | 내용 |
|---|---|
| **D1 09:00** | 인터페이스 확정 (3절). 각자 자기 계획 읽고 이견 즉시 제기 |
| **D1 10:00** | **P1 병합 #1**: `origin/rag` + `origin/security/agent` → main. 이후 전원 main 리베이스 |
| D1 10:00~18:00 | 병렬 구현 |
| **D1 18:00** | **P1 병합 #2** + 전체 테스트 공지 |
| **D2 10:00** | **P1 병합 #3**. 이 시점에 **기능 동결** — 이후는 통합·버그만 |
| D2 10:00~15:00 | 통합, E2E 실주행 |
| **D2 15:00** | 데모 리허설 1회차 (전원) |
| D2 15:00~ | 문서·슬라이드, 리허설 2회차 |

**D2 10:00 이후 새 기능 금지.** 그때까지 안 된 것은 "알려진 한계"로 문서화한다.

---

## 6. 현재 상태 (2026-07-21 기준, 사실)

```
origin/main            182bdda   ← RAG·llm_synth 없음. 460 tests OK
origin/rag             c8e48f8   ← R-1/R-2 RAG 배선. 463 tests OK. main +3/-2
origin/security/agent  a189c17   ← llm_synth + locator CWE 분기(015f23c)
```

- `vc_run_target_audit` **tool 없음** (Python 함수만)
- `vc_export_sarif` **NotImplementedError**
- `vc_register_target()`은 실제 등록이 아니라 체크인 manifest와 byte 비교
- 235B endpoint: 랩탑·P2 로컬 모두 도달 불가 → **현재 모든 run이 휴리스틱**
- `driver.py:145`가 `confirmed=True`를 자동으로 넘김 (안전 불변식 4 위반)
