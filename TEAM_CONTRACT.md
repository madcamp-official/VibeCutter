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
    allowed_hosts: list[str]     # hostname만 저장. 예: ["127.0.0.1"]
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
- `allowed_hosts`에는 **hostname만** 저장한다. port는 목록에 넣지 않으며, 실행 목적지의
  port는 승인된 `base_url`의 명시 port로만 결정한다. 따라서 임의 tool 입력으로 loopback의
  다른 port를 선택할 수 없다
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

## 3A. 추가 계약 (2026-07-21 P2 리뷰 반영)

아래 10건은 초안에 빠져 있던 계약이다. **③④⑥은 실제 결함**이므로 구현 변경을 동반한다.

### 3A-1. 사용자 등록 MCP 인터페이스 (P1) — ✅ 확정·구현됨

```python
vc_register_local_target(manifest: dict, source_path: str, confirmed: bool = False)
    -> RegistrationPreview
```
| 필드 | 의미 |
|---|---|
| `target_id`, `kind`, `base_url`, `source_path` | 승인 대상 요약 |
| `commands: dict[str, list[str]]` | **argv 전문.** 요약·생략 금지 |
| `blockers: list[str]` | 하나라도 있으면 `confirmed=True`여도 **저장하지 않는다** |
| `warnings: list[str]` | 진행은 되나 사용자가 알아야 할 것 |
| `confirmed`, `registered` | 요청값 / 실제 저장 여부 |

**오류 계약**: manifest 스키마 위반은 `ValidationError`(loopback 위반 포함). 정책 거부는 `PolicyViolation`.
`blockers`는 예외가 아니라 **정상 반환**이다 — 사용자가 고칠 수 있는 것이기 때문.

### 3A-2. 승인 manifest 스냅샷 (P2) — ⚠️ 필수

**해시만으로는 catalog가 build/start/reset/test 정보를 복원할 수 없다.**
레지스트리는 **승인된 manifest 본문을 immutable snapshot으로 저장**하고, 이후 실행은 **그 스냅샷만** 쓴다.

```
~/.vibecutter/registry/<target_id>/
  ├─ manifest.yaml     ← 승인 시점 본문 (읽기 전용 취급, 이후 수정 금지)
  ├─ approval.yaml     ← source_path, hashes, approved_at
```
사용자가 원본 manifest 파일을 나중에 고쳐도 **실행에는 영향이 없다.** 해시 불일치는 "재승인이 필요하다"를 알리는 용도이지, 실행 대상을 바꾸는 근거가 아니다.

`approval.yaml`의 `allowed_hosts`는 hostname만 가진다(예: `["127.0.0.1"]`). 실행 port는
snapshot의 `base_url`에 고정한다. P1 정책은 host 허용 여부를 확인하고, P2 runtime은
실제 lifecycle/health 대상이 승인된 `base_url`과 정확히 일치하는지 확인한다.

### 3A-3. `target_id` 충돌 규칙 (P1) — ⚠️ 구현 변경

사용자가 `26s-w1-c1-05`를 등록하면 조회 시 built-in이 이겨서 **자기 프로젝트가 아닌 것이 검사된다.** 조용히 틀린 대상을 스캔하는 것은 최악이다.

- **등록 시 거부**: built-in target_id와 충돌하면 `blockers`에 담고 저장하지 않는다
- **조회 시 built-in 우선**: 이미 저장된 충돌 기록이 있어도 built-in 정의가 이긴다(방어 심층화)
- 권장 규칙: 사용자 target_id는 `local-` 접두사. 강제하지는 않되 충돌 시 안내

### 3A-4. dirty git 정책 (P1) — ⚠️ 구현 변경 (경고 → 차단)

**실행 중인 서비스는 dirty 코드인데 worktree는 마지막 commit이다.** 그러면 스캔·패치 대상과 실제로 도는 코드가 **다르다** — verify 결과가 패치 대상과 대응하지 않는다. 이건 편의 문제가 아니라 **정합성 결함**이다.

- closed-loop(`vc_audit_target`) 대상은 **dirty repo 거부**
- 사용자에게: "커밋하거나 stash한 뒤 다시 시도하세요"
- scan/verify 전용 조회는 경고만으로 허용 가능(패치를 만들지 않으므로)

### 3A-5. `running_local`의 lifecycle 한계 (P3) — K-1 정련

**패치한 worktree를 build/restart 못 하면 `FIXED`를 증명할 수 없다.** attack 게이트를 다시 돌릴 대상이 없기 때문이다.

- `FIXED` 판정 대상이 되려면 **build + patched-worktree restart + health** 세 가지가 가능해야 한다
- 못 하면 그 target은 **scan/verify 전용**으로 제한하고, 최대 도달 상태는 `PATCH_PROPOSED`
- **못 돌린 게이트를 통과로 위조하지 않는다**(P3 K-2와 동일 원칙)

### 3A-6. 패치 전달·보존 (P1) — ✅ **완료(2026-07-21, W-4)**

`reset_run()`이 Compose 정리 후 **worktree를 제거한다**(`runtime/target_service.py`). 사용자의 목표는 **"패치를 받는 것"**인데 지금은 정리와 함께 사라진다.

- [x] **`vc_export_patch(run_id)` 신규** — diff를 `.vibecutter/runs/<run_id>/security-fix.patch`로 보존. **reset보다 먼저** 호출된다(`mcp_server/tools_repair.py`)
- `vc_resume_audit`가 reset 전에 반드시 export를 거친다 — export가 예외를 던지면 reset을 아예 시도하지 않는다
- **원본 branch 반영은 우리가 하지 않는다.** 사용자가 `git apply`하는 별도 행위 — 기획서 10.1 "원본 미변경" 유지
- 테스트: `tests/test_export_patch.py` 5건

### 3A-7. 승인 후 재개 흐름 (P1) — ✅ **완료(2026-07-21, W-4)**

`RunState.WAITING_APPROVAL`은 이미 상태 기계에 있다(`PATCH_PROPOSED → WAITING_APPROVAL → PATCH_APPLIED`). 그런데 driver가 `confirmed=True`를 자동으로 넘겨 **그 상태를 스쳐 지났다** — 지금은 제거됐다(`mcp_server/driver.py:_audit_one_candidate`가 `vc_generate_patch` 직후 멈춘다).

```
driver(batch)  → verify → localize → generate_patch → PATCH_PROPOSED 에서 정지
  ↓ Host가 diff를 사용자에게 표시
vc_apply_patch(patch_id, confirmed=True)  → WAITING_APPROVAL → PATCH_APPLIED
  ↓
vc_resume_audit(run_id):
  vc_build_and_test → vc_replay_attack → vc_validate_regression → FIXED/RETRY
  → vc_export_patch(run_id) → reset_run
```
재개 주체는 **Host(사용자 승인 후)**다. driver가 자동으로 넘어가지 않는다.
테스트: `tests/test_resume_audit.py` 5건, `tests/test_driver.py`의 `RunTargetAuditTests`(자동 apply 미호출 확인으로 갱신).

**보류 — `vc_audit_target(mode=...)` tool 노출은 하지 않았다.** `run_target_audit`의 `_default_invoke`가 `asyncio.run(mcp.call_tool(...))`을 쓰는데, 이걸 그대로 `@mcp.tool()`로 감싸면 FastMCP가 이미 돌리고 있는 이벤트 루프 **안에서** `asyncio.run()`을 또 호출하게 돼(`RuntimeError: asyncio.run() cannot be called from a running event loop`) 라이브 서버에서만 터지는 버그가 된다(단위 테스트는 fake invoke라 안 잡힘). driver는 지금처럼 CLI/배치 전용 Python 함수로 남겨두고, 이 tool 노출은 async 배선을 다시 설계해야 하는 별도 작업으로 분리한다.

### 3A-8. target별 동시 실행 잠금 (P2)

고정 포트를 공유하므로 같은 target에 run이 둘 붙으면 baseline·reset·evidence가 섞인다.

- target당 **active run 1개** lease. 획득 실패 시 명확한 오류
- lease에 timeout과 소유 run_id를 기록. 중단된 run의 lease는 회수 가능
- driver 내부는 이미 순차 실행이지만, **여러 사용자·여러 배치**를 막는 계층은 없다

### 3A-9. write verifier 원복 (P3)

`restore_baseline_after_write()`는 이미 있다(`runtime/target_service.py:211`). 계약으로 고정한다.

- write 검증 candidate는 **safe method / path / body / observe / rollback**을 `attack_params`에 typed로 갖는다
- write verifier 실행 후 **반드시** `restore_baseline_after_write(target_id, approved=True)`
- `reset_run()`은 run-scoped overlay 전용이라 **shared baseline을 원복하지 않는다** — 별도 API인 이유

### 3A-10. egress 동의 · redaction 범위 (P1/P4)

**확인된 결함**: `core/report.py`에 `redact()` 호출이 **0건**이다. evidence와 audit log는 걸지만 리포트는 안 건다.

- [ ] redaction을 **모든 사용자 대면 산출물**에 적용: evidence(✅) / audit log(✅) / **report HTML(❌)** / SARIF / patch diff / container log
- [ ] **egress 동의**: 등록 시 또는 첫 LLM 호출 시 "코드 일부가 LLM 질의로 전송됩니다(secret은 제거)"를 1회 표시하고 기록
- 전송 범위를 사실대로: rerank 스니펫(≈21줄 × 최대 10개) + 패치 대상 파일. 그 외 evidence·DB·로그는 **로컬을 벗어나지 않는다**

### 3A-11. P2 인터페이스 확인 5건 회신 (2026-07-21 확정)

P2가 runtime 독립 구현 전 물은 5건. **P1이 결정하고 확정했다. 이후 안 바꾼다.**

| # | 확정 |
|---|---|
| 1 | **`manifest_for()` 채택.** P1은 snapshot 파일을 직접 읽지 않는다 — 경로·포맷 지식이 소유 경계를 넘어 복제되면 P2가 저장 구조를 바꿀 때 P1이 조용히 깨진다. 실행은 **항상 승인 당시 snapshot만** |
| 2 | **lease 획득은 `run_target_audit` 진입 직후, 해제는 `finally`.** worker가 아니라 **배치 전체** 단위 — scan run과 모든 worker가 같은 고정 포트를 공유하므로 |
| 3 | compose는 `build → start`, running_local은 **readiness 확인 후 진행**. FIXED는 build+restart+health 전부 가능할 때만 |
| 4 | driver는 `confirmed=True`를 **자동 전달하지 않는다**. resume tool = **`vc_resume_audit(run_id)`** |
| 5 | `vc_export_patch(run_id)`를 **reset보다 먼저**. **export 실패 시 reset 금지** |

**2번 보충 — `timeout`의 의미를 고정한다**: **lease TTL(만료)이지 대기 시간이 아니다.**
고정 포트라 기다려도 못 쓰므로 **블로킹 대기 없이 즉시 실패**가 맞다. TTL이 지난 lease는 죽은 run의 것으로 보고 회수 가능해야 한다(중단된 run이 target을 영구 점유하면 안 됨).
예외는 `PolicyViolation`이 아니라 **`TargetBusyError`**(runtime 소유) — 정책 위반이 아니라 자원 경합이다. 메시지에 점유 run_id와 만료 시각을 담는다.

**3번 보충 — 별도 방어 코드가 필요 없다**: `core/judge.py`의 `compute_verdict()`는 게이트 중 하나라도 `None`이면 verdict를 내지 않는다. build 게이트가 `None`이면 **FIXED가 구조적으로 불가능**하다. §3A-5는 기존 구현으로 자동 강제된다(P3 05:07 확인).

**4번 확정 흐름**:
```
vc_audit_target(target_id, mode="propose")   ← 기본. PATCH_PROPOSED 에서 정지
  ↓ Host가 diff를 사용자에게 표시
vc_apply_patch(patch_id, confirmed=True)     ← 승인 지점 (기존 tool 재사용)
  ↓ WAITING_APPROVAL → PATCH_APPLIED
vc_resume_audit(run_id)                      ← 신규. 6게이트 → export → reset
```
완전 자동은 `mode="batch_approved"`로 분리하고 audit log에 mode를 기록한다.

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

## 6. 현재 상태 (2026-07-21 14:40 KST 기준, 사실)

### 브랜치 — **§1 규칙 2가 실제로 작동해서 세 갈래가 main으로 모였다**

```
origin/main  935e362  ← 아래가 전부 들어감
  ├─ c8e48f8  RAG 배선 + 코드 컨텍스트 (구 origin/rag)
  ├─ e2ec373  llm_synth + locator CWE 분기 (구 security/agent, P3 병합)
  ├─ 0d6d961  P4 문서·train_lora (P4 병합)
  ├─ 13706de  정책 이중 출처 + vc_register_local_target (P1 R1)
  └─ 935e362  model/patch_client.py (P4 C-3)

origin/codex/p2-local-registry  8c6ed5c  ← LocalRegistry + running_local kind. **main 미반영**
origin/security/agent           2e30ade  ← P3 결합검증 추가분. **main 미반영**
```

### 해소된 것
- ✅ `llm_synth`(P3) · `patch_client`(P4) · RAG(P1) 전부 **main에 있다**
- ✅ P3가 05:37에 **어댑터↔patch_client 결합 검증 완료**(스모크 3/3 + 헤르메틱 57/57) → R-3b 배선만 남음
- ✅ P2의 `LocalRegistry`가 계약 3.1을 정확히 구현했고 §3A-2 snapshot(`manifest_for()`)까지 포함
- ✅ Juice Shop 계약 확정: regression=**B(image smoke)**, verify=injection blind 차등, `GET /rest/products/search?q=`
- ✅ camp1 c1-05 gold 복구됨

### 남은 블로커
- ❌ **`source_lock.py` external_allowlist** — P1이 03:09에 설계 확정·03:12 승인받고 **미이행**. P2가 Juice Shop 등록을 못 해 3시간+ 대기 중. 값은 이미 확보: `https://github.com/juice-shop/juice-shop.git` @ `1867b926c5f50e4e692dc9c8f61821413cebe0cd`
- ❌ **235B endpoint 미도달** — Cloudflare URL 미제공. **현재 모든 run이 휴리스틱**. P4가 05:23·05:28 두 번 요청. **스프린트 최대 리스크**
- ❌ `driver.py:145`가 `confirmed=True` 자동 전달 (안전 불변식 4 위반)
- ❌ `vc_export_sarif` NotImplementedError / `vc_export_patch`·`vc_resume_audit` 미존재
- ❌ `core/report.py` redaction 0건 (§3A-10)

### 운영 주의 (2026-07-21 03:12 실측)
camp1 c1-05 fresh run이 **DB secret 불일치로 실패**했다. run마다 새 일회성 secret을 쓰는데 기존 DB 볼륨이 남아 MySQL 인증이 어긋난다.
→ **fresh run은 반드시 같은 프로세스에서 새 secret 생성 → `down --volumes` → up/build/verify**. 볼륨 유지한 채 secret만 바꾸면 재발한다. 데모 리허설에서 그대로 지킬 것.
