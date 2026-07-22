# Vibe Cutter

**"내 프로젝트 검사해줘"라고 한 마디만 하면, Claude가 알아서 보안 위험을 찾고 → 고칠 계획을 보여주고 →
승인하면 고치고 → 진짜 고쳐졌는지까지 다시 확인해주는 도구입니다.**

보안 지식이 전혀 없어도 됩니다. 전문 용어(CWE, IDOR, endpoint...)는 채팅에 등장하지 않고, 여러분이
답할 질문은 항상 "네/아니오" 뿐입니다.

> ⚠️ **딱 하나만 기억하세요: 이 도구는 여러분의 컴퓨터 안에서 돌고 있는, 여러분 소유의 프로젝트만
> 검사할 수 있습니다.** 인터넷에 있는 다른 사람의 사이트 주소는 애초에 입력조차 되지 않습니다.

---

## 1. 이게 뭔가요?

보통 보안 점검은 전문가가 여러 도구를 돌리고 결과를 해석해야 하는 어려운 일입니다. Vibe Cutter는
그 과정 전체를 Claude(또는 다른 AI 에이전트)에게 맡길 수 있게 해주는 "능력 확장 도구"(MCP 서버)입니다.

여러분이 하는 일은 딱 두 가지뿐입니다:

1. Claude에게 "내 프로젝트 검사해줘"라고 말한다.
2. 중간중간 나오는 예/아니오 질문에 답한다.

나머지 — 프로젝트 실행, 취약점 재현, 원인 분석, 패치 작성, 패치 적용, 다시 공격해보고 안 뚫리는지
확인, 정상 기능이 안 깨졌는지 확인 — 는 전부 Claude가 알아서 합니다.

## 2. 무엇을 준비해야 하나요?

- **Python 3.13** — macOS는 `brew install python@3.13`
  (다른 버전을 쓰면 안 되는 이유: 사용하는 정적분석 도구 semgrep이 3.14 이상에서 아직 실행되지 않습니다.)
- **검사하려는 프로젝트가 git 저장소여야 합니다**(커밋이 최소 1개 이상 있어야 함). 이유: 수정은
  항상 원본이 아니라 되돌릴 수 있는 별도 복제본에서 이루어지는데, 그 복제본을 만드는 방식(git
  worktree)이 git을 전제로 하기 때문입니다. 아직 git repo가 아니라면 `git init && git add -A &&
  git commit -m init` 한 번이면 됩니다.
- 검사하려는 프로젝트가 **Docker Compose**를 쓴다면 Docker Desktop이 켜져 있어야 합니다.

## 3. 설치 (한 번만 하면 됩니다)

```bash
git clone <이 저장소 주소>
cd Vutter
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium   # 화면에 나타나는 공격(XSS)을 확인할 때 쓰는 격리된 브라우저
```

## 4. Claude와 연결하기 (한 번만 하면 됩니다)

**Claude Code를 쓴다면** 터미널에서 아래 한 줄이면 끝입니다(`/절대/경로/Vutter`는 방금 clone한
폴더의 실제 경로로 바꿔주세요):

```bash
claude mcp add --scope user vibecutter -- /절대/경로/Vutter/.venv/bin/python /절대/경로/Vutter/mcp_server/server.py
```

`--scope user`를 쓰면 어떤 프로젝트에서 Claude Code를 열어도 이 도구를 쓸 수 있습니다. 등록 후
Claude Code를 재시작하면 적용됩니다.

**Claude Desktop 앱을 쓴다면** `~/Library/Application Support/Claude/claude_desktop_config.json`
파일을 열어서(없으면 새로 만들어서) 아래 내용을 넣어주세요:

```json
{
  "mcpServers": {
    "vibecutter": {
      "command": "/절대/경로/Vutter/.venv/bin/python",
      "args": ["/절대/경로/Vutter/mcp_server/server.py"]
    }
  }
}
```

저장 후 Claude Desktop을 재시작하면 적용됩니다. (경로는 반드시 `/Users/...`처럼 처음부터 끝까지
다 적힌 절대경로여야 합니다 — `~`나 상대경로는 동작하지 않습니다.)

## 5. 사용법 — 정말 한 문장이면 충분해요

연결이 끝났다면, Claude와의 대화창에서 이렇게 말해보세요.

> **나**: 내 프로젝트(`~/dev/my-app`) 좀 검사해줘

그러면 대략 이런 대화가 이어집니다:

> **Claude**: (레포를 읽어보고) 앱을 검사하려면 평소 쓰는 시작 명령을 실행해야 해요 — 그대로
> 실행해도 될까요? [네/아니오] (자세히 보기)
>
> **나**: 네
>
> **Claude**: (자동으로 스캔하고 실제로 공격을 재현해봄) 로그인한 사람이면 누구나 URL의
> 주문번호만 바꿔서 남의 주문을 볼 수 있어요.
>
> **Claude**: 주문을 보여주기 전에 그게 본인 것인지 서버가 확인하도록 고칠게요. 고쳐도 될까요?
> [네/아니오] (바뀌는 코드 보기)
>
> **나**: 네
>
> **Claude**: 고쳤어요. 예전 방법으로는 이제 안 뚫리고, 앱이 정상 동작하는 것까지 다시 확인했어요.

이게 전부입니다. 채팅에 CWE 코드나 게이트별 통과 여부 같은 건 기본적으로 안 나옵니다 — 궁금하면
"자세히 보여줘"라고만 하면 상세 내용을 볼 수 있습니다.

## 6. 안전하게 설계된 이유

- **내 컴퓨터 안의, 내가 승인한 프로젝트만** 다룹니다. 인터넷 주소(IP·도메인)는 애초에 입력할 수
  있는 형태로 만들어져 있지 않습니다 — 우회할 방법 자체가 없습니다.
- **예/아니오로 승인하기 전에는** 명령 실행도, 코드 수정도, 그 무엇도 일어나지 않습니다. 이건
  프롬프트로 부탁하는 게 아니라 코드 레벨에서 강제됩니다 — Claude가 실수로 건너뛰어도 막힙니다.
- 수정은 **원본 코드가 아니라 되돌릴 수 있는 복제본**에서만 이루어지고, 실제로 공격이 막히고
  기존 기능이 안 깨졌는지까지 자동으로 재확인된 경우에만 "고쳤다"고 보고합니다.
- 코드 일부가 AI 모델로 전송되는 경우(수정안 생성 시)에도 먼저 동의를 구하고, 비밀번호·토큰
  같은 값은 자동으로 가려집니다.
- 이 서버는 여러분의 컴퓨터에서만 실행되는 프로그램(stdio 방식)이라 외부에 별도 포트를 열지
  않습니다.

## 7. 더 자세히 알고 싶다면

| 문서 | 내용 |
| --- | --- |
| [`SKILL.md`](./SKILL.md) | Claude가 이 도구를 어떤 순서로, 어떤 승인을 받으며 쓰는지(운영 절차) |
| [`SECURITY_POLICY.md`](./SECURITY_POLICY.md) | 안전 정책 상세 — 무엇을 할 수 있고 절대 하지 않는지 |
| [`Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx`](./Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx) | 전체 기획서(아키텍처·모델 전략·평가 설계) |

---

## 프로젝트 정보 (개발/기여용)

아래는 이 저장소에 직접 코드를 기여하는 팀원을 위한 정보입니다. 사용만 하실 분은 몰라도 됩니다.

### 저장소 구조

```
mcp_server/   MCP stdio 서버, resources/tools
core/         state machine, policy engine, evidence store, judge, planner
contracts/    Target/Run/Observation/Candidate/Finding/Patch/Validation/Trajectory 공통 스키마
policies/     scope.yaml, commands.yaml, vulnerability_profiles/ (target allowlist, command 정책)
docs/handoffs/  역할별 일일 handoff 기록
```

### 역할 분담

| 역할 | 담당 | 소유 영역 |
| --- | --- | --- |
| P1 | 이지민 | MCP server, core state/policy/evidence/judge, 공통 contracts, report 기반 |
| P2 | 안종화 | target manifest, adapters, lifecycle/runtime, worktree/reset/test runner |
| P3 | 박준서 | attack surface, verifier, root-cause, patch/validation logic |
| P4 | 유나연 | inventory, RAG/model, dataset, baseline/metrics/evaluation |

### 협업 규약·계획 문서

| 문서 | 내용 |
| --- | --- |
| [`TEAM_CONTRACT.md`](./TEAM_CONTRACT.md) | 인터페이스 계약, 안전 불변식, 타임라인 — 최종 근거 |
| [`cowork_rule.md`](./cowork_rule.md) | 4인 협업 규약 — 역할 경계, 공통 계약, handoff 규칙 |
| [`REMAINING_PLAN.md`](./REMAINING_PLAN.md) | 남은 작업 통합 계획 — 지금 어디까지 됐는지 |
| `docs/handoffs/` | 일자별 역할별 handoff 기록(`D{day}-P{role}.md`) |

### 공통 계약 변경 시 주의

`contracts/`, target manifest, 상태 이름, finding/evidence schema, policy는 프로젝트 전체가 공유하는
계약입니다. 변경이 필요하면 `docs/handoffs/`에 영향 범위와 이유를 남기고, 조용히 바꾸지 않습니다
(cowork_rule.md 2절·6절).
