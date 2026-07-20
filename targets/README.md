# P2 Target Manifest

각 등록 대상은 하나의 versioned YAML manifest로 기술한다. `id`는 반드시 P1 공통 계약의
`contracts.schemas.Target.id`와 같은 값이어야 한다. manifest는 신뢰된
repository configuration이며, MCP caller가 URL·shell 명령을 전달하는 통로가 아니다.

## Required lifecycle commands

모든 manifest는 다음 고정 command ID를 제공해야 한다.

- `build`
- `start`
- `stop`
- `reset` (명시적 run-level approval 필요)

테스트가 있다면 `test_suites[].command_id`로 manifest에 선언한다. command는 문자열
shell이 아니라 `argv` 배열로 선언되며 P2 runner가 `shell=False`로 실행한다.
기본 작업 디렉터리는 `source_dir`이다. 추적되는 P2 Compose overlay처럼 repository 안의
별도 orchestration 파일을 실행해야 할 때만 command의 optional `working_dir`를 repository
root 기준 상대 경로로 선언한다. 상위 경로 탈출과 절대 경로는 허용하지 않는다.

Python helper script가 필요하면 `argv[0]`에 고정 토큰 `"{vibecutter_python}"`을 쓸 수 있다.
P2 lifecycle은 이 값만 현재 VibeCutter 프로세스의 Python interpreter 절대 경로로 해석한다.
이는 Windows `py` launcher나 `python`/`python3` PATH 별칭에 의존하지 않으며, 임의 환경변수나
caller 입력을 확장하는 기능은 아니다.

## Scope and secrets

- `base_url`은 explicit port가 있는 `localhost`, `127.0.0.1`, 또는 `::1` HTTP URL만 허용한다.
- `source_dir`와 `log_paths`는 repository 내부 relative path만 사용할 수 있다.
- role fixture에는 secret 값 대신 `VIBECUTTER_*` 환경변수 이름만 기록한다. 실제 값은
  gitignore된 `.env`에 둔다.
- manifest 파일만으로 target이 MCP에서 승인되는 것은 아니다. P1 policy의 target allowlist와
  연결된 후에만 등록·실행한다.

`example-fastapi.yaml`은 schema 및 Docker command 배열을 보여 주는 예시이며, 실제 서비스
compose 파일이나 credential을 포함하지 않는다.

`tool_versions`에는 inventory 시 확인한 Docker/Gradle/Node/Python 등의 버전을 기록한다.
P1은 이 값을 해당 target의 `Run.tool_versions`에 복사해 run 재현성 metadata로 사용한다.

실제 승인 후보 manifest는 `targets/manifests/`에만 둔다. P2 `TargetCatalog`는 이 경로의
YAML만 읽어 `Target.id`로 조회하며, 예제 파일은 catalog에 포함하지 않는다. P1 policy
allowlist를 통과하기 전에는 catalog에 있는 target도 실행하면 안 된다.

## Source identity and bootstrap

`targets/source-lock.yaml`은 모든 runtime manifest ID를 canonical repository URL과 exact
40자 commit에 1:1로 고정한다. production `TargetCatalog`는 manifest와 lock의 누락·추가 항목을
거부하고, P1 `Target.source_commit`과 run-scoped worktree가 같은 commit을 사용하게 한다.

source 전문은 계속 `.vibecutter/targets/sources/<target_id>`에만 두고 git에 올리지 않는다.
clean host의 누락 clone은 `catalog.bootstrap_source(target_id, approved=True)`로 생성한다.
caller는 URL, destination, revision, Git flag를 전달할 수 없다. 기존 clone이 dirty하거나
origin/HEAD가 lock과 다르면 bootstrap은 그 clone을 fetch/reset/checkout하지 않고 거부한다.

P1의 `vc_check_readiness` 연결점은 `catalog.readiness_for(target_id)`이다. 이 검사는
build/start/reset을 실행하지 않고 source directory, manifest command의 executable, role
fixture 환경변수 이름, 로그 **위치/크기**만 검사한다. 로그 본문이나 secret 값은 반환하지
않으며 evidence에 저장하려면 별도 redaction 절차가 필요하다.

GPU batch의 local runtime 상태는 아래처럼 해당 서버에서 확인한다. queue 밖 target은 probe 전에
거부되고, SSH dispatch나 credential 처리는 이 도구의 범위가 아니다.

```bash
cd /opt/VibeCutter
.venv-p2/bin/python -m runtime.gpu_preflight \
  --worker-id gpu-1 --expect-port-state listening
```

`listening`은 P3 audit 직전, `available`은 build/start 전 port leak 확인에 사용한다. role fixture
환경변수 누락은 runtime blocker와 분리해 `warnings`로 반환한다.

P1 regression gate 연결점은 `catalog.test_runner_for(target_id).run(run_id)`이다. 먼저
`catalog.worktree_manager_for(target_id).create(run_id)`로 **대상 앱 source clone의 Git
worktree**를 `.vibecutter/worktrees/<target_id>/<run_id>`에 만든다. runner는 이 경로가
실제 target Git worktree인지 확인한 뒤에만 manifest test suite를 실행한다. 따라서 patch와
regression은 VibeCutter 원본이나 대상 앱의 원래 branch가 아니라 같은 detached target
worktree에서 수행된다. test suite가 없으면 `not_configured`이며 regression 통과로 처리하면
안 된다.

## Run-scoped patched runtime

P1 승인 apply가 target worktree에 diff를 적용한 뒤에는 P2가
`catalog.run_overlay_for(target_id, run_id).prepare()`로 ignored generated Compose를 만든다.
생성 파일은 `.vibecutter/run-overlays/<target_id>/<run_id>/compose.yaml`에만 존재하며,
checked-in manifest/Compose는 변경하지 않는다. source repository 아래의 build context만 detached
worktree 경로로 바꾸고, P2 Dockerfile·Nginx bind mount 같은 runtime 자산은 repository 내부의
trusted absolute path로 고정한다.

`overlay.execute("build")`, `overlay.execute("start")`, `overlay.check_health()`는 manifest의
고정 argv에서 configured Compose file 인자만 generated Compose로 바꿔 실행한다. 생성 직후에도
동일한 `docker_isolation` static 검사를 다시 통과해야 하며, P1 policy가 승인한 기존 loopback port를
사용한다. 따라서 run instance를 올리기 전 기존 target instance는 approved stop/reset으로 내려야 한다.

write verifier가 shared baseline을 변경한 경우에는 patched overlay 전용 `reset_run()`으로 원복할 수
없다. P1 승인 gate 뒤 `restore_baseline_after_write(target_id, approved=True)`를 호출하면 P2가
provisioning 계약을 먼저 검증하고 reset → start → health를 수행한다. `fixture_file` target은 stale
fixture artifact를 제거하고 고정 command로 재생성하며, `self_signup` target은 fresh baseline만 남긴다.

## P1 policy onboarding

manifest만으로는 실행할 수 없다. 해당 `id`를 `policies/scope.yaml`에 아래처럼 등록하고,
lifecycle tool용 typed command도 `policies/commands.yaml`에 등록해야 한다.

```yaml
# scope.yaml
targets:
  example-fastapi:
    allowed_hosts: [127.0.0.1]
    port: 18080

# commands.yaml
commands:
  build_target: {args: {target_id: str}}
  start_target: {args: {target_id: str}}
  reset_target: {args: {target_id: str}}
  provision_target: {args: {target_id: str}}
```

P2 `TargetRuntimeService`는 checked-in manifest와 MCP로 제출된 manifest가 완전히 같은지,
host와 port가 scope와 같은지, lifecycle command ID가 typed policy에 있는지를 차례로
검증한다. `vc_reset_target`는 추가로 `approved: true`가 필수다.

## P4 inventory reconciliation

`datasets/inventory.yaml`은 전체 감사 대상과 취약점군 coverage의 **discovery catalog**이며,
`targets/manifests/`는 P2가 실제 build/start/health/reset으로 확인한 **executable runtime
catalog**이다. 따라서 미착수 inventory 항목은 manifest가 없을 수 있지만, checked-in manifest는
반드시 inventory ID에 있어야 한다. P4의 adapter는 사전 제안값이므로, 실제 runtime adapter가
다르면 P2가 `inventory_adapter_overrides.yaml`에 이유와 함께 기록한다. 이 계약은
`tests/test_inventory_manifest_contract.py`가 회귀 검사한다.

P4 batch scanner는 이미 clone된 대상만 `.vibecutter/targets/sources/<target_id>`에서 읽는다.
새 P2 manifest는 같은 target ID와 source 경로를 사용해야 하며, 재-clone이나 외부 URL 입력은
필요하지 않다.

## P3 IDOR fixture handoff

실제 앱에서 두 사용자와 소유 자원을 준비해야 할 때 P2는 선택적으로
`prepare_idor_fixture` command를 manifest에 둔다. 이 command는 target이 `start`된 뒤에만
실행하며, 역할 ID·baseline/attack path·안전한 marker만 `.vibecutter/fixtures/`의
gitignored JSON에 기록한다. password, JWT, session cookie와 HTTP response body는 stdout,
manifest, handoff, evidence에 기록하지 않는다. P3는 이 metadata로 candidate별 재현을
구성하고, cross-user request 및 취약점 판정은 P3 verifier가 담당한다.

현재 P3가 바로 사용할 target은 `26s-w1-c2-04`다. `prepare_idor_fixture`가 user A/B,
각자 소유 vocabulary, victim marker와 baseline/attack path를
`.vibecutter/fixtures/26s-w1-c2-04-idor.json`에 생성한다. 이 source는 login credential을
발급하지 않는 identifier-only API이므로 metadata의 `authentication.mode`은 `none`이다.
P3는 metadata 밖의 credential을 추측하거나 저장하지 않으며, cross-user request와 verdict만
자신의 verifier에서 수행한다.

## Docker Compose isolation

Docker Compose target은 `docker_isolation`을 선언한다. readiness 검사는 실행 전에 compose
파일이 repository 내부에 있는지, 모든 service가 egress-blocked network에 속하는지,
host port가 `127.0.0.1` 또는 `::1`에만 bind되는지, `privileged: true`나 `network_mode`가
없는지를 확인한다. egress-blocked network는 `internal: true`이거나, Docker bridge에서
`com.docker.network.bridge.enable_ip_masquerade: "false"`를 설정한 network다. 후자는
Docker Desktop에서 loopback ingress를 유지하면서 runtime outbound NAT를 막기 위한 호환
구성이다. 하나라도 어기면 readiness는 false다.
