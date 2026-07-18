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

P1의 `vc_check_readiness` 연결점은 `catalog.readiness_for(target_id)`이다. 이 검사는
build/start/reset을 실행하지 않고 source directory, manifest command의 executable, role
fixture 환경변수 이름, 로그 **위치/크기**만 검사한다. 로그 본문이나 secret 값은 반환하지
않으며 evidence에 저장하려면 별도 redaction 절차가 필요하다.

P1 regression gate 연결점은 `catalog.test_runner_for(target_id).run(run_id)`이다. runner는
임의 경로를 받지 않고 P2 `WorktreeManager`가 관리하는 `.vibecutter/worktrees/<run_id>`가
실제 Git worktree인지 확인한 뒤에만 manifest test suite를 실행한다. test suite가 없으면
`not_configured`이며 regression 통과로 처리하면 안 된다.

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
```

P2 `TargetRuntimeService`는 checked-in manifest와 MCP로 제출된 manifest가 완전히 같은지,
host와 port가 scope와 같은지, lifecycle command ID가 typed policy에 있는지를 차례로
검증한다. `vc_reset_target`는 추가로 `approved: true`가 필수다.

## P3 IDOR fixture handoff

실제 앱에서 두 사용자와 소유 자원을 준비해야 할 때 P2는 선택적으로
`prepare_idor_fixture` command를 manifest에 둔다. 이 command는 target이 `start`된 뒤에만
실행하며, 역할 ID·baseline/attack path·안전한 marker만 `.vibecutter/fixtures/`의
gitignored JSON에 기록한다. password, JWT, session cookie와 HTTP response body는 stdout,
manifest, handoff, evidence에 기록하지 않는다. P3는 이 metadata로 candidate별 재현을
구성하고, cross-user request 및 취약점 판정은 P3 verifier가 담당한다.

## Docker Compose isolation

Docker Compose target은 `docker_isolation`을 선언한다. readiness 검사는 실행 전에 compose
파일이 repository 내부에 있는지, 모든 service가 egress-blocked network에 속하는지,
host port가 `127.0.0.1` 또는 `::1`에만 bind되는지, `privileged: true`나 `network_mode`가
없는지를 확인한다. egress-blocked network는 `internal: true`이거나, Docker bridge에서
`com.docker.network.bridge.enable_ip_masquerade: "false"`를 설정한 network다. 후자는
Docker Desktop에서 loopback ingress를 유지하면서 runtime outbound NAT를 막기 위한 호환
구성이다. 하나라도 어기면 readiness는 false다.
