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
