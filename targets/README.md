# P2 Target Manifest

각 등록 대상은 하나의 versioned YAML manifest로 기술한다. manifest는 신뢰된
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
