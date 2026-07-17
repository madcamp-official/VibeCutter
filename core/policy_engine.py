"""Policy engine v1: target allowlist + command_id/typed-args 검증.

"등록된 target_id와 manifest에서 허용된 범위만 사용한다. 임의 URL/IP/shell 문자열을 공통
도구 입력으로 받지 않는다. 명령은 command_id + typed arguments로 제한한다"
(cowork_rule.md 4절 공통 안전 규칙)를 코드로 강제한다.

거부는 항상 `PolicyViolation` 예외로 표현한다. 이 모듈 자체는 로깅하지 않는다 — 호출자
(MCP tool 배선, Day2~)가 이 예외를 잡아 audit log(item 10)에 남긴다.

target 허용 목록은 `policies/scope.yaml`, 실행 가능한 command_id는
`policies/commands.yaml`이 정의한다. 두 파일 다 사람이 직접 편집하는 정책 소스이며,
이 모듈은 정책을 읽고 강제하기만 한다 — 정책 값 자체를 코드에 하드코딩하지 않는다.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"
_DEFAULT_SCOPE_PATH = _POLICIES_DIR / "scope.yaml"
_DEFAULT_COMMANDS_PATH = _POLICIES_DIR / "commands.yaml"

_ARG_TYPES: dict[str, type] = {"str": str, "int": int, "float": float, "bool": bool}


class PolicyViolation(PermissionError):
    """target allowlist 또는 command policy를 위반했을 때 발생한다."""


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def load_scope(path: Path = _DEFAULT_SCOPE_PATH) -> dict[str, dict]:
    """`policies/scope.yaml`의 targets 맵. `{target_id: {allowed_hosts: [...], ...}}`."""
    return _load_yaml(path).get("targets") or {}


def load_commands(path: Path = _DEFAULT_COMMANDS_PATH) -> dict[str, dict]:
    """`policies/commands.yaml`의 commands 맵. `{command_id: {args: {name: type}}}`."""
    return _load_yaml(path).get("commands") or {}


def is_target_allowed(target_id: str, *, path: Path = _DEFAULT_SCOPE_PATH) -> bool:
    return target_id in load_scope(path)


def require_target_allowed(target_id: str, *, path: Path = _DEFAULT_SCOPE_PATH) -> dict:
    """등록되지 않은 target_id는 무조건 거부한다 (Definition of Done: 미등록 target_id 전부 거부)."""
    scope = load_scope(path)
    if target_id not in scope:
        raise PolicyViolation(
            f"target_id={target_id!r}는 policies/scope.yaml에 등록되지 않았습니다"
        )
    return scope[target_id]


def _extract_host(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or url_or_host
    if url_or_host.startswith("[") or url_or_host.count(":") > 1:
        # bare "host:port" 형태만 지원한다(기획서 전체가 127.0.0.1만 다룸). IPv6는
        # 콜론이 여러 개라 naive split(":")[0]으로는 조용히 잘못 파싱된다 — 지원하지
        # 않는 형태는 조용히 틀리게 처리하는 대신 명확히 거부한다.
        raise PolicyViolation(f"IPv6로 보이는 host는 아직 지원하지 않습니다: {url_or_host!r}")
    return url_or_host.split(":")[0]


def require_host_allowed(
    target_id: str, url_or_host: str, *, path: Path = _DEFAULT_SCOPE_PATH
) -> None:
    """target의 allowed_hosts 밖의 URL/IP는 전부 거부한다. 임의 네트워크 목적지 구성을 막는 게이트."""
    entry = require_target_allowed(target_id, path=path)
    allowed_hosts = entry.get("allowed_hosts") or []
    host = _extract_host(url_or_host)
    if host not in allowed_hosts:
        raise PolicyViolation(
            f"host={host!r} (target_id={target_id!r})는 allowed_hosts={allowed_hosts}에 없습니다"
        )


def require_valid_command(
    command_id: str, args: dict, *, path: Path = _DEFAULT_COMMANDS_PATH
) -> None:
    """command_id + typed args만 허용한다. shell 문자열을 직접 받지 않는다 (6.7절/10.2절).

    - command_id가 policies/commands.yaml에 없으면 거부.
    - args에 정의되지 않은 키가 있으면 거부.
    - 정의된 키가 빠졌거나 타입이 안 맞으면 거부.
    """
    commands = load_commands(path)
    if command_id not in commands:
        raise PolicyViolation(
            f"command_id={command_id!r}는 policies/commands.yaml에 등록되지 않았습니다"
        )

    schema: dict[str, str] = commands[command_id].get("args") or {}
    unknown = set(args) - set(schema)
    if unknown:
        raise PolicyViolation(f"command_id={command_id!r}: 정의되지 않은 인자 {unknown}")

    for name, type_name in schema.items():
        if name not in args:
            raise PolicyViolation(f"command_id={command_id!r}: 필수 인자 {name!r} 누락")
        expected_type = _ARG_TYPES.get(type_name)
        if expected_type is None:
            raise PolicyViolation(
                f"command_id={command_id!r}: 알 수 없는 타입 {type_name!r} (인자 {name!r})"
            )
        if not isinstance(args[name], expected_type):
            raise PolicyViolation(
                f"command_id={command_id!r}: 인자 {name!r}는 {type_name} 타입이어야 합니다"
                f" (받은 값: {args[name]!r})"
            )
