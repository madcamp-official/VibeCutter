"""Prepare two isolated WordNote users and private resources for P3 IDOR replay.

The script runs only against the fixed P2 loopback target and writes metadata
under ``.vibecutter/fixtures/`` (which is gitignored). It intentionally does
not print response bodies, credentials, or security verdicts. P3 consumes the
owner/attacker IDs, baseline and attack paths, and the victim-only marker from
the generated JSON when constructing a candidate-specific replay.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4


TARGET_ID = "26s-w1-c2-04"
API_BASE = "http://127.0.0.1:14017"
FIXTURE_PATH = Path(".vibecutter/fixtures/26s-w1-c2-04-idor.json")


def request(method: str, path: str, body: dict[str, object] | None = None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request_obj = urllib.request.Request(f"{API_BASE}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request_obj, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        # A fixture failure must not put target response content into terminal
        # output, audit logs, or later evidence by accident.
        return exc.code, None


def require_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise RuntimeError(f"{label}: expected HTTP {expected}, got {actual}")


def require_mapping(payload: object, label: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label}: expected JSON object")
    return payload


def create_user(username: str, password: str) -> dict[str, object]:
    status, payload = request("POST", "/users/", {"username": username, "password": password})
    require_status(status, 201, "user fixture signup")
    user = require_mapping(payload, "user fixture signup")
    if not isinstance(user.get("id"), int):
        raise RuntimeError("user fixture signup: missing numeric id")
    return user


def create_vocab(owner_id: int, title: str) -> dict[str, object]:
    status, payload = request("POST", "/vocabs/", {"owner_id": owner_id, "title": title})
    require_status(status, 201, "vocabulary fixture create")
    vocab = require_mapping(payload, "vocabulary fixture create")
    if not isinstance(vocab.get("id"), int):
        raise RuntimeError("vocabulary fixture create: missing numeric id")
    return vocab


def create_word(vocab_id: int, marker: str) -> dict[str, object]:
    status, payload = request(
        "POST",
        f"/vocabs/{vocab_id}/words/",
        {"word": marker, "meaning": "fixture-only marker", "examples": "P2/P3 isolated IDOR fixture"},
    )
    require_status(status, 201, "vocabulary fixture word create")
    return require_mapping(payload, "vocabulary fixture word create")


def main() -> None:
    status, _ = request("GET", "/api/data")
    require_status(status, 200, "target health")

    nonce = uuid4().hex[:12]
    # The application does not issue a usable session/token at login. Passwords
    # are therefore needed only for the local creation call and are never
    # persisted in the P3 fixture metadata.
    password = f"p2-local-{nonce}"
    owner = create_user(f"p2owner{nonce}", password)
    attacker = create_user(f"p2attacker{nonce}", password)

    owner_id = int(owner["id"])
    attacker_id = int(attacker["id"])
    victim_marker = f"victim-only-{nonce}"
    attacker_marker = f"attacker-only-{nonce}"
    victim_vocab = create_vocab(owner_id, f"P2 private owner {nonce}")
    attacker_vocab = create_vocab(attacker_id, f"P2 private attacker {nonce}")
    victim_word = create_word(int(victim_vocab["id"]), victim_marker)
    attacker_word = create_word(int(attacker_vocab["id"]), attacker_marker)

    # This is a normal owner-resource read only; P2 does not make the
    # cross-user request or decide whether the target is vulnerable.
    status, owner_words = request("GET", f"/vocabs/{victim_vocab['id']}/words/")
    require_status(status, 200, "owner fixture resource read")
    if victim_marker not in json.dumps(owner_words, ensure_ascii=False):
        raise RuntimeError("owner fixture resource read: victim marker missing")

    metadata = {
        "fixture_version": 1,
        "target_id": TARGET_ID,
        "base_url": API_BASE,
        "reset": {"command_id": "reset", "removes_fixture": True},
        "authentication": {
            "mode": "none",
            "login_path": "/login/",
            "note": "The target login response has no bearer/session credential; requests below use no Authorization header.",
        },
        "roles": {
            "user_a": {"id": owner_id, "username": owner["username"], "fixture": "idor_owner_user_a"},
            "user_b": {"id": attacker_id, "username": attacker["username"], "fixture": "idor_attacker_user_b"},
        },
        "resources": {
            "victim_vocabulary": {
                "id": victim_vocab["id"],
                "owner_role": "user_a",
                "is_public": False,
                "word_id": victim_word.get("id"),
                "victim_marker": victim_marker,
                "read_path": f"/vocabs/{victim_vocab['id']}/words/",
                "safe_mutation": {
                    "method": "PUT",
                    "path": f"/vocabs/{victim_vocab['id']}/description/",
                    "json": {"description": "P3 fixture mutation", "tags": "p2,p3"},
                },
            },
            "attacker_vocabulary": {
                "id": attacker_vocab["id"],
                "owner_role": "user_b",
                "word_id": attacker_word.get("id"),
                "baseline_path": f"/vocabs/{attacker_vocab['id']}/words/",
                "marker": attacker_marker,
            },
        },
    }

    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(FIXTURE_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows ACLs govern the effective access policy. The directory is
        # still gitignored and this fixture contains no password or token.
        pass
    print(f"{TARGET_ID} IDOR fixture prepared at {FIXTURE_PATH.as_posix()}")


if __name__ == "__main__":
    main()
