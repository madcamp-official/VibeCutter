#!/usr/bin/env python3
"""Discord <-> local Claude Code relay (REST polling, stdlib only).

Lets teammates' Claude Code sessions talk to each other over a shared
Discord channel. Each teammate runs `listen` with their own bot token
in their own project directory; when someone @-mentions their bot,
it invokes headless `claude -p` locally and posts the reply back.
`send` is a one-shot way to kick off a question.

Only messages that @-mention *this* bot trigger a reply. That is what
keeps several always-on bots in the same channel from replying to each
other forever, and it is also the "who is this addressed to" signal --
without it, a shared channel with N auto-reply bots would either all
fire on every message or need a shared token (which makes "is this my
own message" ambiguous).

Setup (per teammate, ~2 minutes):
  1. https://discord.com/developers/applications -> New Application
     (name it e.g. "P2-Claude") -> Bot tab -> enable "Message Content
     Intent" -> copy the token.
  2. OAuth2 -> URL Generator -> scope "bot", permissions: View
     Channels, Send Messages, Read Message History. Open the
     generated URL and invite it to the shared server.
  3. Everyone joins the same channel, e.g. #claude-relay. Turn on
     Developer Mode (User Settings -> Advanced), right-click the
     channel -> Copy Channel ID.

Usage:
  DISCORD_BOT_TOKEN=... python tools/discord_relay.py send <channel_id> "@P2-Claude 이 스키마 필드명 맞춰줄래?"
  DISCORD_BOT_TOKEN=... python tools/discord_relay.py listen <channel_id>

Security: whoever can @-mention this bot in that channel can make this
Claude run tools (edit files, shell commands, hit targets) in this
project -- keep the channel restricted to the team. Headless
`claude -p` can't show interactive permission prompts; pass extra
flags via CLAUDE_EXTRA_ARGS (e.g. to rely on a .claude/settings.json
allowlist) rather than defaulting to --dangerously-skip-permissions.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://discord.com/api/v10"

CLAUDE_BIN = os.environ.get("CLAUDE_BIN", "claude")
CLAUDE_EXTRA_ARGS = os.environ.get("CLAUDE_EXTRA_ARGS", "").split()
CLAUDE_TIMEOUT_SECONDS = int(os.environ.get("CLAUDE_TIMEOUT_SECONDS", "600"))
PROJECT_DIR = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
SENDER_LABEL = os.environ.get("DISCORD_SENDER_LABEL", "")
POLL_INTERVAL_SECONDS = float(os.environ.get("DISCORD_POLL_INTERVAL_SECONDS", "5"))
MAX_CONTENT_CHARS = 2000

NO_RE_MENTION_HINT = (
    "\n\n(디스코드 팀 채널에서 온 메시지에 답하는 중이다. 새로 질문/요청할 대상이 "
    "있을 때만 그 사람을 @멘션하고, 단순 답장 끝에 습관적으로 다시 멘션하지 마라 "
    "-- 서로 멘션을 주고받으면 봇들이 끝없이 응답하게 된다.)"
)


def _api(token: str, method: str, path: str, body: dict | None = None) -> dict | list:
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://github.com/vibe-cutter, 1.0)",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"discord API {method} {path} -> {exc.code}: {exc.read().decode()}") from exc


def get_self(token: str) -> dict:
    return _api(token, "GET", "/users/@me")  # type: ignore[return-value]


def fetch_recent(token: str, channel_id: str, limit: int = 20) -> list[dict]:
    return _api(token, "GET", f"/channels/{channel_id}/messages?limit={limit}")  # type: ignore[return-value]


def post_message(token: str, channel_id: str, content: str, label: str = "") -> None:
    if label:
        content = f"**{label}** {content}"
    for chunk in _chunks(content):
        _api(token, "POST", f"/channels/{channel_id}/messages", {"content": chunk})


def _chunks(text: str, size: int = MAX_CONTENT_CHARS) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or ["(빈 응답)"]


def run_claude(prompt: str, session_id: str | None) -> tuple[str, str | None]:
    cmd = [CLAUDE_BIN, "-p", prompt + NO_RE_MENTION_HINT, "--output-format", "json", *CLAUDE_EXTRA_ARGS]
    if session_id:
        cmd += ["--resume", session_id]
    result = subprocess_run(cmd)
    if result.returncode != 0:
        return f"(claude 실행 실패, exit={result.returncode})\n```\n{result.stderr[-1500:]}\n```", session_id
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip() or "(빈 응답)", session_id
    new_session_id = data.get("session_id", session_id)
    if data.get("is_error"):
        return f"(claude 오류)\n```\n{str(data.get('result', ''))[:1500]}\n```", new_session_id
    return (data.get("result") or "(빈 응답)"), new_session_id


def subprocess_run(cmd: list[str]):
    import subprocess

    return subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=CLAUDE_TIMEOUT_SECONDS)


def cmd_send(args: argparse.Namespace) -> None:
    post_message(args.token, args.channel_id, args.message, SENDER_LABEL)


def cmd_listen(args: argparse.Namespace) -> None:
    self_user = get_self(args.token)
    self_id = self_user["id"]
    print(f"[discord_relay] logged in as {self_user['username']} ({self_id}), watching channel {args.channel_id}", file=sys.stderr)

    recent = fetch_recent(args.token, args.channel_id, limit=1)
    last_seen_id = int(recent[0]["id"]) if recent else 0
    session_id: str | None = None

    while True:
        try:
            messages = fetch_recent(args.token, args.channel_id, limit=20)
        except RuntimeError as exc:
            print(f"[discord_relay] fetch failed: {exc}", file=sys.stderr)
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        new_messages = sorted(
            (m for m in messages if int(m["id"]) > last_seen_id),
            key=lambda m: int(m["id"]),
        )
        for msg in new_messages:
            last_seen_id = max(last_seen_id, int(msg["id"]))
            if msg["author"]["id"] == self_id:
                continue
            mentioned = any(u["id"] == self_id for u in msg.get("mentions", []))
            if not mentioned:
                continue
            author_name = msg["author"].get("username", "?")
            print(f"[discord_relay] {author_name} mentioned me: {msg['content'][:120]!r}", file=sys.stderr)
            reply, session_id = run_claude(msg["content"], session_id)
            post_message(args.token, args.channel_id, reply, SENDER_LABEL)

        time.sleep(POLL_INTERVAL_SECONDS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--token", default=os.environ.get("DISCORD_BOT_TOKEN"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="post one message and exit")
    p_send.add_argument("channel_id")
    p_send.add_argument("message")
    p_send.set_defaults(func=cmd_send)

    p_listen = sub.add_parser("listen", help="poll forever, reply when @-mentioned")
    p_listen.add_argument("channel_id")
    p_listen.set_defaults(func=cmd_listen)

    args = parser.parse_args()
    if not args.token:
        sys.exit("DISCORD_BOT_TOKEN not set and --token not given")

    args.func(args)


if __name__ == "__main__":
    main()
