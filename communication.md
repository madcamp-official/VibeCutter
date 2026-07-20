# 팀 Claude 간 Discord 소통

P1~P4 각자의 Claude Code가 사람이 중간에서 복붙하지 않고 Discord `#claude-relay` 채널로 직접 메시지를 주고받기 위한 설정. 도구는 `tools/discord_relay.py` (stdlib만 사용, 설치 불필요).

## 핵심 아이디어

- 팀원마다 **자기 이름의 Discord 봇을 따로** 만든다 (토큰 공유 금지). 같은 토큰을 여러 명이 쓰면 "이 메시지가 내가 보낸 건지 남이 보낸 건지" 구분이 안 되고, 멘션 없이 모든 메시지에 반응하게 하면 봇끼리 무한 답장 루프에 빠진다.
- `listen` 모드는 **자기 봇이 @멘션된 메시지에만** 반응해서, 그 내용으로 로컬 `claude -p`를 헤드리스 실행하고 결과를 그대로 채널에 답장으로 올린다. `--resume`으로 세션이 이어져 하나의 스레드처럼 유지된다.
- 답장 프롬프트에는 "불필요하게 다시 멘션하지 말라"는 안내가 자동으로 붙어서(스크립트 내 `NO_RE_MENTION_HINT`) 서로 멘션 주고받다 폭주하는 걸 어느 정도 막는다. 완벽하진 않으니 처음엔 지켜볼 것.

## 이미 되어 있는 것 (P1)

- `#claude-relay` 채널 ID: `1528661803381297213`
- `.env.discord` (repo root, gitignore 처리됨 — `.env*` 패턴): `DISCORD_BOT_TOKEN`, `DISCORD_SENDER_LABEL=[P1]` 저장돼 있음
- P1 봇으로 테스트 메시지 전송 성공 확인함

## 새 세션에서 메시지 보내는 법

```bash
set -a; source .env.discord; set +a
python3 tools/discord_relay.py send 1528661803381297213 "메시지 내용"
```

`send`는 한 번 쏘고 끝나는 one-shot이다. 상대방 Claude의 응답을 받으려면 그 상대가 자기 봇으로 `listen`을 돌리고 있어야 하고, 메시지 안에 그 사람의 Discord @멘션이 들어가야 한다 (예: `"@P2-Claude 이 스키마 필드명 맞춰줄래?"`).

## 계속 떠서 자동 응답하게 하려면 (listen)

```bash
set -a; source .env.discord; set +a
python3 tools/discord_relay.py listen 1528661803381297213
```

포그라운드 프로세스라 터미널을 계속 띄워두거나 `nohup .../listen ... &`, tmux 등으로 백그라운드에 둬야 한다. 이 세션(대화형 VSCode 세션)은 사람이 있을 때만 켜져 있으므로, 지금은 주로 `send`만 쓰고 `listen`은 필요할 때 켜는 걸 권장.

## 다른 팀원 설정 (P2/P3/P4)

각자 아래를 따라 자기 몫을 준비한다:

1. [discord.com/developers/applications](https://discord.com/developers/applications) → New Application (`P2-Claude` 등) → **Bot** 탭 → **Add Bot** → **Privileged Gateway Intents**에서 **Message Content Intent** 켜고 Save → 토큰 복사
2. **OAuth2** → URL Generator → scope `bot`, 권한 `View Channels`/`Send Messages`/`Read Message History` → 생성된 URL로 `#claude-relay`가 있는 서버에 봇 초대
3. repo root에 `.env.discord` 파일 생성 (channel ID는 위와 동일한 `1528661803381297213` 공유):
   ```
   DISCORD_BOT_TOKEN=<자기 봇 토큰>
   DISCORD_SENDER_LABEL=[P2]
   ```
4. `git pull`로 최신 `tools/discord_relay.py` 받기 (User-Agent 헤더 수정 포함 — 없으면 Cloudflare가 403으로 막음)

## 보안 주의

- `DISCORD_BOT_TOKEN`은 진짜 비밀이다. 채팅에 붙여넣지 말고, `.env.discord`에만 저장하고, 커밋 금지(이미 `.gitignore`의 `.env*`에 걸림).
- `#claude-relay`에 @멘션을 올릴 수 있는 사람은 사실상 그 팀원의 Claude에게 파일 수정/셸 명령 실행 등을 시킬 수 있다는 뜻이다. 채널을 팀 전용으로 유지할 것.
- Headless `claude -p`는 대화형 승인 프롬프트를 못 띄운다. `CLAUDE_EXTRA_ARGS` 환경변수로 필요한 플래그를 넘기되, `.claude/settings.json` allowlist로 안전한 도구만 허용하는 쪽을 `--dangerously-skip-permissions`보다 우선 고려할 것.

## 알려진 이슈

- urllib 기본 User-Agent(`Python-urllib/...`)로 Discord API를 호출하면 Cloudflare가 `403 error code: 1010`으로 막는다 — `discord_relay.py`는 이미 `User-Agent: DiscordBot (...)` 헤더로 고쳐져 있음. 이 스크립트를 복붙해서 딴 곳에 쓸 거면 헤더 유지할 것.
