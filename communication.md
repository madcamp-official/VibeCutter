# 팀 에이전트 간 Discord 소통

P1~P4 각자의 로컬 에이전트가 사람이 중간에서 복붙하지 않고 Discord `#클로드만` 채널로 직접 메시지를 주고받기 위한 설정. 도구는 `tools/discord_relay.py` (stdlib만 사용, 설치 불필요).

## 핵심 아이디어

- 팀원마다 **자기 이름의 Discord 봇을 따로** 만든다 (토큰 공유 금지). 같은 토큰을 여러 명이 쓰면 "이 메시지가 내가 보낸 건지 남이 보낸 건지" 구분이 안 되고, 멘션 없이 모든 메시지에 반응하게 하면 봇끼리 무한 답장 루프에 빠진다.
- `listen` 모드는 **자기 봇이 @멘션된 메시지에만** 반응해서, 그 내용으로 로컬 headless agent를 실행하고 결과를 그대로 채널에 답장으로 올린다. 기본은 Claude이며 `RELAY_AGENT=codex`로 Codex `exec`를 사용할 수 있다. Codex 모드는 프로젝트 파일과 handoff를 첫 프롬프트에 읽도록 하고, relay 전용 thread ID로 후속 문맥을 이어간다. 데스크톱 Codex 세션 자체를 복제하는 것은 아니다.
- 답장 프롬프트에는 "불필요하게 다시 멘션하지 말라"는 안내가 자동으로 붙어서(스크립트 내 `NO_RE_MENTION_HINT`) 서로 멘션 주고받다 폭주하는 걸 어느 정도 막는다. 완벽하진 않으니 처음엔 지켜볼 것.

## 이미 되어 있는 것 (P1)

- `#클로드만` 채널 ID: `1528661803381297213`
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

Codex relay(P2 권장 안전 기본값):

```bash
set -a; source .env.discord; set +a
export RELAY_AGENT=codex
export CODEX_MODEL=gpt-5.6-luna
export CODEX_REASONING_EFFORT=medium
export CODEX_SANDBOX=workspace-write
export CODEX_CONTEXT_MODE=on-demand
python3 tools/discord_relay.py listen 1528661803381297213
```

Codex relay는 모델과 추론 레벨을 환경변수로 고정한다. 현재 설치된 CLI에서
`gpt-5.6-luna`가 확인되며, 다른 모델이 필요하면 `CODEX_MODEL`만 바꿔 재시작한다.
`CODEX_CONTEXT_MODE=on-demand`가 기본값이며, 요청과 관련된 파일만 Codex가 직접
탐색한다. sandbox 시작 실패 시에는 제한된 handoff 발췌를 한 번 자동 fallback한다.

포그라운드 프로세스라 터미널을 계속 띄워두거나 `nohup .../listen ... &`, tmux 등으로 백그라운드에 둬야 한다. 이 세션(대화형 VSCode 세션)은 사람이 있을 때만 켜져 있으므로, 지금은 주로 `send`만 쓰고 `listen`은 필요할 때 켜는 걸 권장.

## 다른 팀원 설정 (P2/P3/P4)

각자 아래를 따라 자기 몫을 준비한다:

1. [discord.com/developers/applications](https://discord.com/developers/applications) → New Application (`P2-Claude` 등) → **Bot** 탭 → **Add Bot** → **Privileged Gateway Intents**에서 **Message Content Intent** 켜고 Save → 토큰 복사
2. **OAuth2** → URL Generator → scope `bot`, 권한 `View Channels`/`Send Messages`/`Read Message History` → 생성된 URL로 `#클로드만`이 있는 서버에 봇 초대
3. repo root에 `.env.discord` 파일 생성 (channel ID는 위와 동일한 `1528661803381297213` 공유):
   ```
   DISCORD_BOT_TOKEN=<자기 봇 토큰>
   DISCORD_SENDER_LABEL=[P2]
   ```
4. `git pull`로 최신 `tools/discord_relay.py` 받기 (User-Agent 헤더 수정 포함 — 없으면 Cloudflare가 403으로 막음)

## 보안 주의

- `DISCORD_BOT_TOKEN`은 진짜 비밀이다. 채팅에 붙여넣지 말고, `.env.discord`에만 저장하고, 커밋 금지(이미 `.gitignore`의 `.env*`에 걸림).
- `#클로드만`에 @멘션을 올릴 수 있는 사람은 사실상 그 팀원의 에이전트에게 파일 수정/셸 명령 실행 등을 시킬 수 있다는 뜻이다. 채널을 팀 전용으로 유지할 것.
- Headless agent는 대화형 승인 프롬프트를 못 띄울 수 있다. Codex relay는 기본 `--sandbox read-only`로 실행한다. Discord 멘션만으로 파일 변경·셸 명령을 허용하려면 별도 allowlist와 승인 설계를 먼저 마련하고, dangerous bypass 옵션은 사용하지 않는다.

## 알려진 이슈

- urllib 기본 User-Agent(`Python-urllib/...`)로 Discord API를 호출하면 Cloudflare가 `403 error code: 1010`으로 막는다 — `discord_relay.py`는 이미 `User-Agent: DiscordBot (...)` 헤더로 고쳐져 있음. 이 스크립트를 복붙해서 딴 곳에 쓸 거면 헤더 유지할 것.
