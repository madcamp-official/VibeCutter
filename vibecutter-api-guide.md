# Qwen3-235B API 사용 가이드 (Vibe Cutter 팀 전달용)

## 기본 정보

```
Endpoint:  https://organizer-naturally-ann-viewers.trycloudflare.com/v1/chat/completions
Health:    https://organizer-naturally-ann-viewers.trycloudflare.com/health   (인증 불필요)
Model ID:  qwen3-235b
인증:      Authorization: Bearer <partner-team 키>
호환:      OpenAI Chat Completions API (streaming 지원)
```

> **키 값**: camp-73에서 `cat /root/api_keys.txt` 실행 시 나오는 두 줄 중 `partner-team`이 붙은 줄의 키를 사용하세요. (`our-team` 키는 저희 전용이니 넘기지 마세요.)

> **터널 안정성**: 이 URL은 임시 터널(Cloudflare Quick Tunnel)이라 서버 쪽에서 재시작하면 바뀔 수 있습니다. 안 되면 저희에게 새 URL을 요청하세요.

---

## 1) 헬스체크 (제일 먼저 확인)

```bash
curl https://organizer-naturally-ann-viewers.trycloudflare.com/health
```

정상이면:
```json
{"proxy":"ok","upstream":200}
```

---

## 2) 기본 호출 (curl)

```bash
curl https://organizer-naturally-ann-viewers.trycloudflare.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <partner-team 키>" \
  -d '{
    "model": "qwen3-235b",
    "messages": [
      {"role": "user", "content": "이 취약점을 어떻게 재현하는지 설명해줘: SQL Injection in login form"}
    ],
    "max_tokens": 1000
  }'
```

---

## 3) Python — OpenAI SDK 그대로 사용 가능

`base_url`만 바꾸면 기존 OpenAI 클라이언트 코드가 그대로 동작합니다.

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://organizer-naturally-ann-viewers.trycloudflare.com/v1",
    api_key="<partner-team 키>",
)

resp = client.chat.completions.create(
    model="qwen3-235b",
    messages=[{"role": "user", "content": "이 코드의 IDOR 취약점을 찾아줘"}],
    max_tokens=1000,
    timeout=600,  # 속도가 느려서(7~8 tok/s) 넉넉하게
)
print(resp.choices[0].message.content)
```

---

## 4) 스트리밍 (실시간 출력, 권장)

응답이 완성될 때까지 기다리지 않고 토큰이 나오는 대로 받고 싶으면:

```python
stream = client.chat.completions.create(
    model="qwen3-235b",
    messages=[{"role": "user", "content": "..."}],
    max_tokens=1000,
    stream=True,
)
for chunk in stream:
    delta = chunk.choices[0].delta.content
    if delta:
        print(delta, end="", flush=True)
```

---

## 5) 여러 턴 대화 (대화 맥락 유지)

`messages` 배열에 이전 대화를 계속 쌓아서 보내면 됩니다.

```python
messages = [{"role": "user", "content": "1번째 질문"}]
r1 = client.chat.completions.create(model="qwen3-235b", messages=messages)
messages.append({"role": "assistant", "content": r1.choices[0].message.content})
messages.append({"role": "user", "content": "이어지는 질문"})
r2 = client.chat.completions.create(model="qwen3-235b", messages=messages)
```

---

## 알아둘 것

| 항목 | 값 |
|---|---|
| **속도** | 약 7~8 tok/s — 긴 답변은 1~2분 걸릴 수 있음. `timeout=600` 권장 |
| **동시 요청 제한** | 현재 미설정 (자유 사용 가능하나, 과도한 동시 호출 시 협의 필요) |
| **재시도 정책** | 5xx 에러 시 지수 백오프(1s→2s→4s) 권장, 401은 키 확인 |
| **URL 안정성** | 임시 터널이라 서버 쪽에서 재시작하면 URL이 바뀔 수 있음 |
| **로깅** | 모든 요청/응답이 서버 측에 기록됩니다 (품질 개선/학습 데이터 목적) |
