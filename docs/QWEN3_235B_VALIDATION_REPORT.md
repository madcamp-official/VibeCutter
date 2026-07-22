# Qwen3-235B 실전 연동 검증 보고서 — VibeCutter

> Validation Report · Patch Synthesis

## Qwen3-235B, 실전 파이프라인에서 검증했습니다

연결해주신 235B 엔드포인트를 VibeCutter의 취약점 자동 수정 파이프라인에 실제로 물려서, 서로 다른 언어·프레임워크의 실제 코드베이스 3곳에서 발견→검증→패치 합성→6단계 결정론적 게이트 검증까지 끝까지 돌려봤습니다. 이 문서는 그 결과 기록입니다.

- **모델**: qwen3-235b
- **역할**: 패치 합성 전용 (판정은 항상 결정론 게이트)
- **기간**: 2026-07-22
- **작성**: P1

## 요약 지표

| 지표 | 값 |
|---|---|
| 실앱 케이스 최종 FIXED | 3 / 3 |
| 취약점 유형 | 2 (CWE-89 SQLi · CWE-79 XSS) |
| 서로 다른 스택 | 3 (Node·Angular·Python) |

셋 다 진짜 취약점입니다 — 만들어낸 게 아니라 실제 요청을 보내 응답 차이·스크립트 실행을 직접 관찰해 확인(verified)한 뒤에만 235B에게 패치를 맡겼습니다. 235B는 **코드를 어떻게 고칠지 제안만** 하고, 그 제안이 실제로 안전하고 정상 동작하는지는 이 모델과 무관한 6단계 게이트(빌드·공격 재현·정상 기능·회귀·정적분석·범위)가 독립적으로 재확인합니다 — 아래 사례마다 그 6게이트 결과를 그대로 실었습니다.

---

## 사례 1 — SQL 인젝션, Juice Shop

**● FIXED**

`OWASP Juice Shop` · `routes/search.ts` (Node.js + Sequelize) · CWE-89 · run `run-4ce5d5400775`

검색 API(`/rest/products/search?q=`)가 사용자 입력을 SQL 문자열에 그대로 이어붙이고 있었습니다. 불리언 참/거짓 페이로드로 응답 길이가 13,609바이트 차이 나는 것을 실측해 확인. 235B에게 첫 시도를 맡겼습니다.

### 시도 1 — 문법이 SQLite와 안 맞음

`routes/search.ts`

```diff
@@ searchProducts() @@
- name LIKE '%${criteria}%' OR description LIKE '%${criteria}%'
+ name LIKE '%' + :criteria + '%' OR description LIKE '%' + :criteria + '%'
```

게이트: build ✅ · attack ✅ · positive ✅ · regression ❌ · static ✅ · scope ✅ → **RETRY**

**왜 걸렸나** — SQLite에서 `+`는 문자열 결합이 아니라 산술 연산입니다. Node/T-SQL 계열 문법 습관이 섞여 `LIKE 0`으로 평가돼 검색 자체가 먹통이 됐고, 회귀 게이트(정상 검색 스모크 테스트)가 정확히 이걸 잡아냈습니다.

### 시도 2 — 재시도에서 스스로 수정

`routes/search.ts`

```diff
@@ searchProducts() @@
- name LIKE '%${criteria}%' OR description LIKE '%${criteria}%'
+ name LIKE :criteria OR description LIKE :criteria
  // criteria = `%${originalQuery}%` 를 JS에서 먼저 완성한 뒤 바인딩
```

게이트: build ✅ · attack ✅ · positive ✅ · regression ✅ · static ✅ · scope ✅ → **FIXED**

SQL에서 문자열을 결합하는 대신, **와일드카드를 JS 쪽에서 미리 완성해** 바인딩하는 방식으로 접근을 바꿨습니다 — 같은 결함을 다른 전략으로 다시 풀어낸 것으로, 근본 원인(파라미터 미바인딩)을 정확히 이해하고 있었다는 신호로 읽었습니다.

---

## 사례 2 — 반사 XSS, Juice Shop

**● FIXED**

`OWASP Juice Shop` · `search-result.component.ts` (Angular) · CWE-79 · run `run-92fbb4bcd13c`

검색어가 Angular `DomSanitizer.bypassSecurityTrustHtml()`로 살균 없이 그대로 렌더링되고 있었습니다. 격리 브라우저에서 실제로 `<img onerror=...>` 페이로드가 실행되는 것까지 관찰해 확인한 뒤 패치를 맡겼습니다.

### 수정 내용 — 살균 우회 자체를 제거

`search-result.component.ts`

```diff
@@ filterTable() @@
- this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
+ this.searchValue = queryParam
```

게이트: build ✅ · attack ✅ · positive ✅ · regression ✅ · static ✅ · scope ✅ → **FIXED**

**수정 판단이 정확했습니다** — "살균을 강화"하는 대신 애초에 살균을 우회하는 호출 자체를 걷어내 Angular 기본 sanitizer가 다시 작동하게 두는, 가장 근본적인 해법을 골랐습니다. 같은 파일에 있던 무관한 다른 코드(상품 설명 렌더링)는 건드리지 않았습니다.

---

## 사례 3 — SQL 인젝션, 임의 사용자 프로젝트

**● FIXED**

데모 앱(Flask + SQLite, VibeCutter와 무관한 신규 프로젝트) · `app.py` · CWE-89 · run `run-2907a2028fa4`

Juice Shop처럼 이미 알려진 타깃이 아니라, 이번 검증을 위해 새로 만든 메모 검색 앱입니다 — 235B가 처음 보는 코드에서도 근본 원인을 정확히 짚는지 보려는 의도였습니다.

### 수정 내용 — 처음부터 정확한 파라미터 바인딩

`app.py`

```diff
@@ search_notes() @@
- query = f"SELECT id, title, body FROM notes WHERE title LIKE '%{q}%' OR body LIKE '%{q}%'"
- rows = conn.execute(query).fetchall()
+ query = "SELECT id, title, body FROM notes WHERE title LIKE ? OR body LIKE ?"
+ rows = conn.execute(query, (f'%{q}%', f'%{q}%')).fetchall()
```

게이트: build ✅ · attack ✅ · positive ✅ · regression ✅ · static ✅ · scope ✅ → **FIXED**

SQLite 표준 `?` placeholder를 정확히 사용했고, 와일드카드 `%`를 파이썬 쪽에서 미리 계산해 바인딩값에 넣는 방식까지 — 사례 1의 시도 2에서 보인 것과 **같은 패턴**을 처음부터 적용했습니다. (이 케이스에서 한 번의 재시도가 있었지만 원인은 VibeCutter 자체의 포트/경로 처리 버그였고, 235B가 낸 수정 내용은 재시도 전후로 완전히 동일했습니다 — 아래 관찰 사항 참고.)

---

## 관찰 사항 — 정직하게 남깁니다

운영에 지장을 준 건 아니지만, 실제로 마주친 두 가지는 숨기지 않고 적습니다.

### 해결됨 · 파이프라인 쪽에서 흡수 — diff hunk header의 줄 수 계산이 가끔 틀립니다

사례 2의 정확한 대상을 찾아낸 이후, 같은 finding에 대해 **두 번 연속** `@@ -156,7 +156,7 @@`로 헤더를 냈는데 실제 본문은 5줄이었습니다(수정 내용 자체는 두 번 다 정확했습니다). git이 이 불일치를 "corrupt patch"로 통째로 거부해서 적용 자체가 안 됐고, 재시도에서도 모델이 스스로 고치지 못했습니다 — 결국 저희 쪽(`repair/llm_synth.py`)에 본문을 실제로 세어 헤더를 재계산하는 보정 로직을 추가해 해결했습니다. 이후로는 모델이 어떤 헤더를 내든 항상 올바르게 적용됩니다.

### 모델과 무관 · VibeCutter 인프라 버그 — 사례 3의 재시도는 저희 쪽 버그였습니다

임의 사용자 프로젝트 지원 경로가 이번에 처음 실전 실행됐는데, 패치 적용 후 원본 인스턴스를 내리고 패치된 버전을 같은 포트에 다시 띄우는 로직이 "VibeCutter 자체 경로" 기준으로만 짜여 있어서 사용자의 실제 프로젝트 경로를 못 찾았습니다. 235B가 낸 패치 내용은 이 버그와 무관하게 처음부터 끝까지 동일했습니다 — 저희 쪽 3개 파일을 고친 뒤 같은 패치로 바로 FIXED까지 갔습니다.

---

## 결론

**판정에는 절대 관여하지 않고, 제안만 하는 자리에서 — 235B는 신뢰할 만합니다.**

세 사례 모두 서로 다른 언어·프레임워크·근본 원인이었는데, 235B는 매번 "무엇을 고쳐야 하는가"를 정확히 짚었고, 최소한의 변경으로 접근했으며, 무관한 코드는 건드리지 않았습니다. 한 번 잘못된 접근(사례 1의 SQL 문법)은 재시도에서 스스로 더 나은 전략으로 바꿔 왔습니다. 실제로 안전과 무관하게 저희가 자체적으로 고친 두 가지 마찰(헤더 계산·인프라 경로 버그)을 빼면, 지금 이대로 primary tier에 계속 두는 데 문제가 없다고 판단합니다. 연결해주셔서 감사합니다 — 계속 이 엔드포인트로 갑니다.

---

*VibeCutter · 판정은 항상 결정론적 6게이트(build/attack/positive/regression/static/scope)가 독립적으로 내립니다 — 이 문서에 나온 어떤 verdict도 LLM 자체 판단이 아닙니다.*
