# 정적(GPU-free) 개선 실험 ①②③ — 결과와 결론

> P4 / Model·Eval. B1(Semgrep-only) baseline(`B1_baseline.md`)의 약점 3개를 GPU 없이
> 개선 시도한 실측 기록. **결론: 정적 레버는 IDOR 하나뿐, 나머지는 동적 verify가 답이다.**
> 이 문서는 "어디까지 정적으로 되고, 어디서부터 동적/모델이 필요한가"를 숫자로 못 박는다.

## ① IDOR 후보 소스 — ✅ 큰 성공

**문제**: SAST 는 IDOR 를 0/13 탐지(인가 로직 이해 불가).
**개선**: P3 정적 프리필터(`find_idor_suspects`, id-param 라우트 구조 신호)를 P4 candidate 로
변환(`scanners/surface_idor.py`).
**실측**(`B1_vs_surface_idor.txt`):

| metric | B1(SAST) | +Surface | Δ |
| --- | --- | --- | --- |
| IDOR F1 | 0.00 | **0.60** | **+0.60** |
| IDOR recall | 0.00 | 0.46 (6/13) | +0.46 |
| overall F1 | 0.53 | 0.66 | +0.13 |

**왜 됐나**: IDOR 는 "id 를 받는 라우트"라는 **구조적 정적 신호**가 있다. 트레이드오프로
FPR↑(프리필터가 넓게 던짐) — 이 오탐은 동적 verify 가 회수한다(closed-loop 앞단).
**한계**: 데코레이터/express/Spring 라우팅엔 되지만 스펙기반(Connexion)·Django 엔 0 — 6개 앱만 개선.

## ② XSS recall — ❌ 정적 개선 없음 (정직한 음성)

**문제**: XSS recall 0.27(11개 중 ~3개만).
**시도**: `p/xss` 룰셋 추가.
**실측**: 미탐 앱(dvpwa·tiredful)에서 `p/xss` 는 **findings 0** — 아무것도 추가 못 함.
**진단**: 태깅 버그 0(진짜 CWE-79 는 전부 focus:xss 정확 매핑). 미탐은 **semgrep 커버리지
한계** — PHP(dvwa/bwapp) 약함, Java/JSP·Django 템플릿 XSS 는 코드 룰이 못 잡음.
**결론**: 룰셋/태깅으로 개선 불가. **진짜 레버는 동적 스캔(B2/ZAP)** — P2 runtime 대기.

## ③ injection precision(audit 오탐) — ❌ 안전한 정적 개선 없음

**문제**: clean 앱 c2-05 에 injection 오탐 1건.
**정체**: 전부 `...security.audit.avoid-sqlalchemy-text`(CWE-89) — semgrep **"audit"** 카테고리
= "확정"이 아니라 "검토 요망"(안전한 `text()` 도 flag).
**시도**: audit 룰 candidate 를 FP-reject.
**실측 분석**(저장 candidate 기준): audit 제거 시 —

| 앱 | 효과 |
| --- | --- |
| c2-05(clean) | injection FP 제거 ✓ (audit-only 7건) |
| **dvga**(injection 양성) | injection **TP 소멸** ✗ (audit-only 3건) |
| **dvna**(injection 양성) | injection **TP 소멸** ✗ (audit-only 1건) |

→ **오탐 1개 없애려다 진짜 양성 2개를 잃는다(F1 하락).** c2-05 의 안전한 `text()` 와
dvga/dvna 의 위험한 `text()` 는 **정적으로 구분 불가**.
**결론**: 정적 FP-reject 불가. 구분하려면 **실행해서 재현(동적 verify)** 해야 한다.

## 종합 결론 — 이 프로젝트의 논지 그 자체

```
약점            정적 개선 가능?    레버
IDOR            ✅ 예            정적 attack-surface 프리필터 (구조 신호 존재)
XSS recall      ❌ 아니오        동적 스캔(B2/ZAP) — semgrep 커버리지 한계
injection FP    ❌ 아니오        동적 verify — audit TP/FP 정적 구분 불가
```

**정적 분석은 IDOR 후보 발굴 하나에서 크게 이기고, 그 다음 벽에 부딪힌다 — 그 벽 너머가
동적 verify + 모델(LLM rerank·LoRA)의 몫이다.** ①이 정적으로 짜낼 수 있는 이득을 실증했고,
②③이 "왜 동적/모델이 필요한가"를 실측으로 증명한다. 이 세 결과가 closed-loop 설계의 근거다.

## 다음(블로커 해제 시)
- **B2(ZAP 동적)**: XSS recall 회복 — P2 runtime 필요.
- **동적 verify**: ①의 IDOR 오탐 회수 + ③의 audit FP 판별 — P3 verifier + evidence.
- **LLM rerank**(`model/serving.py`): 오탐 강등으로 precision↑ — GPU 필요.
