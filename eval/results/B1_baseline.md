# B1 (Semgrep-only) Baseline — 실측 결과

> P4 / Model·Eval. 정적분석(SAST) 단독 성능의 기준선.
> 이 숫자가 이후 **full closed-loop 시스템**과 **fine-tuned 모델**을 비교하는 좌측 기준(base)이 된다.

## 방법 (재현 가능)

- **대상**: `datasets/inventory_benchmark.yaml` 의 공개 취약앱 16개(15 양성 + c2-05 음성 정답).
- **스캐너**: Semgrep 1.90.0, 룰셋 `p/default`(큐레이트 기본셋). WSL/Linux/Python 3.13.
- **파이프라인**: shallow clone → `scanners.sast.run_semgrep` → `scanners.aggregate` →
  `eval.baseline.evaluate`(앱×3군 셀 단위 confusion).
- **정답**: `expected_vulns` → 3군{idor,xss,injection} 매핑(`vuln_tokens_to_focus`).
- **한계**: 앱×군 셀 단위(라인 단위 아님). expected_vulns 는 문헌 기반 coarse label(12.5절).

재현:
```bash
source .venv/bin/activate    # semgrep 이 PATH 에 있어야 함(3.13)
# 벤치마크 앱 배치 스캔 후:
python -m eval.run_baseline --candidates <candidates_dir> --label B1
```

## 결과

```
apps=16  cells=48 (앱×3군)
              P     R(TPR)  FPR    F1   TPR-FPR   (TP/FP/FN/TN)
------------------------------------------------------------------
overall     0.84   0.41   0.33   0.55   0.08    16/3/23/6
idor        0.00   0.00   0.00   0.00   0.00     0/0/13/3
injection   0.93   0.87   1.00   0.90  -0.13    13/1/2/0
xss         0.60   0.27   0.40   0.37  -0.13     3/2/8/3
```

### 핵심 발견

1. **SAST 는 IDOR 를 하나도 못 잡는다 — 0/13.** IDOR 있는 13개 앱 전부 미탐(FN).
   정적분석은 인가(authz) 로직을 이해 못 하는 근본적 한계. **동적 verifier 가 필요한 이유.**
2. **injection = SAST 강점** (P 0.93 / R 0.87). 15개 중 13개 정확. nodegoat·vampi 만
   미탐(NoSQL injection 은 기본 룰이 약함).
3. **XSS = 절반 이하** (R 0.27). juice-shop·crapi·dvna·mutillidae·vulnerable-node 만 탐지.
4. **음성 샘플 c2-05 에서 오탐(FP)** — P3 가 "완전 clean" 판정한 앱인데 Semgrep 이
   injection 후보를 냄. raw SAST 는 clean 앱도 과탐한다는 증거. closed-loop 은 이를 동적
   재현→실패→reject 로 걸러 precision 을 올린다(이 baseline 대비 개선 지점).

### 앱별 (예측 3군 vs 정답)

| 앱 | Semgrep 예측 | 정답 | 미탐(FN) |
| --- | --- | --- | --- |
| juice-shop | injection, xss | idor, injection, xss | idor |
| nodegoat | — | injection, xss | injection, xss |
| dvna | injection, xss | idor, injection, xss | idor |
| vulnerable-node | injection, xss | idor, injection | idor |
| dvga | injection | idor, injection | idor |
| vampi | — | idor, injection | idor, injection |
| tiredful-api | injection | idor, injection, xss | idor, xss |
| dvpwa | injection | injection, xss | xss |
| dsvw | injection | idor, injection, xss | idor, xss |
| webgoat | injection | idor, injection, xss | idor, xss |
| java-sec-code | injection | idor, injection, xss | idor, xss |
| crapi | injection, xss | idor, injection | idor |
| dvwa | injection | idor, injection, xss | idor, xss |
| bwapp | injection | idor, injection, xss | idor, xss |
| mutillidae | injection, xss | idor, injection, xss | idor |
| **26s-w1-c2-05** | **injection (FP)** | **— (음성)** | — |

원시 candidate 수(참고): webgoat 207, crapi 210, java-sec-code 101, mutillidae 81,
juice-shop 80, dvwa 84, bwapp 59, vulnerable-node 46, dvga 40, nodegoat 37,
tiredful-api 24, dvna 23, dsvw 10, dvpwa 9, vampi 8, c2-05 7. (총 candidate ≫ 3군 매핑 수
= 많은 findings 가 3군 밖 CWE 라 미매핑 — 정적분석 노이즈의 실체.)

## 주의 (정직한 한계)

- `injection FPR=1.00` 은 **표본 아티팩트** — 벤치마크 대부분이 injection 양성이라 injection
  음성(TN)이 0. 분모가 (FP+TN)=(1+0)이라 1.0 이 됨. FPR 은 음성 표본이 늘어야 안정된다.
- **음성 표본이 c2-05 1개뿐** — precision/FPR 통계력 약함. P3 가 추가 clean 앱을 판정하면 보강.
- B1 은 **정적(SAST)만**. B2(ZAP 동적)는 앱이 실제로 떠야 해서 P2 runtime 필요(미측정).
