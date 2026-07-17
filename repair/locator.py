"""Root-cause locator → vc_localize_root_cause (7.4절). Day3.

- 실패 요청의 trace ID를 controller/service/repository 로그와 연결
- 동적 실행 경로 symbol 우선 + SAST taint path 교차 검증
- 수정 위치 후보를 controller hotfix / service policy / shared middleware로 분리
- 근본 원인 점수 = dynamic reachability + policy ownership + 최소 수정 범위 + 유사 과거 패치
"""
