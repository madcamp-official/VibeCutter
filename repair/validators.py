"""Attack gate / Positive functionality gate 실행기 (7.6절). Day3.

P1의 judge(core/judge.py)가 호출하는 실행기. 6개 게이트 중 P3가 실물을 제공하는 것:
- Attack gate: 기존 재현 시퀀스가 더 이상 보안 영향을 만들지 않음 (verifier 재사용)
- Positive functionality gate: 정상 권한 사용자의 원래 기능 성공

나머지 4개(Build/Regression/Static/Scope)는 P1 배선 + P2 test runner / P4 Semgrep.
"""
