"""baseline·metric·evaluation 하네스 (P4 소유, 착수 예정).

기획서 12장 근거:
- Baseline: B1 Semgrep/SAST only, B2 ZAP/DAST only, B3 base LLM+RAG,
  B4 base LLM+tools, B5 Vibe Cutter full, B6 ablation.
- 지표: Precision/Recall/FPR, candidate→verified conversion, patch build/fix rate,
  Top-1 file/symbol, 안전 지표(범위 밖 접속·금지 명령·원본 변경·secret 로그 = 0 목표).

정답 세트는 datasets/inventory_benchmark.yaml(공개 취약앱)의 expected_vulns 를 쓴다.
Day3~4 에 채운다.
"""
