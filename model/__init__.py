"""RAG 코드 인덱스·모델 서빙·LoRA (P4 소유, 착수 예정).

기획서 근거:
- Code Index: `code_index.py` — BM25 어휘 검색 + 정규식 심볼 그래프(GPU 불필요).
  임베딩 벡터 검색은 `search(..., embed_fn=)` 훅으로 교체(임베딩 모델은 GPU 선택).
- Model Serving: vLLM 또는 llama.cpp local endpoint (7B + 14B 4-bit) — GPU 필요, 미착수.
- Training: Transformers/PEFT/TRL/bitsandbytes, 7B QLoRA — GPU 필요, 미착수.

학습 샘플은 evidence_store 의 verified trajectory(contracts.schemas.Trajectory)를
조인해 만든다(P1 이 Day4 에 JSONL export 제공). Day3~4(밤 배치)에 채운다.
"""
