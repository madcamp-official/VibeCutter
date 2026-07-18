"""model.serving 단위 테스트 (GPU/네트워크 불필요, 주입식 목으로 검증).

실행: python -m model.test_serving
"""

from __future__ import annotations

from contracts.schemas import Candidate
from model.serving import (
    _candidate_brief,
    _parse_rerank_order,
    build_rerank_messages,
    make_embed_fn,
    make_rerank_fn,
)


def _c(cid: str, conf: float, vclass: str = "injection") -> Candidate:
    return Candidate(
        id=cid, run_id="r", confidence=conf, vuln_class=vclass,
        cwe="CWE-89", source_symbols=[f"{cid}.py:1"], signals=[f"focus:{vclass}", "severity:ERROR"],
    )


def test_parse_rerank_order_recovers_permutation() -> None:
    assert _parse_rerank_order("2, 0, 1", 3) == [2, 0, 1]
    # 여분/중복/범위밖은 정리하고 빠진 인덱스는 뒤에 붙여 유효 순열 보장
    assert _parse_rerank_order("2 2 9 -1 0", 3) == [2, 0, 1]
    assert _parse_rerank_order("garbage", 3) == [0, 1, 2]      # 못 뽑으면 항등
    assert _parse_rerank_order("rank: [1] then [0]", 2) == [1, 0]


def test_brief_has_no_secret_only_meta() -> None:
    b = _candidate_brief(_c("a", 0.8), 0)
    assert b.startswith("[0]") and "class=injection" in b and "CWE-89" in b


def test_build_rerank_messages_lists_all_indices() -> None:
    msgs = build_rerank_messages([_c("a", 0.8), _c("b", 0.5)])
    assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
    assert "[0]" in msgs[1]["content"] and "[1]" in msgs[1]["content"]


def test_rerank_fn_reorders_by_model_output() -> None:
    cands = [_c("a", 0.8), _c("b", 0.5), _c("c", 0.9)]

    # 목 모델: 항상 "1,2,0" 이라고 답한다.
    rerank = make_rerank_fn(lambda messages: "1, 2, 0")
    out = rerank(cands)
    assert [c.id for c in out] == ["b", "c", "a"]


def test_rerank_fn_nondestructive_on_error() -> None:
    def boom(messages):
        raise RuntimeError("endpoint down")

    cands = [_c("a", 0.8), _c("b", 0.5)]
    out = make_rerank_fn(boom)(cands)
    assert [c.id for c in out] == ["a", "b"]      # 원본 순서 유지, 후보 손실 없음


def test_rerank_fn_single_or_empty_noops() -> None:
    assert make_rerank_fn(lambda m: "0")([]) == []
    one = [_c("a", 0.8)]
    assert make_rerank_fn(lambda m: "0")(one) == one


def test_rerank_fn_caps_and_appends_tail() -> None:
    cands = [_c(str(i), 0.5) for i in range(5)]
    # 상위 3개만 LLM 에 보내고 "2,1,0" 재정렬, 나머지(3,4)는 뒤에 그대로.
    rerank = make_rerank_fn(lambda m: "2,1,0", max_candidates=3)
    out = rerank(cands)
    assert [c.id for c in out] == ["2", "1", "0", "3", "4"]


def test_embed_fn_delegates() -> None:
    calls = []

    def fake_embed(texts):
        calls.append(list(texts))
        return [[float(len(t))] for t in texts]

    embed = make_embed_fn(fake_embed)
    vecs = embed(["ab", "cde"])
    assert vecs == [[2.0], [3.0]] and calls == [["ab", "cde"]]


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
