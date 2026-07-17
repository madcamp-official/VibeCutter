"""model.code_index 단위 테스트. 실행: python -m model.test_code_index"""

from __future__ import annotations

from pathlib import Path

from model.code_index import CodeIndex, tokenize

REPO = Path(__file__).with_name("testdata") / "sample_repo"


def _index() -> CodeIndex:
    return CodeIndex.build(REPO)


def test_tokenize_splits_identifiers() -> None:
    toks = set(tokenize("getUserById user_id"))
    assert {"get", "user", "by", "id"} <= toks       # camelCase 분해
    assert {"getuserbyid", "user", "id"} <= toks      # snake_case 분해 + 원형


def test_build_collects_chunks_and_symbols() -> None:
    idx = _index()
    assert idx.chunks, "chunk 가 있어야 함"
    files = {c.file for c in idx.chunks}
    assert any(f.endswith("users.py") for f in files)
    assert any(f.endswith("profile.js") for f in files)


def test_symbols_extracted_per_language() -> None:
    idx = _index()
    names = {s.name for s in idx.symbols}
    assert "get_user_by_id" in names       # python def
    assert "UserRepository" in names        # python class
    assert "renderProfile" in names         # js function
    assert "listOrders" in names            # js arrow const


def test_search_finds_sql_injection_site() -> None:
    idx = _index()
    hits = idx.search("sql query user id", k=3)
    assert hits, "검색 결과가 있어야 함"
    assert hits[0].chunk.file.endswith("users.py")


def test_search_finds_xss_site() -> None:
    idx = _index()
    hits = idx.search("render html response name", k=3)
    assert hits
    assert hits[0].chunk.file.endswith("profile.js")


def test_find_symbol_partial_case_insensitive() -> None:
    idx = _index()
    hits = idx.find_symbol("user")
    got = {s.name for s in hits}
    assert "get_user_by_id" in got and "UserRepository" in got


def test_search_supports_embed_fn_hook() -> None:
    idx = _index()
    # 더미 임베딩: 토큰 집합 겹침 기반 2차원 벡터(훅 배선만 검증).
    def embed(texts):
        vocab = ["sql", "user", "render", "html"]
        out = []
        for t in texts:
            toks = set(tokenize(t))
            out.append([1.0 if v in toks else 0.0 for v in vocab])
        return out
    hits = idx.search("sql user", k=2, embed_fn=embed)
    assert hits and hits[0].score >= hits[-1].score


def test_missing_root_raises() -> None:
    try:
        CodeIndex.build("/no/such/repo/xyz")
    except FileNotFoundError:
        return
    raise AssertionError("없는 root 는 FileNotFoundError")


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
