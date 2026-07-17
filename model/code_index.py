"""RAG 코드 인덱스 (P4 소유) — 코드 검색 + 심볼 그래프.

기획서 tech stack: tree-sitter, ripgrep, symbol graph, vector store.
이 Day1 스캐폴딩은 **의존성·GPU 없이** 동작하는 것을 우선한다:

- 파일 walk(ripgrep 있으면 사용, 없으면 순수 파이썬).
- 심볼 추출: 언어별 정규식(python/js-ts/java/go). tree-sitter 는 추후 교체 지점.
- 검색: 순수 파이썬 BM25(어휘 기반). identifier 를 camelCase/snake 로 분해해
  코드 검색에 맞춘다.
- 벡터 스토어: `embed_fn` 훅을 주면 코사인 유사도로 대체 가능(임베딩 모델은 GPU
  선택). 기본은 BM25 라 GPU 불필요.

P3 root-cause locator(기획서 7.4절, D11~12)가 endpoint/증상으로 관련 코드 위치를
찾을 때 `CodeIndex.search()` / `.find_symbol()` 를 소비한다.

CLI:
    python -m model.code_index --root <경로> --query "sql query user id"
    python -m model.code_index --root <경로> --symbols
"""

from __future__ import annotations

import argparse
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

# 확장자 → 언어.
LANG_BY_EXT = {
    ".py": "python",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js",
    ".java": "java",
    ".go": "go",
}

# walk 시 건너뛸 디렉터리(vendor/빌드 산출물).
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", "venv", ".venv",
    "__pycache__", "target", "vendor", ".gradle", "coverage", ".idea",
}

# 언어별 심볼 정의 정규식(줄 단위). (심볼종류, 패턴).
SYMBOL_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "python": [
        ("def", re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")),
        ("class", re.compile(r"^\s*class\s+(\w+)")),
    ],
    "js": [
        ("function", re.compile(r"\bfunction\s+(\w+)")),
        ("arrow", re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")),
        ("class", re.compile(r"\bclass\s+(\w+)")),
    ],
    "java": [
        ("class", re.compile(r"\b(?:class|interface|enum)\s+(\w+)")),
        ("method", re.compile(r"\b(?:public|private|protected)\s+[\w<>\[\],\s]+?\s+(\w+)\s*\(")),
    ],
    "go": [
        ("func", re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")),
        ("type", re.compile(r"\btype\s+(\w+)\s+struct")),
    ],
}

_WINDOW = 40         # chunk 당 줄 수
_MAX_LINES = 6000    # 이보다 큰 파일은 스킵(생성물/번들 가능성)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]+|[a-z0-9]+|[A-Z]+")


def tokenize(text: str) -> list[str]:
    """코드 친화 토크나이저: identifier 를 camelCase/snake_case 서브토큰으로 분해."""
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text):
        tokens.append(raw.lower())
        for part in _CAMEL_RE.findall(raw):
            p = part.lower()
            if p and p != raw.lower():
                tokens.append(p)
        for part in raw.split("_"):
            p = part.lower()
            if p and p != raw.lower():
                tokens.append(p)
    return tokens


@dataclass
class Symbol:
    name: str
    kind: str
    file: str
    line: int


@dataclass
class CodeChunk:
    file: str
    language: str
    start_line: int
    end_line: int
    text: str
    symbols: tuple[str, ...] = ()
    tokens: list[str] = field(default_factory=list)


@dataclass
class SearchHit:
    chunk: CodeChunk
    score: float


def _iter_source_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in LANG_BY_EXT:
            yield p


def _extract_symbols(language: str, lines: Sequence[str], file_rel: str) -> list[Symbol]:
    out: list[Symbol] = []
    for i, ln in enumerate(lines, start=1):
        for kind, pat in SYMBOL_PATTERNS.get(language, []):
            m = pat.search(ln)
            if m:
                out.append(Symbol(name=m.group(1), kind=kind, file=file_rel, line=i))
    return out


class CodeIndex:
    """BM25 어휘 검색 + 심볼 그래프. `build()` 로 생성."""

    def __init__(self, chunks: list[CodeChunk], symbols: list[Symbol]) -> None:
        self.chunks = chunks
        self.symbols = symbols
        self._df: Counter[str] = Counter()
        for c in chunks:
            for t in set(c.tokens):
                self._df[t] += 1
        n = len(chunks) or 1
        self._idf = {
            t: math.log((n - df + 0.5) / (df + 0.5) + 1.0) for t, df in self._df.items()
        }
        self._avgdl = (sum(len(c.tokens) for c in chunks) / n) if chunks else 0.0

    @classmethod
    def build(cls, root: Path | str, *, window: int = _WINDOW) -> "CodeIndex":
        root = Path(root)
        if not root.exists():
            raise FileNotFoundError(f"root 없음: {root}")
        chunks: list[CodeChunk] = []
        symbols: list[Symbol] = []
        for path in _iter_source_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            if len(lines) > _MAX_LINES:
                continue
            language = LANG_BY_EXT[path.suffix.lower()]
            rel = str(path.relative_to(root))
            file_syms = _extract_symbols(language, lines, rel)
            symbols.extend(file_syms)
            for start in range(0, max(len(lines), 1), window):
                block = lines[start : start + window]
                if not any(l.strip() for l in block):
                    continue
                lo, hi = start + 1, start + len(block)
                syms = tuple(s.name for s in file_syms if lo <= s.line <= hi)
                body = "\n".join(block)
                chunks.append(
                    CodeChunk(
                        file=rel,
                        language=language,
                        start_line=lo,
                        end_line=hi,
                        text=body,
                        symbols=syms,
                        tokens=tokenize(body),
                    )
                )
        return cls(chunks, symbols)

    def _bm25(self, query_tokens: Sequence[str], chunk: CodeChunk, k1=1.5, b=0.75) -> float:
        if not chunk.tokens:
            return 0.0
        tf = Counter(chunk.tokens)
        dl = len(chunk.tokens)
        score = 0.0
        for t in query_tokens:
            if t not in tf:
                continue
            idf = self._idf.get(t, 0.0)
            f = tf[t]
            score += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * dl / (self._avgdl or 1)))
        return score

    def search(
        self,
        query: str,
        k: int = 5,
        *,
        embed_fn: Optional[Callable[[Sequence[str]], list[Sequence[float]]]] = None,
    ) -> list[SearchHit]:
        """query 로 상위 k chunk. embed_fn 을 주면 임베딩 코사인, 아니면 BM25."""
        if not self.chunks:
            return []
        if embed_fn is not None:
            return self._search_embeddings(query, k, embed_fn)
        qtok = tokenize(query)
        scored = [SearchHit(c, self._bm25(qtok, c)) for c in self.chunks]
        scored = [h for h in scored if h.score > 0]
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:k]

    def _search_embeddings(self, query, k, embed_fn) -> list[SearchHit]:
        texts = [query] + [c.text for c in self.chunks]
        vecs = embed_fn(texts)
        qv = vecs[0]
        def cos(a, b):
            dot = sum(x * y for x, y in zip(a, b))
            na = math.sqrt(sum(x * x for x in a)) or 1.0
            nb = math.sqrt(sum(y * y for y in b)) or 1.0
            return dot / (na * nb)
        hits = [SearchHit(c, cos(qv, v)) for c, v in zip(self.chunks, vecs[1:])]
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:k]

    def find_symbol(self, name: str) -> list[Symbol]:
        """이름(대소문자 무시, 부분일치)으로 심볼 정의 위치를 찾는다."""
        q = name.lower()
        return [s for s in self.symbols if q in s.name.lower()]


def _main() -> None:
    parser = argparse.ArgumentParser(description="RAG 코드 인덱스 (P4)")
    parser.add_argument("--root", required=True, help="인덱싱할 소스 루트")
    parser.add_argument("--query", help="검색어")
    parser.add_argument("--symbols", action="store_true", help="심볼 목록 출력")
    parser.add_argument("-k", type=int, default=5)
    args = parser.parse_args()

    index = CodeIndex.build(args.root)
    print(f"# {len(index.chunks)} chunks, {len(index.symbols)} symbols")

    if args.symbols:
        for s in index.symbols[:200]:
            print(f"  {s.kind:9} {s.name:28} {s.file}:{s.line}")
        return
    if args.query:
        for hit in index.search(args.query, k=args.k):
            c = hit.chunk
            syms = f" [{', '.join(c.symbols)}]" if c.symbols else ""
            print(f"  {hit.score:6.2f}  {c.file}:{c.start_line}-{c.end_line}{syms}")


if __name__ == "__main__":
    _main()
