"""Lexical recall (BM25) to complement the vector index.

Vector search is good at "what is this about" and bad at exact tokens: a config
field name, an error code, a product model. Those are precisely the questions a
knowledge base gets asked most. BM25 over the same chunks catches them.

Tokenisation needs no dictionary: ASCII runs (identifiers, numbers, error codes)
become one token each, CJK text becomes character bigrams. That is enough for
exact-term matching, which is all this index is for — ranking across the two
retrievers is done with reciprocal rank fusion in `retrieval`.

The index lives in memory and is rebuilt lazily when the store changes; a few
thousand chunks take well under a second.
"""
import math
import re
import threading
from collections import Counter

from app.rag import store

ASCII = re.compile(r"[a-z0-9][a-z0-9_.\-/:]*[a-z0-9]|[a-z0-9]")
CJK = re.compile(r"[\u4e00-\u9fff]+")
K1, B = 1.5, 0.75


def tokenize(text: str):
    text = (text or "").lower()
    tokens = ASCII.findall(text)
    for run in CJK.findall(text):
        if len(run) == 1:
            tokens.append(run)
        tokens.extend(run[i:i + 2] for i in range(len(run) - 1))
    return tokens


class _Index:
    def __init__(self, ids, texts, metas):
        self.ids, self.texts, self.metas = ids, texts, metas
        self.tf = [Counter(tokenize(t)) for t in texts]
        self.lengths = [sum(c.values()) for c in self.tf]
        self.avg = (sum(self.lengths) / len(self.lengths)) if self.lengths else 1.0
        df = Counter()
        for counter in self.tf:
            df.update(counter.keys())
        n = len(texts)
        self.idf = {term: math.log(1 + (n - d + 0.5) / (d + 0.5)) for term, d in df.items()}

    def search(self, query: str, limit: int, sources=None):
        terms = [t for t in set(tokenize(query)) if t in self.idf]
        if not terms:
            return []
        scores = []
        for i, counter in enumerate(self.tf):
            if sources is not None and self.metas[i].get("source") not in sources:
                continue
            s = 0.0
            norm = K1 * (1 - B + B * self.lengths[i] / self.avg)
            for term in terms:
                f = counter.get(term)
                if f:
                    s += self.idf[term] * f * (K1 + 1) / (f + norm)
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [(self.ids[i], self.texts[i], self.metas[i], s) for s, i in scores[:limit]]


_lock = threading.Lock()
_index = None
_built_for = -1


def search(query: str, limit: int, sources=None):
    """Top `limit` chunks by BM25 as (id, text, meta, score). `sources` 给了就只在这些文档里找。"""
    global _index, _built_for
    with _lock:
        if _index is None or _built_for != store.version():
            got = store.collection.get(include=["documents", "metadatas"])
            _index = _Index(got["ids"], got["documents"] or [], got["metadatas"] or [])
            _built_for = store.version()
        index = _index
    return index.search(query, limit, sources)
