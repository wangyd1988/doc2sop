"""Recall: question -> vector + BM25 -> fused ranking -> citable snippets.

Two retrievers, fused with reciprocal rank fusion:
  - vector search finds chunks *about* the question;
  - BM25 finds chunks that *contain the exact words* (field names, error codes, model numbers).
A chunk ranked well by either makes the list; a chunk ranked well by both rises to the top.

The similarity shown to users (and to the model as a hint) stays the cosine
score, so its meaning does not change with this fusion.
"""
import re
from pathlib import Path

from langsmith import traceable

from app.config import MIN_SCORE, TOP_K
from app.rag import lexical, store
from app.rag.embedding import embed_query

CANDIDATES = 30     # how deep each retriever looks before fusion
RRF_K = 60
# A chunk only BM25 found must earn its place: either it contains an exact identifier
# from the question (mem_limit, OOMKilled, E1234…) or it is at least this close semantically.
# Otherwise common CJK bigrams ("有几", "区别") drag in noise.
LEXICAL_MIN_SCORE = 0.40
# Everyday English words are not identifiers; "full" or "and" in the question must not admit a chunk.
STOP = {"the", "and", "or", "is", "are", "of", "to", "in", "on", "for", "with", "by", "at", "from",
        "as", "be", "it", "this", "that", "full", "not", "all", "new", "old", "set", "get", "use"}


def _identifiers(text: str):
    return {t for t in lexical.tokenize(text)
            if lexical.ASCII.fullmatch(t) and len(t) >= 3 and t not in STOP}


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _location(meta):
    return meta["source"] + (f" 第 {meta['page']} 页" if meta.get("page") else "")


@traceable(name="知识库检索", run_type="retriever")
def retrieve(question: str):
    """Return up to TOP_K snippets, each with its source location and score."""
    total = store.collection.count()
    if total == 0:
        return []
    query_vector = embed_query(question)
    depth = min(CANDIDATES, total)
    result = store.collection.query(
        query_embeddings=[query_vector], n_results=depth,
        include=["documents", "metadatas", "distances"])

    # id -> record; rank lists feed the fusion.
    records, vector_rank, lexical_rank = {}, [], []
    for cid, text, meta, distance in zip(result["ids"][0], result["documents"][0],
                                         result["metadatas"][0], result["distances"][0]):
        records[cid] = {"text": text, "meta": meta, "score": round(1 - distance, 3)}
        vector_rank.append(cid)

    try:
        lexical_hits = lexical.search(question, depth)
    except Exception:
        lexical_hits = []
    missing = []
    for cid, text, meta, _ in lexical_hits:
        if cid in records:
            lexical_rank.append(cid)
            continue
        records[cid] = {"text": text, "meta": meta, "score": None}
        missing.append(cid)
    if missing:
        # Lexical-only hits still get a real cosine score so the UI stays comparable.
        got = store.collection.get(ids=missing, include=["embeddings"])
        for cid, vector in zip(got["ids"], got["embeddings"]):
            records[cid]["score"] = round(_cosine(query_vector, list(vector)), 3)
        wanted = _identifiers(question)
        for cid in missing:
            record = records[cid]
            exact = bool(wanted & _identifiers(record["text"]))
            if exact or (record["score"] or 0) >= LEXICAL_MIN_SCORE:
                lexical_rank.append(cid)
            else:
                del records[cid]
        # keep BM25 order for the ones that survived
        order = {cid: i for i, (cid, *_rest) in enumerate(lexical_hits)}
        lexical_rank.sort(key=order.get)

    fused = {}
    for rank_list in (vector_rank, lexical_rank):
        for rank, cid in enumerate(rank_list, 1):
            fused[cid] = fused.get(cid, 0.0) + 1.0 / (RRF_K + rank)
    both = set(vector_rank) & set(lexical_rank)

    hits = []
    for cid in sorted(fused, key=lambda c: (-fused[c], -(records[c]["score"] or 0))):
        record = records[cid]
        if (record["score"] or 0) < MIN_SCORE:
            continue
        meta = record["meta"]
        hits.append({"index": len(hits) + 1, "location": _location(meta),
                     "text": record["text"], "score": record["score"],
                     "category": meta.get("category") or "",
                     "match": "both" if cid in both else
                              "lexical" if cid in lexical_rank else "vector"})
        if len(hits) >= TOP_K:
            break
    return hits


def as_context(hits) -> str:
    """Format snippets so the model can cite them by [number].

    The similarity is included so the model can weigh it — but only as a hint:
    with bge-style embeddings an unrelated chunk can still score 0.6.
    """
    if not hits:
        return "（这次没有检索到相关片段）"
    return "\n\n".join(f"[{h['index']}] 来源：{h['location']}（相似度 {h['score']:.2f}）\n{h['text']}"
                       for h in hits)


# 「知识库里都有什么」这类问题问的是全局，8 个片段答不了；要看文档目录。
OVERVIEW = re.compile(
    r"(知识库|资料库|文档库|库里|你)(里|中|都)?(有|包含|收录|存|放)(了)?(哪些|什么|啥|多少)"
    r"|(总结|概括|介绍|梳理|盘点|列)(一下)?(知识库|所有文档|全部文档|这些文档|资料)"
    r"|有哪些(文档|资料|文件|主题|内容|分类)"
    r"|(知识库|文档)(的)?(目录|清单|分类|概览|结构)")


def is_overview(question: str) -> bool:
    return bool(OVERVIEW.search(question or ""))


def catalog_context() -> str:
    """The whole catalogue, grouped by category, for overview questions."""
    docs = store.list_documents()
    if not docs:
        return "知识库目前是空的，还没有任何文档。"
    groups = {}
    for d in docs:
        groups.setdefault(d["category"], []).append(d)
    lines = [f"知识库目录：共 {len(docs)} 个文档、{sum(d['chunks'] for d in docs)} 个片段，分 {len(groups)} 类。"]
    for category, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        names = "、".join(f"《{Path(d['source']).stem}》" for d in items)
        lines.append(f"- {category}（{len(items)} 篇）：{names}")
    lines.append("\n请按分类概述知识库涵盖的主题，点出几个代表性文档；这是目录信息，不要用 [编号] 引用。"
                 "下面的检索片段只是随机样本，不能代表全库，不要据此说「知识库里没有某内容」。")
    return "\n".join(lines)
