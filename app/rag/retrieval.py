"""Recall: question -> vector + BM25 -> fused ranking -> citable snippets.

Two retrievers, fused with reciprocal rank fusion:
  - vector search finds chunks *about* the question;
  - BM25 finds chunks that *contain the exact words* (field names, error codes, model numbers).
A chunk ranked well by either makes the list; a chunk ranked well by both rises to the top.

The similarity shown to users (and to the model as a hint) stays the cosine
score, so its meaning does not change with this fusion.

向量服务超时或不可达时不让整次提问失败：退化为只用 BM25 召回，hit 上没有相似度（score=None）并带
degraded 标记，日志、给模型的上下文和页面来源卡片都标明这一点。
"""
import re
import time
from pathlib import Path

from langsmith import traceable

from app.config import MIN_SCORE, RERANK_CANDIDATES, TOP_K, log
from app.rag import lexical, rerank, store
from app.rag.embedding import EmbeddingError, embed_query

CANDIDATES = 30     # how deep each retriever looks before fusion
RRF_K = 60
# A chunk only BM25 found must earn its place: either it contains an exact identifier
# from the question (mem_limit, OOMKilled, E1234…) or it is at least this close semantically.
# Otherwise common CJK bigrams ("有几", "区别") drag in noise.
LEXICAL_MIN_SCORE = 0.40
# Everyday English words are not identifiers; "full" or "and" in the question must not admit a chunk.
STOP = {"the", "and", "or", "is", "are", "of", "to", "in", "on", "for", "with", "by", "at", "from",
        "as", "be", "it", "this", "that", "full", "not", "all", "new", "old", "set", "get", "use"}
DEGRADED_NOTE = "向量服务超时，本次只按关键词召回，没有相似度"


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
def retrieve(question: str, progress=None):
    """Return up to TOP_K snippets, each with its source location and score.

    `progress(stage)` 可选：开始召回时报 "retrieve"、真要调重排时报 "rerank"，
    问答流靠它把等待态分阶段告诉用户。各段耗时记一行 info 日志，慢在哪一眼能看出来。
    """
    report = progress or (lambda stage: None)
    report("retrieve")
    total = store.collection.count()
    if total == 0:
        return []
    timing, clock = {}, time.monotonic()

    def lap(name):
        nonlocal clock
        now = time.monotonic()
        timing[name] = now - clock
        clock = now

    try:
        query_vector = embed_query(question)
    except EmbeddingError as exc:
        # 向量服务挂了不该让提问失败：关键词召回还在，照样能答「文档上怎么说」
        log.warning("retrieve: embedding unavailable (%s), falling back to BM25 only", exc)
        query_vector = None
    lap("embed")
    depth = min(CANDIDATES, total)
    # id -> record; rank lists feed the fusion.
    records, vector_rank, lexical_rank = {}, [], []
    if query_vector is not None:
        result = store.collection.query(
            query_embeddings=[query_vector], n_results=depth,
            include=["documents", "metadatas", "distances"])
        lap("vector")
        for cid, text, meta, distance in zip(result["ids"][0], result["documents"][0],
                                             result["metadatas"][0], result["distances"][0]):
            records[cid] = {"text": text, "meta": meta, "score": round(1 - distance, 3)}
            vector_rank.append(cid)

    try:
        lexical_hits = lexical.search(question, depth)
    except Exception:
        lexical_hits = []
    lap("lexical")
    missing = []
    for cid, text, meta, _ in lexical_hits:
        if cid in records:
            lexical_rank.append(cid)
            continue
        records[cid] = {"text": text, "meta": meta, "score": None}
        missing.append(cid)
    if missing and query_vector is None:
        # 没有向量就没有余弦可比：BM25 的顺序就是全部依据，也不做相似度门槛
        lexical_rank.extend(missing)
    elif missing:
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
        lap("fill")

    fused = {}
    for rank_list in (vector_rank, lexical_rank):
        for rank, cid in enumerate(rank_list, 1):
            fused[cid] = fused.get(cid, 0.0) + 1.0 / (RRF_K + rank)
    both = set(vector_rank) & set(lexical_rank)

    hits = []
    # 融合后先多留一些给重排（它只看前 RERANK_CANDIDATES 条），没开重排时就是 TOP_K
    want = max(TOP_K, RERANK_CANDIDATES) if rerank.enabled() else TOP_K
    for cid in sorted(fused, key=lambda c: (-fused[c], -(records[c]["score"] or 0))):
        record = records[cid]
        if query_vector is not None and (record["score"] or 0) < MIN_SCORE:
            continue
        meta = record["meta"]
        hit = {"index": len(hits) + 1, "location": _location(meta),
               "text": record["text"], "score": record["score"],
               "category": meta.get("category") or "",
               "match": "both" if cid in both else
                        "lexical" if cid in lexical_rank else "vector"}
        if query_vector is None:
            hit["degraded"] = True
        hits.append(hit)
        if len(hits) >= want:
            break
    if rerank.enabled() and len(hits) > 1:
        report("rerank")
    out = rerank.rerank(question, hits, TOP_K)
    lap("rerank")
    log.info("retrieve: %s candidates=%d hits=%d total=%.0fms%s",
             " ".join(f"{k}={v * 1000:.0f}ms" for k, v in timing.items()),
             len(hits), len(out), sum(timing.values()) * 1000,
             " degraded=bm25-only" if query_vector is None else "")
    return out


def as_context(hits) -> str:
    """Format snippets so the model can cite them by [number].

    The similarity is included so the model can weigh it — but only as a hint:
    with bge-style embeddings an unrelated chunk can still score 0.6.
    """
    if not hits:
        return "（这次没有检索到相关片段）"
    note = ""
    if any(h.get("degraded") for h in hits):
        note = f"（{DEGRADED_NOTE}；片段是否相关只能看内容本身）\n\n"
    if any(h.get("rerank") is not None for h in hits):
        note += ("（重排分由交叉编码器给出：大于 0 通常相关，小于 -2 基本无关；它比相似度可靠得多，"
                 "全部为负时应判断为知识库没有相关内容）\n\n")
    return note + "\n\n".join(
        f"[{h['index']}] 来源：{h['location']}（"
        + (f"相似度 {h['score']:.2f}" if h.get("score") is not None else "相似度 —")
        + (f"，重排分 {h['rerank']:.1f}" if h.get("rerank") is not None else "") + f"）\n{h['text']}"
        for h in hits)


# 「知识库里都有什么」这类问题问的是全局，8 个片段答不了；要看文档目录。
OVERVIEW = re.compile(
    r"(知识库|资料库|文档库|库里|你)(里|中|都)?(有|包含|收录|存|放)(了)?(哪些|什么|啥|多少)"
    r"|(总结|概括|介绍|梳理|盘点|列)(一下)?(知识库|所有文档|全部文档|这些文档|资料)"
    r"|有哪些(文档|资料|文件|主题|内容|分类)"
    r"|(知识库|文档)(的)?(目录|清单|分类|概览|结构)")


def is_overview(question: str) -> bool:
    return bool(OVERVIEW.search(question or ""))


# 「继续」「好的」「都查」这类确认语：用户是在回应上一轮的提问，不是新问题。
# 拿它去检索只会召回一堆无关片段，还会让页面上的来源和正文引用对不上。
CONTINUATION = re.compile(
    r"^(?:(?:请|麻烦|那就|那|好|好的|行|嗯|是|是的|对|可以|ok|okay|yes|y|go|继续|继续吧|继续查|接着查|接着来|"
    r"查吧|查一下|都查|都要|两个都|全部|全都|第[一二三四五12345]个|前者|后者|要|需要|帮我|来吧|"
    r"看看|看一下|拉一下|拉吧|试试|开始)[吧呢啊呀哦嘛的了！!。.，,、～~\s]*)+$",
    re.IGNORECASE)


def is_continuation(question: str, history) -> bool:
    """短确认语 + 有上文 → 不检索，让 Agent 凭线程记忆接着上一轮做。"""
    q = (question or "").strip()
    return bool(history) and len(q) <= 12 and bool(CONTINUATION.match(q))


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
    lines.append("\n请按分类概述知识库涵盖的主题，点出几个代表性文档；这是目录信息，不要用 [编号] 引用，也不要调用工具。")
    return "\n".join(lines)
