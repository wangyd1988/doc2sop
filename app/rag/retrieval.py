"""Recall: question -> vector -> nearest chunks -> citable snippets."""
from langsmith import traceable

from app.config import MIN_SCORE, TOP_K
from app.rag import store
from app.rag.embedding import embed_query


@traceable(name="知识库检索", run_type="retriever")
def retrieve(question: str):
    """Return up to TOP_K snippets, each with its source location and score."""
    total = store.collection.count()
    if total == 0:
        return []
    result = store.collection.query(
        query_embeddings=[embed_query(question)],
        n_results=min(TOP_K, total),
        include=["documents", "metadatas", "distances"])

    hits = []
    for text, meta, distance in zip(result["documents"][0], result["metadatas"][0],
                                    result["distances"][0]):
        # Cosine distance -> similarity, so a bigger number always means "closer".
        score = round(1 - distance, 3)
        if score < MIN_SCORE:
            continue
        location = meta["source"] + (f" 第 {meta['page']} 页" if meta.get("page") else "")
        hits.append({"index": len(hits) + 1, "location": location,
                     "text": text, "score": score})
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
