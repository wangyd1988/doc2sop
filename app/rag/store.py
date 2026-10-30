"""Vector store access: Chroma holds the chunk text, its vector and its metadata.

The vector is only an index. A query returns the *records* it points at — text,
source file and page — which is what the model and the citations actually need.
"""
import threading

import chromadb

from app.config import CHROMA_DIR, DEFAULT_CATEGORY

chroma = chromadb.PersistentClient(path=str(CHROMA_DIR))
collection = chroma.get_or_create_collection("knowledge", metadata={"hnsw:space": "cosine"})
write_lock = threading.Lock()
# Bumped on every write so derived indexes (BM25) know when to rebuild.
_version = 0

# Chroma rejects writes larger than a few thousand records.
BATCH = 256


def version() -> int:
    return _version


def _bump():
    global _version
    _version += 1


def replace_document(ids, texts, vectors, metas, source: str):
    """Insert a document, replacing any previous upload with the same file name."""
    with write_lock:
        collection.delete(where={"source": source})
        for start in range(0, len(texts), BATCH):
            end = start + BATCH
            collection.add(ids=ids[start:end], documents=texts[start:end],
                           embeddings=vectors[start:end], metadatas=metas[start:end])
        _bump()


def delete_document(source: str):
    with write_lock:
        collection.delete(where={"source": source})
        _bump()


def reset_collection():
    """Drop every vector and start an empty collection.

    Needed when the embedding model changes: Chroma refuses vectors of a different
    dimension in the same collection, and vectors from two models cannot be compared anyway.
    """
    global collection
    with write_lock:
        try:
            chroma.delete_collection("knowledge")
        except Exception:
            pass
        collection = chroma.get_or_create_collection("knowledge", metadata={"hnsw:space": "cosine"})
        _bump()


def dimension() -> int | None:
    """Vector size of the current index, or None when empty."""
    if collection.count() == 0:
        return None
    got = collection.get(limit=1, include=["embeddings"])
    vectors = got.get("embeddings")
    return len(vectors[0]) if vectors is not None and len(vectors) else None


def set_category(source: str, category: str) -> bool:
    """Re-tag every chunk of one document. False when the document is unknown."""
    with write_lock:
        got = collection.get(where={"source": source}, include=["metadatas"])
        if not got["ids"]:
            return False
        collection.update(ids=got["ids"],
                          metadatas=[{**m, "category": category} for m in got["metadatas"]])
        _bump()
    return True


def list_documents():
    """One row per source file, with its chunk count and category."""
    records = collection.get(include=["metadatas"])
    docs = {}
    for meta in records["metadatas"] or []:
        item = docs.setdefault(meta["source"],
                               {"source": meta["source"], "chunks": 0,
                                "category": meta.get("category") or DEFAULT_CATEGORY})
        item["chunks"] += 1
    return sorted(docs.values(), key=lambda d: (d["category"], d["source"]))


def all_categories():
    return sorted({d["category"] for d in list_documents()})


# --- 知识类工具用：目录缓存、按分类 / 文档过滤、按片段 id 取原文 -------------------------

_catalog_lock = threading.Lock()
_catalog = {"key": None, "docs": []}


def catalog():
    """list_documents() 的缓存版。

    知识类工具每轮都要看目录（kb_search 的说明、按分类过滤），几千个片段的元数据扫一遍要几十毫秒。
    写入会让 version 变，重建索引会换掉 collection，片段数也一起比，任何一个变了就重扫。
    """
    key = (_version, id(collection), collection.count())
    with _catalog_lock:
        if _catalog["key"] != key:
            _catalog.update(key=key, docs=list_documents())
        return [dict(d) for d in _catalog["docs"]]


def sources_for(category: str | None = None, source: str | None = None):
    """按分类、文档名过滤时允许的文档名集合；都不给返回 None（不过滤）。

    分类不直接按片段元数据过滤：老片段没有 category 字段，目录里按「未分类」显示，
    换成文档名再过滤，两边才对得上。
    """
    if not category and not source:
        return None
    return {d["source"] for d in catalog()
            if (not category or d["category"] == category) and (not source or d["source"] == source)}


def where_sources(sources):
    """文档名集合 → Chroma 的 where 条件。"""
    names = sorted(sources)
    return {"source": names[0]} if len(names) == 1 else {"source": {"$in": names}}


def split_id(chunk_id: str):
    """片段 id「文档键:序号」→ (文档键, 序号)；格式不对返回 None。同一文档的片段按序号连续编号。"""
    key, sep, seq = str(chunk_id or "").strip().rpartition(":")
    if not sep or not key or not seq.isdigit():
        return None
    return key, int(seq)


def get_chunks(ids):
    """按 id 取片段：[(id, 正文, 元数据)]，按文档内序号排好；不存在的 id 跳过。"""
    got = collection.get(ids=list(ids), include=["documents", "metadatas"])
    rows = list(zip(got["ids"], got["documents"] or [], got["metadatas"] or []))
    return sorted(rows, key=lambda row: (split_id(row[0]) or ("", 0))[1])


def page_chunks(source: str, page: int):
    """某个文档某一页的全部片段，按序号排好。"""
    got = collection.get(where={"$and": [{"source": source}, {"page": int(page)}]},
                         include=["documents", "metadatas"])
    rows = list(zip(got["ids"], got["documents"] or [], got["metadatas"] or []))
    return sorted(rows, key=lambda row: (split_id(row[0]) or ("", 0))[1])


def pages_of(source: str):
    """文档有哪些页码（没有页码的文档返回空列表）。"""
    got = collection.get(where={"source": source}, include=["metadatas"])
    return sorted({m["page"] for m in got["metadatas"] or [] if m.get("page") is not None})
