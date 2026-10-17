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
