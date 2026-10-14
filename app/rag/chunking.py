"""Chunking: turn extracted pages into retrievable chunks.

Chunks are deliberately small (~400 chars). A whole document compressed into one
768-dim vector loses every detail, and a page number can only be attached to a
chunk, not to a file.
"""
import hashlib
from pathlib import Path

from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import CHUNK_OVERLAP, CHUNK_SIZE

# Prefer paragraph and sentence boundaries over a hard cut, including Chinese
# punctuation, so a chunk rarely ends mid-sentence.
splitter = RecursiveCharacterTextSplitter(
    chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP,
    separators=["\n\n", "\n", "。", "！", "？", ". ", "! ", "? ", " ", ""],
)


def document_key(name: str) -> str:
    """Stable id prefix per file.

    Keyed by file name, not content: two different files with identical content
    must coexist instead of silently overwriting each other.
    """
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def chunk_pages(name: str, pages, digest: str, category: str):
    """Return (ids, texts, metadatas) ready for the vector store."""
    texts, metas = [], []
    for page, text in pages:
        for chunk in splitter.split_text(text):
            if not chunk.strip():
                continue
            texts.append(chunk)
            meta = {"source": name, "sha256": digest, "category": category}
            if page is not None:
                meta["page"] = page
            metas.append(meta)
    key = document_key(name)
    ids = [f"{key}:{i}" for i in range(len(texts))]
    return ids, texts, metas


def suffix_of(name: str) -> str:
    return Path(name).suffix.lower()
