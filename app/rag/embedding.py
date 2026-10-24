"""Vectorisation.

The embedding model is self-hosted on a separate host and reached through the
same LiteLLM gateway as the chat models, so this module only has to care about
batching and error wrapping.

两个客户端只差超时：入库一批 16 段在 CPU 向量服务上要跑几秒到几十秒，查询只有一条短文本，
等不起就该让检索降级，而不是让整次提问卡住（见 config.EMBED_TIMEOUT / EMBED_INGEST_TIMEOUT）。
"""
from app import clients, settings
from app.config import log, why


class EmbeddingError(RuntimeError):
    """Raised when the embedding backend is unreachable or rejects the input."""


def embed_documents(texts):
    """Vectorise chunks for storage."""
    if clients.embeddings_bulk is None:
        raise EmbeddingError(settings.NOT_CONFIGURED)
    try:
        return clients.embeddings_bulk.embed_documents(texts)
    except Exception as exc:
        log.warning("embedding %d chunks failed", len(texts), exc_info=True)
        raise EmbeddingError(why(exc)) from exc


def embed_query(text: str):
    """Vectorise one question for similarity search."""
    if clients.embeddings is None:
        raise EmbeddingError(settings.NOT_CONFIGURED)
    try:
        return clients.embeddings.embed_query(text)
    except Exception as exc:
        log.warning("embedding query failed", exc_info=True)
        raise EmbeddingError(why(exc)) from exc
