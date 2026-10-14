"""Vectorisation.

The embedding model is self-hosted on a separate host and reached through the
same LiteLLM gateway as the chat models, so this module only has to care about
batching and error wrapping.
"""
from app.clients import embeddings
from app.config import log, why


class EmbeddingError(RuntimeError):
    """Raised when the embedding backend is unreachable or rejects the input."""


def embed_documents(texts):
    """Vectorise chunks for storage."""
    try:
        return embeddings.embed_documents(texts)
    except Exception as exc:
        log.warning("embedding %d chunks failed", len(texts), exc_info=True)
        raise EmbeddingError(why(exc)) from exc


def embed_query(text: str):
    """Vectorise one question for similarity search."""
    try:
        return embeddings.embed_query(text)
    except Exception as exc:
        log.warning("embedding query failed", exc_info=True)
        raise EmbeddingError(why(exc)) from exc
