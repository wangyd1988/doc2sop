"""Shared fixtures: isolate every test from real data and real model calls."""
import os
import tempfile
from pathlib import Path

# Must be set before app.config is imported.
_TEMP = tempfile.TemporaryDirectory()
os.environ.setdefault("LLM_BASE_URL", "http://127.0.0.1:9/v1")
os.environ.setdefault("LLM_API_KEY", "test-key")
os.environ.setdefault("WEB_USER", "tester")
os.environ.setdefault("WEB_PASSWORD", "test-password")
os.environ["DATA_DIR"] = _TEMP.name
os.environ["LANGSMITH_TRACING"] = "false"

Path(_TEMP.name, "files").mkdir(parents=True, exist_ok=True)


class FakeReply:
    """Minimal stand-in for an LLM response object."""

    def __init__(self, content):
        self.content = content


class FakeCollection:
    """In-memory Chroma substitute backed by a plain dict."""

    def __init__(self, store=None):
        self.store = {} if store is None else store
        self.last_query = {}

    def get(self, where=None, include=None, **kwargs):
        items = [(i, d, m) for i, (d, m) in self.store.items()
                 if not where or m.get("source") == where["source"]]
        return {"ids": [i for i, _, _ in items],
                "documents": [d for _, d, _ in items],
                "metadatas": [m for _, _, m in items]}

    def add(self, ids, documents, embeddings, metadatas):
        for i, d, m in zip(ids, documents, metadatas):
            self.store[i] = (d, m)

    def update(self, ids, metadatas):
        for i, m in zip(ids, metadatas):
            self.store[i] = (self.store[i][0], m)

    def delete(self, where=None, **kwargs):
        for i in [i for i, (_, m) in self.store.items()
                  if m.get("source") == where["source"]]:
            del self.store[i]

    def count(self):
        return len(self.store)

    def query(self, **kwargs):
        self.last_query = kwargs
        size = min(kwargs["n_results"], len(self.store))
        items = list(self.store.values())[:size]
        return {"documents": [[d for d, _ in items]],
                "metadatas": [[m for _, m in items]],
                "distances": [[0.3] * size]}
