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
# 这几个必须强制覆盖，不能 setdefault：在配好的机器上跑测试时，
# 它们会让问答走 Agent 分支去调真实网关、宿主机接口和沙箱服务，测试就不再可复现。
os.environ["AGENT_MODE"] = "off"
os.environ["OPS_URL"] = ""
os.environ["OPS_TOKEN"] = ""
os.environ["SANDBOX_URL"] = ""
os.environ["SANDBOX_TOKEN"] = ""
# 场景包自动导入是后台线程，测试里必须关掉，要导入就在用例里显式调 packs.import_pack。
os.environ["DEMO_PACKS"] = ""

Path(_TEMP.name, "files").mkdir(parents=True, exist_ok=True)


def clear_graph():
    """清空组织运行图谱（graph.db），让每个用例从空图开始。延迟导入：env 必须先设好。"""
    from app import graph
    with graph.lock:
        for table in ("feedback", "proposals", "facts", "tool_calls", "executions", "entities"):
            graph.db.execute(f"DELETE FROM {table}")
        graph.db.commit()


class FakeReply:
    """Minimal stand-in for an LLM response object."""

    def __init__(self, content):
        self.content = content


def _matches(meta, where):
    """Chroma 的 where 子集：等值、$in、$and。"""
    if not where:
        return True
    if "$and" in where:
        return all(_matches(meta, clause) for clause in where["$and"])
    for key, cond in where.items():
        if isinstance(cond, dict):
            if "$in" in cond and meta.get(key) not in cond["$in"]:
                return False
            if "$eq" in cond and meta.get(key) != cond["$eq"]:
                return False
        elif meta.get(key) != cond:
            return False
    return True


class FakeCollection:
    """In-memory Chroma substitute backed by a plain dict: id -> (document, metadata[, embedding])."""

    def __init__(self, store=None):
        self.store = {} if store is None else store
        self.embeddings = {}
        self.last_query = {}

    def get(self, where=None, ids=None, include=None, **kwargs):
        items = [(i, d, m) for i, (d, m) in self.store.items()
                 if _matches(m, where) and (ids is None or i in ids)]
        out = {"ids": [i for i, _, _ in items],
               "documents": [d for _, d, _ in items],
               "metadatas": [m for _, _, m in items]}
        if include and "embeddings" in include:
            out["embeddings"] = [self.embeddings.get(i, [0.0]) for i, _, _ in items]
        return out

    def add(self, ids, documents, embeddings, metadatas):
        for i, d, e, m in zip(ids, documents, embeddings, metadatas):
            self.store[i] = (d, m)
            self.embeddings[i] = e

    def update(self, ids, metadatas):
        for i, m in zip(ids, metadatas):
            self.store[i] = (self.store[i][0], m)

    def delete(self, where=None, **kwargs):
        for i in [i for i, (_, m) in self.store.items()
                  if m.get("source") == where["source"]]:
            del self.store[i]
            self.embeddings.pop(i, None)

    def count(self):
        return len(self.store)

    def query(self, **kwargs):
        self.last_query = kwargs
        items = [(i, (d, m)) for i, (d, m) in self.store.items() if _matches(m, kwargs.get("where"))]
        size = min(kwargs["n_results"], len(items))
        items = items[:size]
        return {"ids": [[i for i, _ in items]],
                "documents": [[d for _, (d, _) in items]],
                "metadatas": [[m for _, (_, m) in items]],
                "distances": [[0.3] * size]}
