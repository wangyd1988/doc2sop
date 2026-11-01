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
# 智能模式按代码默认关着测；要测它的用例自己 patch app.main.SMART_MODE。
os.environ["SMART_MODE"] = "false"
# 工具申请的模型预审同理：开着会在后台调真实网关；要测它的用例自己 patch app.config.TOOL_PREREVIEW。
os.environ["TOOL_PREREVIEW"] = "false"
os.environ.pop("TOOL_PREREVIEW_MODEL", None)
# 工具服务的自动检查：所有真正的试探共用每分钟 30 次的名额。几十个用例都会提交申请，按这个名额会在后台互相排队；
# 测名额的用例自己清掉这个变量、patch ops_readonly.PRECHECK_BUDGET。
os.environ["OPS_PRECHECK_PER_MINUTE"] = "100000"
# 场景包自动导入是后台线程，测试里必须关掉，要导入就在用例里显式调 packs.import_pack。
os.environ["DEMO_PACKS"] = ""
# 页面审批的口令文件指向临时目录（用例自己写），不读这台机器上真的 /etc/ops-readonly/approval.hash；
# OPS_CLI（页面上给的宿主机命令前缀）按默认拼法。
os.environ["OPS_APPROVAL_FILE"] = str(Path(_TEMP.name, "approval.hash"))
os.environ.pop("OPS_CLI", None)
# 自动执行的服务器配置（SMTP、收件组、告警令牌）指向临时目录里一个不存在的文件：不会读到这台机器上真的配置、
# 也就不会真的发邮件；要测的用例自己写这个文件。定时执行的后台线程也关掉，用例直接调 schedules.tick()。
os.environ["AUTOMATION_FILE"] = str(Path(_TEMP.name, "automation.yaml"))
os.environ["SCHEDULER"] = "false"

Path(_TEMP.name, "files").mkdir(parents=True, exist_ok=True)


def clear_graph():
    """清空组织运行图谱（graph.db），让每个用例从空图开始。延迟导入：env 必须先设好。
    SOP 执行记录、计划、告警规则、知识库缺口也在 graph.db 里，一起清。"""
    from app import graph
    with graph.lock:
        for table in ("feedback", "proposals", "facts", "tool_calls", "executions", "entities",
                      "sop_runs", "sop_schedules", "sop_slots", "alert_rules", "alert_events",
                      "kb_gaps", "kb_gap_ignores", "app_state"):
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
