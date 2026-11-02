"""/api/ask 的对照记录：把问答的公共核心抽出来、以后再给群聊加参数，网页问答的行为都要一字不差。

每个场景用替身模型、替身检索跑一遍真实的 /api/ask（真实的 Agent 循环、图谱、执行记录、对话库），记下：
    events    流式返回的每一行（NDJSON）：原样逐字节比较，顺序、键的顺序、转义都算
    db        写进库里的：对话、消息（正文、来源、工具、模式）、图谱的执行、工具调用、实体和事实、SOP 执行记录；
              库里存的 JSON 文本也原样比较
    model     发给模型的每一次输入：系统提示词和消息、绑了哪些工具；检索、改写、沉淀调度收到的参数
ID、时间换成按出现顺序编号的占位符，和 tests/fixtures/ask_transcripts.json 逐项比较。

对照文件是在抽公共核心之前的代码上生成的。只有确认行为本来就该变时才重写它：
    ASK_GOLDEN_WRITE=1 python -m unittest tests.test_ask_golden
"""
import json
import os
import re
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量
from tests.support import clear_graph

from app import clients, conversations, graph, playbooks
from app import main as app_main
from app.agent import grow, kb_tools, ops_client, web_search
from app.agent import loop as agent_loop
from app.config import WEB_PASSWORD, WEB_USER
from app.rag import store

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "ask_transcripts.json"
WRITE = os.environ.get("ASK_GOLDEN_WRITE") == "1"

HITS = [{"index": 1, "location": "退款制度.md", "text": "退款在 7 个工作日内原路退回。", "score": 0.71,
         "category": "制度", "match": "vector", "id": "doc-a:0"},
        {"index": 2, "location": "值班手册.pdf 第 3 页", "text": "kb-app 内存超过 80% 时先看容器的内存上限。",
         "score": 0.55, "category": "运维", "match": "both", "id": "doc-b:4"}]
MORE = [{"index": 1, "location": "值班手册.pdf 第 4 页", "text": "调大上限前先看是不是有泄漏。", "score": 0.6,
         "category": "运维", "match": "vector", "id": "doc-b:5"}]
CATALOG = [{"source": "退款制度.md", "chunks": 3, "category": "制度"},
           {"source": "值班手册.pdf", "chunks": 9, "category": "运维"}]
TOOLS = {"host_disk": {"desc": "宿主机各分区的使用率", "params": {}},
         "container_stats": {"desc": "容器的 CPU 和内存", "params": {
             "name": {"type": "str", "pattern": "name", "required": True, "desc": "容器名"}}}}
SOP_TABLE = ("按 SOP《每日巡检》执行：\n\n| 步骤 | 检查项 | 结果 | 结论 |\n|---|---|---|---|\n"
             "| 1 | 宿主机磁盘 | 根分区 87% | ⚠️ 超过 85% |\n| 2 | 容器内存 | kb-app 512MB | ✅ 正常 |\n\n"
             "结论：⚠️ 有 1 项异常，建议清理日志。")

UUID = re.compile(r"\b[0-9a-f]{32}\b")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?")


class Normalizer:
    """ID 换成 <id1>、<id2>……（按第一次出现的顺序），时间换成 <time>。"""

    def __init__(self):
        self.ids = {}

    def text(self, value):
        value = UUID.sub(lambda m: self.ids.setdefault(m.group(0), f"<id{len(self.ids) + 1}>"), value)
        return TIME.sub("<time>", value)

    def __call__(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(str(k)): self(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self(v) for v in value]
        return value


class FakeChunk:
    def __init__(self, content):
        self.content = content


def dump_message(message):
    if isinstance(message, tuple):
        return list(message)
    out = {"type": message.type, "content": message.content}
    if getattr(message, "tool_calls", None):
        out["tool_calls"] = [{"name": c["name"], "args": c["args"]} for c in message.tool_calls]
    if getattr(message, "name", None):
        out["name"] = message.name
    return out


class ScriptedModel:
    """替身模型：按剧本回（(工具调用, 正文) 或异常）；记下每次绑了哪些工具、收到了什么。
    tool_choice 一律不收（和只认字符串写法以外的上游一样），forced 模式因此退回 prefetch。"""

    def __init__(self, script, seen):
        self.script, self.seen = iter(script), seen
        self.model_name = "kb-chat"

    def bind_tools(self, tools, tool_choice=None, **kwargs):
        if tool_choice is not None:
            raise TypeError("bind_tools() got an unexpected keyword argument 'tool_choice'")
        return _Bound(self, [t.name for t in tools])

    def invoke(self, messages):
        return _Bound(self, []).invoke(messages)


class _Bound:
    def __init__(self, model, names):
        self.model, self.names = model, names

    def invoke(self, messages):
        self.model.seen.append({"tools": self.names, "messages": [dump_message(m) for m in messages]})
        step = next(self.model.script)
        if isinstance(step, Exception):
            raise step
        calls, content = step
        return AIMessage(content=content, tool_calls=[{"name": n, "args": a, "id": f"c{i}"}
                                                      for i, (n, a) in enumerate(calls)])


def call(tool, /, **args):
    return (tool, args)


class Scenario:
    """一个场景：一组开关、替身，按顺序发几次提问，最后把库里的东西读出来。"""

    def __init__(self, test, switches=None, script=(), plain=("答案第一段，", "第二段 [1]"), ops=False,
                 retrieve_fails=None, model_fails=None, web=False, agent_run=None):
        self.test, self.switches = test, {"KB_TOOLS": False, "KB_RETRIEVAL_MODE": "prefetch", "PLAN_TOOL": False,
                                          "AGENT_MODE": "auto", "SMART_MODE": False, **(switches or {})}
        self.script, self.plain, self.ops, self.web = list(script), list(plain), ops, web
        self.retrieve_fails, self.model_fails, self.agent_run = retrieve_fails, model_fails, agent_run
        self.record = {"retrieve": [], "kb_search": [], "rewrite": [], "grow": [], "plain_model": [],
                       "agent_model": [], "exec": []}
        self.events = []

    def __enter__(self):
        self.stack = ExitStack()
        enter = self.stack.enter_context
        record = self.record
        for name, value in self.switches.items():
            enter(patch.object(app_main, name, value))

        def retrieve(query, progress=None, **kwargs):
            record["retrieve"].append({"query": query, **{k: v for k, v in kwargs.items() if v is not None}})
            if progress:
                progress("search")
            if self.retrieve_fails:
                raise self.retrieve_fails
            return [dict(h) for h in HITS]

        def kb_retrieve(query, **kwargs):
            record["kb_search"].append({"query": query, **{k: sorted(v) if isinstance(v, (set, frozenset)) else v
                                                           for k, v in kwargs.items() if v is not None}})
            return [dict(h) for h in MORE]

        def rewrite(question, history):
            record["rewrite"].append({"question": question, "history": [list(h) for h in history]})
            return f"{question}（接上文）"

        def plain_stream(_self, messages, **kwargs):
            record["plain_model"].append([dump_message(m) for m in messages])
            if self.model_fails:
                raise self.model_fails
            return [FakeChunk(part) for part in self.plain]

        def execute(name, args):
            record["exec"].append({"tool": name, "args": args})
            return {"ok": True, "output": f"{name} 的输出：根分区 87%，kb-app 512MB"}

        enter(patch.object(app_main, "retrieve", side_effect=retrieve))
        enter(patch.object(kb_tools.retrieval, "retrieve", side_effect=kb_retrieve))
        enter(patch.object(app_main, "rewrite_question", side_effect=rewrite))
        enter(patch.object(type(clients.llm), "stream", plain_stream))
        enter(patch.object(store, "catalog", return_value=[dict(d) for d in CATALOG]))
        enter(patch.object(store, "list_documents", return_value=[dict(d) for d in CATALOG]))
        enter(patch.object(ops_client, "enabled", return_value=self.ops))
        enter(patch.object(ops_client, "available_tools", return_value=json.loads(json.dumps(TOOLS))
                           if self.ops else {}))
        enter(patch.object(ops_client, "execute", side_effect=execute))
        enter(patch.object(web_search, "enabled", return_value=self.web))
        enter(patch.object(web_search, "search", side_effect=lambda q: (q, [
            {"title": "Redis 官方文档", "url": "https://redis.io/docs/maxmemory", "snippet": "maxmemory 的说明"}])))
        enter(patch.object(grow, "schedule", side_effect=lambda execution_id, answer, specs:
                           record["grow"].append({"execution_id": execution_id, "answer": answer})))
        enter(patch.object(agent_loop, "_today", return_value="2026-11-02 星期一"))
        enter(patch.object(agent_loop, "chat_model", return_value=ScriptedModel(self.script, record["agent_model"])))
        if self.agent_run is not None:
            enter(patch.object(agent_loop, "run", side_effect=self.agent_run))
        return self

    def __exit__(self, *exc):
        self.stack.close()
        return False

    def ask(self, question, **body):
        payload = {"question": question, **body}
        response = self.test.client.post("/api/ask", json=payload, auth=self.test.auth)
        self.test.assertEqual(response.status_code, 200, response.text)
        # 原样记下每一行（逐字节比较：键的顺序、转义都算），测试自己要用的另外解析一份
        lines = [line for line in response.text.split("\n") if line]
        self.test.assertTrue(response.text.endswith("\n"))
        self.events.append(lines)
        return [json.loads(line) for line in lines]

    def result(self):
        with conversations.lock:
            convs = conversations.db.execute("SELECT id, title FROM conversations ORDER BY rowid").fetchall()
            msgs = conversations.db.execute("SELECT id, conversation_id, role, content, sources, model, tools, mode"
                                            " FROM messages ORDER BY id").fetchall()
        index = {row["id"]: n for n, row in enumerate(msgs)}
        with graph.lock:
            execs = graph.db.execute("SELECT id, conversation_id, playbook_id, question, channel, outcome, message_id"
                                     " FROM executions ORDER BY rowid").fetchall()
            calls = graph.db.execute("SELECT execution_id, seq, tool, args, output_full, ok FROM tool_calls"
                                     " ORDER BY id").fetchall()
            entities = graph.db.execute("SELECT kind, name, attrs FROM entities WHERE kind != 'execution'"
                                        " ORDER BY kind, name").fetchall()
            facts = graph.db.execute(
                "SELECT s.kind, s.name, f.predicate, o.kind AS ok_, o.name AS on_, f.source_kind, f.status FROM facts f"
                " JOIN entities s ON s.id = f.subject LEFT JOIN entities o ON o.id = f.object_entity"
                " ORDER BY f.id").fetchall()
            sop = graph.db.execute("SELECT id, execution_id, playbook_name, trigger, note, params, status, level,"
                                   " summary, report, answer, error, conversation_id FROM sop_runs"
                                   " ORDER BY rowid").fetchall()
        # 库里存的 JSON 文本也原样比较
        db = {"conversations": [dict(r) for r in convs],
              "messages": [{k: r[k] for k in ("conversation_id", "role", "content", "sources", "model", "tools",
                                              "mode")} for r in msgs],
              "executions": [{**{k: r[k] for k in ("id", "conversation_id", "playbook_id", "question", "channel",
                                                   "outcome")},
                              "message": index.get(r["message_id"])} for r in execs],
              "tool_calls": [dict(r) for r in calls],
              "entities": [list(r) for r in entities],
              "facts": [list(r) for r in facts],
              "sop_runs": [dict(r) for r in sop]}
        return Normalizer()({"events": self.events, "db": db, "calls": self.record})


class AskGoldenTests(unittest.TestCase):
    maxDiff = None
    results = {}

    @classmethod
    def setUpClass(cls):
        cls.golden = {} if WRITE else json.loads(GOLDEN.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        if WRITE:
            GOLDEN.write_text(json.dumps(dict(sorted(cls.results.items())), ensure_ascii=False, indent=1) + "\n",
                              encoding="utf-8")

    def setUp(self):
        with conversations.lock:
            conversations.db.execute("DELETE FROM messages")
            conversations.db.execute("DELETE FROM conversations")
            conversations.db.commit()
        clear_graph()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        for cache in (agent_loop._no_tool_choice, agent_loop._ignored):
            cache.clear()
            self.addCleanup(cache.clear)
        self.client = TestClient(app_main.app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def check(self, name, scenario):
        got = scenario.result()
        type(self).results[name] = got
        if not WRITE:
            self.assertIn(name, self.golden, "对照文件里没有这个场景：先在改动之前的代码上用 ASK_GOLDEN_WRITE=1 生成")
            self.assertEqual(got, self.golden[name])

    # --- 纯知识库问答（没有工具可绑） ---------------------------------------------------------

    def test_plain_question_and_follow_up(self):
        with Scenario(self) as s:
            first = s.ask("退款多久能到账")
            s.ask("那加急呢", conversation_id=first[0]["conversation"]["id"])
        self.check("plain_question_and_follow_up", s)

    def test_plain_overview_uses_the_catalogue(self):
        with Scenario(self, plain=("知识库里有两类文档。",)) as s:
            s.ask("知识库里都有什么")
        self.check("plain_overview_uses_the_catalogue", s)

    def test_plain_retrieval_failure(self):
        with Scenario(self, retrieve_fails=RuntimeError("chroma down")) as s:
            s.ask("退款多久能到账")
        self.check("plain_retrieval_failure", s)

    def test_plain_model_failure(self):
        with Scenario(self, model_fails=RuntimeError("网关超时")) as s:
            s.ask("退款多久能到账")
        self.check("plain_model_failure", s)

    def test_agent_off_falls_back_to_plain(self):
        with Scenario(self, {"AGENT_MODE": "off", "KB_TOOLS": True}, ops=True) as s:
            s.ask("kb-app 内存高怎么办")
        self.check("agent_off_falls_back_to_plain", s)

    # --- Agent：知识类工具、数据类工具、按 SOP 执行、智能模式、forced、联网 --------------------------------

    def test_agent_kb_prefetch_with_follow_up_search(self):
        script = [([call("kb_search", query="内存泄漏")], ""), ([], "先看容器上限 [2]，再查泄漏 [3]。")]
        with Scenario(self, {"KB_TOOLS": True}, script=script) as s:
            s.ask("kb-app 内存高怎么办")
        self.check("agent_kb_prefetch_with_follow_up_search", s)

    def test_agent_data_tool_and_continuation(self):
        script = [([call("container_stats", name="kb-app")], ""), ([], "kb-app 用了 512MB，没超上限 [2]。"),
                  ([call("host_disk")], ""), ([], "根分区 87%，建议清理。")]
        with Scenario(self, {"KB_TOOLS": True}, script=script, ops=True) as s:
            first = s.ask("kb-app 内存高怎么办")
            s.ask("继续", conversation_id=first[0]["conversation"]["id"])
        self.check("agent_data_tool_and_continuation", s)

    def test_agent_runs_a_playbook(self):
        script = [([call("host_disk"), call("container_stats", name="kb-app")], ""), ([], SOP_TABLE)]
        with Scenario(self, {"PLAN_TOOL": True}, script=script, ops=True) as s:
            pid = playbooks.save(None, "每日巡检", "每天上班后", [
                {"tool": "host_disk", "args": {}}, {"tool": "container_stats", "args": {"name": ""}}],
                set(TOOLS))
            s.ask("执行 SOP《每日巡检》（name：kb-app）", playbook_id=pid)
        self.check("agent_runs_a_playbook", s)

    def test_agent_smart_mode(self):
        script = [([call("kb_search", query="退款")], ""), ([], "7 个工作日 [1]。一般银行到账更快。[💡]")]
        with Scenario(self, {"KB_TOOLS": True, "SMART_MODE": True}, script=script) as s:
            s.ask("退款多久能到账", answer_mode="smart")
        self.check("agent_smart_mode", s)

    def test_agent_forced_mode_falls_back_to_prefetch(self):
        script = [([], "7 个工作日 [1]。")]
        with Scenario(self, {"KB_TOOLS": True, "KB_RETRIEVAL_MODE": "forced"}, script=script) as s:
            s.ask("退款多久能到账")
        self.check("agent_forced_mode_falls_back_to_prefetch", s)

    def test_agent_web_search(self):
        script = [([call("web_search", query="Redis maxmemory")], ""), ([], "maxmemory 控制上限 [W1]。")]
        with Scenario(self, {"KB_TOOLS": True}, script=script, web=True) as s:
            s.ask("Redis 的 maxmemory 是什么", web=True)
        self.check("agent_web_search", s)

    def test_agent_model_failure(self):
        with Scenario(self, {"KB_TOOLS": True}, script=[RuntimeError("网关超时")]) as s:
            s.ask("kb-app 内存高怎么办")
        self.check("agent_model_failure", s)

    def test_agent_loop_crash(self):
        def crash(*args, **kwargs):
            yield "tool_call", {"tool": "host_disk", "args": {}, "category": "data"}
            raise RuntimeError("循环崩了")

        with Scenario(self, {"KB_TOOLS": True}, ops=True, agent_run=crash) as s:
            s.ask("kb-app 内存高怎么办")
        self.check("agent_loop_crash", s)


if __name__ == "__main__":
    unittest.main()
