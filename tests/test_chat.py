"""Multi-turn memory, query rewriting and LangSmith tracing."""
import json
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from tests.support import FakeReply, clear_graph

from app import clients, conversations, graph, models, playbooks, tracing
from app.config import CHAT_MODEL, WEB_PASSWORD, WEB_USER
from app.main import app
from app.rag import answer


class FakeChunk:
    def __init__(self, content):
        self.content = content


class ChatTests(unittest.TestCase):
    def setUp(self):
        with conversations.lock:
            conversations.db.execute("DELETE FROM messages")
            conversations.db.execute("DELETE FROM conversations")
            conversations.db.commit()
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        self.hits = [{"index": 1, "location": "手册.pdf 第 2 页",
                      "text": "退款需在 7 天内提出。", "score": 0.62}]

    def ask(self, question, conversation_id=None, captured=None, reply="好的，已为您查到。"):
        def fake_stream(_self, messages, **kwargs):
            if captured is not None:
                captured.append(messages)
            return [FakeChunk(reply)]

        body = {"question": question}
        if conversation_id:
            body["conversation_id"] = conversation_id
        with patch("app.main.retrieve", return_value=self.hits), \
             patch.object(type(clients.llm), "stream", fake_stream), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            response = self.client.post("/api/ask", json=body, auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        return [json.loads(line) for line in response.text.splitlines() if line]

    # --- memory --------------------------------------------------------------

    def test_overview_question_gets_the_catalogue_and_skips_retrieval(self):
        captured = []
        with patch("app.main.store.list_documents", return_value=[
                {"source": "巡检.md", "chunks": 5, "category": "运维"}]):
            events = self.ask("总结一下知识库里有哪些主要内容", captured=captured)
        prompt = captured[0][-1][1]
        self.assertIn("知识库目录：共 1 个文档", prompt)
        self.assertIn("《巡检》", prompt)
        # 目录问题不向量化、不重排：ask() 里的假 retrieve 会返回 self.hits，这里必须是空
        self.assertEqual(events[1]["sources"], [])

    def test_ordinary_question_does_not_get_the_catalogue(self):
        captured = []
        self.ask("退款政策是什么？", captured=captured)
        self.assertNotIn("知识库目录", captured[0][-1][1])

    def test_follow_up_receives_previous_turns(self):
        first = self.ask("退款政策是什么？")
        conversation_id = first[0]["conversation"]["id"]
        self.assertEqual(first[1]["sources"], self.hits)

        captured = []
        self.ask("那超过期限呢？", conversation_id, captured)
        roles = [role for role, _ in captured[0]]
        contents = [content for _, content in captured[0]]
        self.assertEqual(roles, ["system", "human", "ai", "human"])
        self.assertIn("退款政策是什么？", contents)
        self.assertIn("好的，已为您查到。", contents)
        self.assertIn("那超过期限呢？", contents[-1])

    def test_history_is_isolated_per_conversation(self):
        first = self.ask("第一个话题")
        other = self.ask("第二个话题")
        self.assertNotEqual(first[0]["conversation"]["id"], other[0]["conversation"]["id"])

        captured = []
        self.ask("继续", other[0]["conversation"]["id"], captured)
        contents = " ".join(content for _, content in captured[0])
        self.assertIn("第二个话题", contents)
        self.assertNotIn("第一个话题", contents)

    def test_conversation_is_listed_and_replayable(self):
        events = self.ask("容器内存上限怎么设？")
        conversation_id = events[0]["conversation"]["id"]

        listed = self.client.get("/api/conversations", auth=self.auth).json()["conversations"]
        self.assertEqual(listed[0]["id"], conversation_id)
        self.assertEqual(listed[0]["title"], "容器内存上限怎么设？")
        self.assertEqual(listed[0]["messages"], 2)

        saved = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        self.assertEqual([m["role"] for m in saved["messages"]], ["user", "assistant"])
        # Citations are replayed with the answer, not recomputed.
        self.assertEqual(saved["messages"][1]["sources"], self.hits)

    def test_delete_and_unknown_conversation(self):
        conversation_id = self.ask("要删掉的对话")[0]["conversation"]["id"]
        self.client.delete(f"/api/conversations/{conversation_id}", auth=self.auth)
        self.assertEqual(
            self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).status_code,
            404)
        with conversations.lock:
            left = conversations.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        self.assertEqual(left, 0)
        self.assertEqual(
            self.client.post("/api/ask", json={"question": "在吗", "conversation_id": "missing"},
                             auth=self.auth).status_code, 404)

    def test_requires_authentication(self):
        self.assertEqual(self.client.get("/api/conversations").status_code, 401)
        self.assertEqual(self.client.post("/api/ask", json={"question": "你好"}).status_code, 401)

    # --- model selection -----------------------------------------------------

    def test_tool_activity_is_saved_with_the_answer_and_replayed(self):
        """工具调用过程随回答存下来，回放时能看到调了什么、返回了什么。"""
        def fake_run(question, context, history, **kwargs):
            yield "tool_call", {"tool": "host_disk", "args": {}}
            yield "tool_result", {"tool": "host_disk", "preview": "/dev/vda1 41%", "lines": 1, "chars": 13}
            yield "delta", "磁盘正常"

        with patch("app.main.retrieve", return_value=self.hits), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch("app.main.AGENT_MODE", "auto"), \
             patch("app.main.ops_client.enabled", return_value=True), \
             patch("app.main.agent_loop.run", side_effect=fake_run):
            response = self.client.post("/api/ask", json={"question": "磁盘怎么样", "web": False}, auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        conversation_id = events[0]["conversation"]["id"]
        replay = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        tools = replay["messages"][-1]["tools"]
        self.assertEqual(tools, [{"tool": "host_disk", "args": {}, "preview": "/dev/vda1 41%", "lines": 1}])

    # --- organisation graph --------------------------------------------------

    def test_every_turn_gets_an_execution_that_is_closed_with_the_answer(self):
        """首行带 execution_id；回答落库后执行记录指回那条消息，回放时消息也挂着它。"""
        clear_graph()
        events = self.ask("退款期限是多久？")
        execution_id = events[0]["execution_id"]
        run = graph.execution(execution_id)
        conversation_id = events[0]["conversation"]["id"]
        self.assertEqual(run["conversation_id"], conversation_id)
        self.assertEqual(run["question"], "退款期限是多久？")
        self.assertEqual(run["outcome"], "unknown")       # 纯知识库回答，没观察系统
        self.assertIsNotNone(run["finished_at"])
        replay = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        assistant = replay["messages"][-1]
        self.assertEqual(assistant["execution_id"], execution_id)
        self.assertEqual(run["message_id"], assistant["id"])
        self.assertNotIn("execution_id", replay["messages"][0])   # 用户消息没有执行记录

    def test_execute_button_records_the_playbook(self):
        clear_graph()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        pid = playbooks.save(None, "巡检", "", [{"tool": "host_disk", "args": {}}], {"host_disk"})

        def fake_run(question, context, history, **kwargs):
            graph.record_tool_call(kwargs["execution_id"], "host_disk", {}, "/dev/vda1 41%", True, 2)
            yield "tool_call", {"tool": "host_disk", "args": {}}
            yield "tool_result", {"tool": "host_disk", "preview": "/dev/vda1 41%", "lines": 1, "chars": 13}
            yield "delta", "⚠️ 告警：磁盘 91%"

        with patch("app.main.retrieve", return_value=self.hits), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch("app.main.AGENT_MODE", "auto"), \
             patch("app.main.ops_client.enabled", return_value=True), \
             patch("app.main.agent_loop.run", side_effect=fake_run):
            response = self.client.post("/api/ask", json={"question": "执行 SOP《巡检》", "playbook_id": pid},
                                        auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        run = graph.execution(events[0]["execution_id"])
        self.assertEqual((run["playbook_id"], run["outcome"]), (pid, "anomaly"))
        self.assertEqual(run["tool_calls"][0]["output"], "/dev/vda1 41%")

    def test_unknown_playbook_is_refused_before_anything_runs(self):
        response = self.client.post("/api/ask", json={"question": "执行", "playbook_id": "nope"},
                                    auth=self.auth)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.client.get("/api/conversations", auth=self.auth).json()["conversations"], [])

    def test_failed_turn_is_closed_as_failed(self):
        clear_graph()
        with patch("app.main.retrieve", return_value=self.hits), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch.object(type(clients.llm), "stream", side_effect=RuntimeError("网关超时")):
            response = self.client.post("/api/ask", json={"question": "会失败"}, auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        run = graph.execution(events[0]["execution_id"])
        self.assertEqual(run["outcome"], "failed")
        self.assertIsNone(run["message_id"])

    def test_feedback_is_recorded_against_the_execution(self):
        clear_graph()
        execution_id = self.ask("年假有几天？")[0]["execution_id"]
        response = self.client.post("/api/feedback", json={"execution_id": execution_id,
                                                           "verdict": "false_alarm", "note": "阈值太低"},
                                    auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["verdict"], "false_alarm")
        self.assertEqual([f["value"] for f in graph.facts_of("execution", execution_id, "judged")],
                         ["false_alarm"])
        self.assertEqual(self.client.post("/api/feedback", json={"execution_id": "nope", "verdict": "correct"},
                                          auth=self.auth).status_code, 404)
        self.assertEqual(self.client.post("/api/feedback", json={"execution_id": execution_id, "verdict": "meh"},
                                          auth=self.auth).status_code, 422)

    def test_model_list_falls_back_to_default_when_gateway_is_down(self):
        def down():
            raise OSError("connection refused")

        with patch.object(models, "_fetch", down):
            models._cache.update(at=0.0, models=[])
            data = self.client.get("/api/models", auth=self.auth).json()
        self.assertEqual(data["models"], [CHAT_MODEL])
        self.assertEqual(data["default"], CHAT_MODEL)

    def test_model_list_comes_from_the_gateway_and_hides_non_chat_models(self):
        with patch.object(models, "_fetch", return_value=["kb-embedding", "b-model", "a-model", CHAT_MODEL]):
            models._cache.update(at=0.0, models=[])
            data = self.client.get("/api/models", auth=self.auth).json()
        self.assertEqual(data["models"], [CHAT_MODEL, "a-model", "b-model"])

    def test_unknown_model_is_refused_before_anything_runs(self):
        with patch.object(models, "_fetch", return_value=[CHAT_MODEL]), \
             patch("app.main.retrieve") as retrieve:
            response = self.client.post("/api/ask", json={"question": "你好", "model": "nope"},
                                        auth=self.auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn("nope", response.json()["detail"])
        retrieve.assert_not_called()
        self.assertEqual(conversations.list_conversations(), [])

    def test_chosen_model_is_used_and_recorded(self):
        used = []

        def fake_stream(_self, messages, **kwargs):
            used.append(_self.model_name)
            return [FakeChunk("回答")]

        with patch.object(models, "_fetch", return_value=[CHAT_MODEL, "other-model"]), \
             patch("app.main.retrieve", return_value=self.hits), \
             patch.object(type(clients.llm), "stream", fake_stream), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            models._cache.update(at=0.0, models=[])
            response = self.client.post("/api/ask", json={"question": "你好", "model": "other-model"},
                                        auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        self.assertEqual(used, ["other-model"])
        self.assertEqual(events[0]["model"], "other-model")
        conversation_id = events[0]["conversation"]["id"]
        replay = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        self.assertEqual(replay["messages"][-1]["model"], "other-model")

    def test_default_model_when_none_chosen(self):
        events = self.ask("你好")
        self.assertEqual(events[0]["model"], CHAT_MODEL)

    # --- query rewriting -----------------------------------------------------

    def test_rewrite_expands_follow_up(self):
        history = [("user", "容器内存上限怎么设"), ("assistant", "见文档")]
        with patch.object(type(clients.rewriter), "invoke",
                          lambda _s, _m, **kw: FakeReply(' "容器内存上限的推荐值是多少" \n多余解释')):
            self.assertEqual(answer.rewrite_question("那推荐值呢", history),
                             "容器内存上限的推荐值是多少")

    def test_rewrite_falls_back_when_model_fails(self):
        def boom(_self, _messages, **kwargs):
            raise RuntimeError("boom")

        history = [("user", "容器内存上限怎么设"), ("assistant", "见文档")]
        with patch.object(type(clients.rewriter), "invoke", boom):
            self.assertEqual(answer.rewrite_question("那推荐值呢", history), "那推荐值呢")
        # No history means nothing to resolve, so the model is never called.
        self.assertEqual(answer.rewrite_question("独立问题", []), "独立问题")

    # --- thinking models -----------------------------------------------------

    def test_reasoning_effort_is_off_by_default(self):
        """Some gateways leak English reasoning into the answer when this is sent."""
        self.assertEqual(clients.REASONING_EFFORT, "")
        for client in (clients.llm, clients.rewriter):
            self.assertIsNone(client.reasoning_effort)

    def test_reasoning_effort_can_be_configured(self):
        with patch.object(clients, "REASONING_EFFORT", "low"):
            self.assertEqual(clients.chat_model().reasoning_effort, "low")
        with patch.object(clients, "REASONING_EFFORT", ""):
            self.assertIsNone(clients.chat_model().reasoning_effort)

    # --- tracing -------------------------------------------------------------

    def test_no_tracing_calls_when_disabled(self):
        """RunTree reaches out to LangSmith on creation, so it must stay untouched."""
        with patch.object(tracing, "TRACING", False), \
             patch.object(tracing, "RunTree") as run_tree:
            events = self.ask("追踪关闭时的提问")
            self.assertIsNone(tracing.start_root_run("q", None))
        run_tree.assert_not_called()
        self.assertEqual(events[1]["sources"], self.hits)

    def test_root_run_records_question_and_answer(self):
        root = MagicMock()
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", return_value=root) as run_tree:
            self.ask("退款政策是什么？", reply="七天内可退。")

        kwargs = run_tree.call_args.kwargs
        self.assertEqual(kwargs["name"], "知识库问答")
        self.assertEqual(kwargs["inputs"], {"question": "退款政策是什么？"})
        root.post.assert_called_once()
        root.patch.assert_called_once()
        outputs = root.end.call_args.kwargs["outputs"]
        self.assertEqual(outputs["answer"], "七天内可退。")
        self.assertEqual(outputs["sources"], len(self.hits))
        self.assertIsNone(root.end.call_args.kwargs["error"])

    def test_real_run_tree_keeps_metadata(self):
        """RunTree drops a bare metadata= kwarg, so assert against a real object, not a mock."""
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing.RunTree, "post", lambda _self: None):
            root = tracing.start_root_run("问题文本", "conv-123")
        self.assertEqual(root.inputs, {"question": "问题文本"})
        self.assertEqual(root.extra["metadata"]["conversation_id"], "conv-123")
        self.assertIn("chat_model", root.extra["metadata"])
        self.assertIn("top_k", root.extra["metadata"])

    def test_first_turn_carries_real_conversation_id(self):
        """Threads are grouped by conversation_id, so it must never be a placeholder."""
        root = MagicMock()
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", return_value=root) as run_tree:
            events = self.ask("全新对话的第一句")
        traced_id = run_tree.call_args.kwargs["extra"]["metadata"]["conversation_id"]
        self.assertEqual(traced_id, events[0]["conversation"]["id"])
        self.assertTrue(conversations.exists(traced_id))

    def test_root_run_closed_when_model_fails(self):
        def boom(_self, _messages, **kwargs):
            raise RuntimeError("model down")

        root = MagicMock()
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", return_value=root), \
             patch("app.main.retrieve", return_value=self.hits), \
             patch.object(type(clients.llm), "stream", boom), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            response = self.client.post("/api/ask", json={"question": "会失败的提问"},
                                        auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        self.assertIn("大模型调用失败", events[-1]["error"])
        root.patch.assert_called_once()
        self.assertIn("大模型调用失败", root.end.call_args.kwargs["error"])

    def test_failed_first_turn_leaves_no_empty_conversation(self):
        """检索在流里做，失败只能作为 error 事件发出；新对话没答出任何东西就不该留在历史里，执行记录也要收口。"""
        clear_graph()
        root = MagicMock()
        before = len(self.client.get("/api/conversations",
                                     auth=self.auth).json()["conversations"])
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", return_value=root), \
             patch("app.main.retrieve", side_effect=RuntimeError("chroma down")), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            response = self.client.post("/api/ask", json={"question": "检索会失败"},
                                        auth=self.auth)
        self.assertEqual(response.status_code, 200)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        self.assertIn("conversation", events[0])
        self.assertIn("检索失败", events[-1]["error"])
        self.assertFalse(any("sources" in e or "delta" in e for e in events))
        root.patch.assert_called_once()
        self.assertIn("检索失败", root.end.call_args.kwargs["error"])
        after = self.client.get("/api/conversations", auth=self.auth).json()["conversations"]
        self.assertEqual(len(after), before)
        run = graph.execution(events[0]["execution_id"])
        self.assertEqual(run["outcome"], "failed")
        self.assertIsNotNone(run["finished_at"])

    def test_retrieval_stages_are_streamed_before_the_sources(self):
        """等待期间页面要看到「检索 → 重排 → 思考」在推进：阶段事件来自 retrieve 的 progress 回调，只加不改既有事件。"""
        def staged_retrieve(query, progress=None):
            progress("retrieve")
            progress("rerank")
            return self.hits

        def fake_stream(_self, messages, **kwargs):
            return [FakeChunk("答案")]

        with patch("app.main.retrieve", side_effect=staged_retrieve), \
             patch.object(type(clients.llm), "stream", fake_stream), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            response = self.client.post("/api/ask", json={"question": "退款政策是什么？"}, auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        self.assertEqual([next(iter(e)) for e in events],
                         ["conversation", "stage", "stage", "sources", "stage", "delta"])
        self.assertEqual([e["stage"] for e in events if "stage" in e], ["retrieve", "rerank", "think"])
        self.assertEqual(events[3]["sources"], self.hits)

    def test_follow_up_announces_the_rewrite_stage(self):
        first = self.ask("退款政策是什么？")
        events = self.ask("那超过期限呢？", first[0]["conversation"]["id"])
        self.assertEqual(events[1], {"stage": "rewrite"})

    def test_broken_tracing_never_breaks_answers(self):
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", side_effect=RuntimeError("langsmith unreachable")):
            events = self.ask("追踪故障时的提问", reply="照常回答。")
        self.assertEqual("".join(e.get("delta", "") for e in events), "照常回答。")


if __name__ == "__main__":
    unittest.main()
