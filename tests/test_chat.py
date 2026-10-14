"""Multi-turn memory, query rewriting and LangSmith tracing."""
import json
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from tests.support import FakeReply

from app import clients, conversations, tracing
from app.config import WEB_PASSWORD, WEB_USER
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
        root = MagicMock()
        before = len(self.client.get("/api/conversations",
                                     auth=self.auth).json()["conversations"])
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", return_value=root), \
             patch("app.main.retrieve", side_effect=RuntimeError("chroma down")), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q):
            response = self.client.post("/api/ask", json={"question": "检索会失败"},
                                        auth=self.auth)
        self.assertEqual(response.status_code, 502)
        root.patch.assert_called_once()
        self.assertIn("检索失败", root.end.call_args.kwargs["error"])
        after = self.client.get("/api/conversations", auth=self.auth).json()["conversations"]
        self.assertEqual(len(after), before)

    def test_broken_tracing_never_breaks_answers(self):
        with patch.object(tracing, "TRACING", True), \
             patch.object(tracing, "RunTree", side_effect=RuntimeError("langsmith unreachable")):
            events = self.ask("追踪故障时的提问", reply="照常回答。")
        self.assertEqual("".join(e.get("delta", "") for e in events), "照常回答。")


if __name__ == "__main__":
    unittest.main()
