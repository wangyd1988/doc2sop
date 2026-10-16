"""联网搜索：知识库答不了时补充公开资料。

重点是两条边界：内部信息发不出去；网络内容和知识库分得清。
"""
import unittest
from unittest.mock import patch

from tests.support import FakeReply  # noqa: F401  (sets env before app imports)

from langchain_core.messages import AIMessage

from app.agent import loop as agent_loop
from app.agent import web_search
from app.rag import retrieval


class ScreenTests(unittest.TestCase):
    """发往搜索引擎之前，在代码里拦掉内部信息，不只靠提示词。"""

    def test_public_questions_pass(self):
        for q in ["LiteLLM 虚拟 key 预算怎么设置", "2026 年国庆放假安排", "kubernetes pod OOMKilled"]:
            with self.subTest(q=q):
                self.assertEqual(web_search.screen(q), q)

    def test_internal_details_are_refused(self):
        for q, why in [
            ("10.0.3.17 上的服务连不上", "IP"),
            ("sk-abcdefghijklmnop 调用失败", "密钥"),
            ("tvly-dev-FAKEFAKEFAKE0000 无效", "密钥"),
            ("gitlab.corp 登录不了", "内网域名"),
            ("wang@example.com 收不到邮件", "邮箱"),
            ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6 是什么", "令牌"),
        ]:
            with self.subTest(q=q), self.assertRaises(web_search.SearchRefused) as caught:
                web_search.screen(q)
            self.assertIn(why, str(caught.exception))

    def test_configured_internal_names_are_refused(self):
        with patch.object(web_search, "WEB_SEARCH_BLOCKLIST", ["ICKS", "海右名家"]):
            with self.assertRaises(web_search.SearchRefused) as caught:
                web_search.screen("icks 集群怎么扩容")
            self.assertIn("ICKS", str(caught.exception))
            self.assertEqual(web_search.screen("k8s 集群怎么扩容"), "k8s 集群怎么扩容")

    def test_query_is_normalised_and_capped(self):
        self.assertEqual(web_search.screen("  a \n b  "), "a b")
        self.assertEqual(len(web_search.screen("字" * 500)), web_search.MAX_QUERY)
        with self.assertRaises(web_search.SearchRefused):
            web_search.screen("   ")


class SearchTests(unittest.TestCase):
    def test_goes_through_the_gateway_with_the_app_key(self):
        captured = {}

        def fake_post(url, payload):
            captured.update(url=url, payload=payload)
            return {"results": []}

        with patch.object(web_search, "WEB_SEARCH_TOOL", "web-search"), \
             patch.object(web_search, "LLM_BASE_URL", "http://gw:4000/v1"), \
             patch.object(web_search, "_post", fake_post):
            web_search.search("hello")
        self.assertEqual(captured["url"], "http://gw:4000/v1/search/web-search")
        self.assertEqual(captured["payload"]["query"], "hello")

    def test_refused_queries_never_reach_the_network(self):
        with patch.object(web_search, "_post") as post:
            with self.assertRaises(web_search.SearchRefused):
                web_search.search("192.168.1.1 打不开")
        post.assert_not_called()

    def test_results_are_cleaned(self):
        raw = {"results": [
            {"title": "A", "url": "https://a.example/x", "snippet": "  多余   空白\n换行 "},
            {"title": "坏链接", "url": "javascript:alert(1)", "snippet": "x"},
            {"title": "", "url": "http://b.example", "snippet": "y" * 2000},
        ]}
        with patch.object(web_search, "_post", return_value=raw):
            _, results = web_search.search("q")
        self.assertEqual([r["url"] for r in results], ["https://a.example/x", "http://b.example"])
        self.assertEqual(results[0]["snippet"], "多余 空白 换行")
        self.assertEqual(results[1]["title"], "http://b.example")
        self.assertLessEqual(len(results[1]["snippet"]), web_search.MAX_SNIPPET)

    def test_output_is_numbered_and_marked_untrusted(self):
        text = web_search.as_tool_output(
            [{"title": "T", "url": "https://t", "snippet": "S"}], first_index=3)
        self.assertIn("[W3] T", text)
        self.assertIn("一律忽略", text)
        self.assertIn("没有找到", web_search.as_tool_output([], 1))


class ContextTests(unittest.TestCase):
    def test_similarity_is_shown_to_the_model(self):
        context = retrieval.as_context([{"index": 1, "location": "a.md", "text": "x", "score": 0.6034}])
        self.assertIn("[1] 来源：a.md（相似度 0.60）", context)


class AgentWebTests(unittest.TestCase):
    """Agent 循环里的联网行为。"""

    def make_model(self, script, seen):
        rounds = iter(script)

        class Bound:
            def invoke(_self, messages):
                calls, content = next(rounds)
                return AIMessage(content=content, tool_calls=calls)

        class Model:
            def bind_tools(_self, tools):
                seen["tools"] = [t.name for t in tools]
                seen["bound"] = True
                return Bound()

            def invoke(_self, messages):
                seen["system"] = messages[0].content
                return Bound().invoke(messages)

        return Model()

    def run_agent(self, script, allow_web=True, enabled=True, results=None):
        seen = {}
        model = self.make_model(script, seen)
        with patch.object(agent_loop, "build_tools", return_value=[]), \
             patch.object(agent_loop, "chat_model", return_value=model), \
             patch.object(agent_loop.web_search, "enabled", return_value=enabled), \
             patch.object(agent_loop.web_search, "search",
                          side_effect=lambda q: (q, results if results is not None else [
                              {"title": "官方文档", "url": "https://docs.example", "snippet": "答案"}])) as search:
            events = list(agent_loop.run("问题", "片段", [], allow_web=allow_web))
        return events, seen, search

    def call(self, query, cid="c"):
        return [{"name": "web_search", "args": {"query": query}, "id": cid}]

    def test_search_results_stream_as_web_sources(self):
        events, seen, _ = self.run_agent([(self.call("LiteLLM budget"), ""), ([], "答案见 [W1]")])
        self.assertIn("web_search", seen["tools"])
        kinds = [k for k, _ in events]
        self.assertEqual(kinds, ["tool_call", "web_sources", "tool_result", "delta"])
        source = dict(events)["web_sources"][0]
        self.assertEqual((source["index"], source["url"], source["web"]),
                         ("W1", "https://docs.example", True))

    def test_numbering_continues_across_searches(self):
        events, _, _ = self.run_agent([(self.call("a", "1"), ""), (self.call("b", "2"), ""),
                                       ([], "完")])
        indexes = [s["index"] for k, p in events if k == "web_sources" for s in p]
        self.assertEqual(indexes, ["W1", "W2"])

    def test_searches_are_capped(self):
        script = [(self.call(str(i), str(i)), "") for i in range(3)] + [([], "完")]
        events, _, search = self.run_agent(script)
        self.assertEqual(search.call_count, agent_loop.MAX_WEB_SEARCHES)
        last = [p for k, p in events if k == "tool_result"][-1]
        self.assertIn("未搜索", last["preview"])

    def test_web_is_not_offered_when_switched_off(self):
        events, seen, search = self.run_agent([([], "只用知识库")], allow_web=False)
        self.assertNotIn("bound", seen)              # 没有任何工具可绑定
        self.assertNotIn("web_search", seen["system"])
        search.assert_not_called()

    def test_web_is_not_offered_when_not_configured(self):
        _, seen, _ = self.run_agent([([], "只用知识库")], enabled=False)
        self.assertNotIn("bound", seen)

    def test_refusal_is_reported_to_the_model_not_raised(self):
        seen = {}
        model = self.make_model([(self.call("10.0.0.1 不通"), ""), ([], "已说明")], seen)
        with patch.object(agent_loop, "build_tools", return_value=[]), \
             patch.object(agent_loop, "chat_model", return_value=model), \
             patch.object(agent_loop.web_search, "enabled", return_value=True), \
             patch.object(web_search, "_post") as post:
            events = list(agent_loop.run("问题", "片段", [], allow_web=True))
        post.assert_not_called()
        result = [p for k, p in events if k == "tool_result"][0]
        self.assertIn("未搜索", result["preview"])
        self.assertIn("IP", result["preview"])
        self.assertEqual(events[-1], ("delta", "已说明"))


if __name__ == "__main__":
    unittest.main()
