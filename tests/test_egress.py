"""统一出网规则（app/agent/egress.py）：搜索词和链接发出去之前，在代码里过同一套规则。

钉住的判定：
- 静态拦截：搜索词的规则不变；链接解码后再查一遍，slug 不算令牌；
- 污点：x-entity 实参（用户提过也算）、返回里同时有字母和数字或连字符的标识符（用户本轮原样说过的除外）；
  OOMKilled、137、带单位的数量、v1.2 这类不算；按词边界、不分大小写匹配；
- 严格模式 WEB_AFTER_DATA=deny：调过数据类工具之后不再联网；默认 screen 照常；
- 链接来源：只认本轮搜索结果和用户本轮消息里的链接；
- 这些都接在真实的 Agent 循环里；WEB_FETCH 没绑时提示词和以前一字不差，外网类各工具分别限次。
"""
import unittest
from unittest.mock import patch

from tests.support import clear_graph

from langchain_core.messages import AIMessage

from app.agent import egress, ops_client, registry, web_fetch, web_search
from app.agent import loop as agent_loop

ENTITY_SCHEMA = {"type": "object", "properties": {
    "name": {"type": "string", "x-entity": "container"},
    "lines": {"type": "integer"}}}


def turn_for(question=""):
    turn = registry.Turn()
    turn.usage[egress.STATE] = egress.start(question)
    return turn


def refused(check, *args):
    try:
        check(*args)
    except egress.Refused as exc:
        return str(exc)
    return None


class StaticScreenTests(unittest.TestCase):
    """screen() 同时用于搜索词和链接：同一套规则，链接里的 slug 不算令牌。"""

    def test_query_rules_and_messages_are_unchanged(self):
        self.assertEqual(refused(egress.screen, "10.0.3.17 上的服务连不上"),
                         "搜索词里含有IP 地址，为防止内部信息外泄，已拒绝上网搜索")
        self.assertIsNone(refused(egress.screen, "kubernetes pod OOMKilled"))
        # 搜索词里，连字符连起来的长串照旧算令牌
        self.assertIn("令牌", refused(egress.screen, "how-to-check-oomkilled-in-kubernetes-pod"))

    def test_url_slugs_are_not_tokens(self):
        for url in ["https://stackoverflow.com/questions/52456337/how-to-check-oomkilled-in-kubernetes-pod",
                    "https://learn.microsoft.com/en-us/azure/aks/troubleshoot-memory-saturation-aks",
                    "https://en.wikipedia.org/wiki/Comparison_of_continuous_integration_software",
                    "https://medium.com/@someone/understanding-oomkilled-in-kubernetes-1a2b3c4d5e6f",
                    "https://blog.csdn.net/weixin_43123456/article/details/123456789"]:
            with self.subTest(url=url):
                self.assertIsNone(refused(egress.screen_url, url))

    def test_url_secrets_and_internal_details_are_refused(self):
        for url, label in [
            ("https://github.com/o/r/commit/0123456789abcdef0123456789abcdef01234567", "令牌"),
            ("https://api.example.com/x?t=AbCdEfGhIjKlMnOpQrStUv-WxYz0123456789_abcdEF", "令牌"),
            ("https://example.com/hook?key=sk-abcdefghijklmnop", "密钥"),
            ("https://example.com/a?ip=10.0.0.1", "IP"),
            ("https://gitlab.corp/group/project", "内网域名"),
            ("https://example.com/u/wang@example.com", "邮箱"),
            # 百分号编码过的令牌照样拦：解码后再查一遍
            ("https://example.com/x?t=" + "".join(f"%{ord(c):02X}" for c in "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
             "令牌"),
        ]:
            with self.subTest(url=url):
                reason = refused(egress.screen_url, url)
                self.assertIsNotNone(reason)
                self.assertIn(label, reason)
                self.assertTrue(reason.startswith("链接里含有"))

    def test_blocklist_applies_to_urls_even_when_percent_encoded(self):
        with patch.object(egress, "WEB_SEARCH_BLOCKLIST", ["海右名家", "ICKS"]):
            self.assertIn("海右名家", refused(egress.screen_url,
                                              "https://example.com/s?q=%E6%B5%B7%E5%8F%B3%E5%90%8D%E5%AE%B6"))
            self.assertIn("ICKS", refused(egress.screen_url, "https://example.com/icks/scale"))
            self.assertIsNone(refused(egress.screen_url, "https://example.com/k8s/scale"))

    def test_refusals_carry_the_rule_and_what_matched_for_the_log(self):
        """日志里记规则类别和命中的词；疑似密钥、令牌只记开头几个字符。"""
        for query, rule, word in [("10.0.3.17 上的服务连不上", "static:IP 地址", "10.0.3.17"),
                                  ("sk-abcdefghijklmnop 调用失败", "static:疑似密钥", "sk-a…（19 字符）"),
                                  ("gitlab.corp 登录不了", "static:内网域名", "gitlab.corp")]:
            with self.subTest(query=query), self.assertRaises(egress.Refused) as caught:
                egress.screen(query)
            self.assertEqual((caught.exception.rule, caught.exception.word), (rule, word))


class TaintRuleTests(unittest.TestCase):
    """污点：哪些算、哪些不算。"""

    OUTPUT = ("NAME        STATUS      REASON     EXIT\n"
              "payroll-db  Restarting  OOMKilled  137\n"
              "web01       Up 3 hours  -          0\n"
              "image python:3.12-slim  mem 512MiB / 1Gi  cpu 250m  api v1.2.3  host db01.prod.example.com\n"
              "container a1b2c3d4e5f6 limit 700m uptime 30s")

    def test_resource_like_identifiers(self):
        found = set(egress.identifiers(self.OUTPUT))
        for name in ("payroll-db", "web01", "a1b2c3d4e5f6", "db01", "db01.prod.example.com"):
            self.assertIn(name, found)
        # 公开术语、纯数字、带单位的数量、版本号、太短的都不算
        for word in ("OOMKilled", "Restarting", "137", "512MiB", "1Gi", "250m", "700m", "30s", "v1.2.3",
                     "NAME", "EXIT", "0", "prod", "example"):
            self.assertNotIn(word, found)

    def test_x_entity_arguments_are_taint_even_if_the_user_said_them(self):
        turn = turn_for("payroll-db 为什么一直重启")
        egress.observe(turn, ENTITY_SCHEMA, {"name": "payroll-db", "lines": 100}, "（没有输出）")
        reason = refused(egress.check_query, turn, "payroll-db OOMKilled 原因")
        self.assertEqual(reason, "搜索词里含有本轮查过的内部对象「payroll-db」，为防止内部信息外泄，已拒绝上网搜索；"
                                 "去掉它、只用公开的通用词再搜")
        self.assertIsNone(refused(egress.check_query, turn, "kubernetes OOMKilled 137 原因"))

    def test_output_identifiers_are_taint_unless_the_user_said_them(self):
        turn = turn_for("看下 web01 上的容器为什么重启")
        egress.observe(turn, {}, {}, self.OUTPUT)
        self.assertIn("本轮数据里出现过的标识符「payroll-db」",
                      refused(egress.check_query, turn, "payroll-db OOMKilled"))
        # 用户本轮原样说过的 web01 不算；公开术语照常能搜
        for query in ["web01 OOMKilled 137 是什么原因", "OOMKilled exit code 137", "python 内存 512MiB 限制"]:
            with self.subTest(query=query):
                self.assertIsNone(refused(egress.check_query, turn, query))

    def test_matching_follows_word_boundaries_case_insensitively(self):
        turn = turn_for("")
        egress.observe(turn, {}, {}, "node web01 is down")
        for query in ["WEB01 down", "web01-backup 怎么配", "查web01的日志", "https://x.example/web01/status"]:
            with self.subTest(query=query):
                self.assertIsNotNone(refused(egress.check_query, turn, query))
        for query in ["web010 down", "myweb01 down", "web01x"]:
            with self.subTest(query=query):
                self.assertIsNone(refused(egress.check_query, turn, query))

    def test_taint_applies_to_urls_too(self):
        url = "https://status.example.com/hosts/web01"
        turn = turn_for(f"帮我看下 {url}")
        egress.observe(turn, ENTITY_SCHEMA, {"name": "web01"}, "")
        self.assertIn("内部对象「web01」", refused(egress.check_url, turn, url))
        # 只出现在返回里、用户自己贴过的链接里有它：不算污点
        turn = turn_for(f"帮我看下 {url}")
        egress.observe(turn, {}, {}, "web01 load 9.5")
        self.assertIsNone(refused(egress.check_url, turn, url))

    def test_nothing_is_collected_when_the_turn_cannot_go_online(self):
        turn = registry.Turn()
        egress.observe(turn, ENTITY_SCHEMA, {"name": "payroll-db"}, "web01")
        self.assertNotIn(egress.STATE, turn.usage)


class StrictModeTests(unittest.TestCase):
    def test_deny_stops_going_online_after_a_data_call(self):
        turn = turn_for("")
        with patch.object(egress, "WEB_AFTER_DATA", "deny"):
            self.assertIsNone(refused(egress.check_query, turn, "OOMKilled"))
            egress.observe(turn, {}, {}, "ok")
            self.assertIn("WEB_AFTER_DATA=deny", refused(egress.check_query, turn, "OOMKilled"))
            egress.allow_urls(turn, ["https://docs.example.com/a"])
            self.assertIn("WEB_AFTER_DATA=deny", refused(egress.check_url, turn, "https://docs.example.com/a"))

    def test_screen_keeps_public_searches_working(self):
        turn = turn_for("")
        egress.observe(turn, {}, {}, "ok")
        self.assertIsNone(refused(egress.check_query, turn, "OOMKilled"))

    def test_a_failure_while_collecting_taint_closes_the_turn(self):
        turn = turn_for("")
        egress.poison(turn)
        self.assertIn("出网检查出错", refused(egress.check_query, turn, "OOMKilled"))

    def test_too_much_taint_closes_the_turn_instead_of_forgetting_some(self):
        turn = turn_for("")
        with patch.object(egress, "TAINT_MAX", 3):
            egress.observe(turn, {}, {}, "web01 web02 web03 web04 web05")
        self.assertIn("数据太多", refused(egress.check_query, turn, "OOMKilled"))


class UrlSourceTests(unittest.TestCase):
    """web_fetch 只读本轮搜索结果、用户本轮消息里的链接。"""

    def test_links_from_the_user_message(self):
        found = egress.find_urls("看下 https://docs.example.com/guide/install?x=1#part，"
                                 "还有（https://example.com/a）和 https://en.wikipedia.org/wiki/Foo_(bar) 。")
        self.assertEqual(found, ["https://docs.example.com/guide/install?x=1#part", "https://example.com/a",
                                 "https://en.wikipedia.org/wiki/Foo_(bar)"])

    def test_only_listed_links_pass_and_the_listed_spelling_is_what_gets_read(self):
        approved = "https://docs.example.com/guide/install?x=1#part"
        turn = turn_for(f"看下 {approved}")
        # 等价的写法能认出来，但读的是批准过的原样链接：靠挑写法（编码、端口、协议、斜杠）带不出信息
        for url in ["https://docs.example.com/guide/install?x=1",
                    "http://DOCS.example.com:443/guide/install/?x=1#other",
                    "https://docs.example.com/guide/%69nstall?x=1",
                    "https://docs.example.com:80/%67uide/install?%78=1"]:
            with self.subTest(url=url):
                self.assertEqual(egress.check_url(turn, url), approved)
        for url in ["https://docs.example.com/guide/install?x=2",
                    "https://docs.example.com/guide/install?x=1&leak=web01",
                    "https://docs.example.com/guide/install/web01?x=1",
                    "https://docs.example.com/guide/install",
                    "https://evil.example/collect?d=payroll"]:
            with self.subTest(url=url):
                self.assertIn("只能读取本轮搜索结果里的链接", refused(egress.check_url, turn, url))
        self.assertIn("链接无效", refused(egress.check_url, turn, "javascript:alert(1)"))

    def test_search_results_are_readable_for_this_turn_only(self):
        found = [{"title": "官方文档", "url": "https://kubernetes.io/docs/concepts/", "snippet": "…"}]
        turn = turn_for("")
        with patch.object(web_search, "search", side_effect=lambda q: (q, found)):
            web_search.run_tool({"query": "kubernetes"}, turn)
        self.assertIsNone(refused(egress.check_url, turn, "https://kubernetes.io/docs/concepts/"))
        self.assertIsNotNone(refused(egress.check_url, turn_for(""), "https://kubernetes.io/docs/concepts/"))


class SearchResultLinkTests(unittest.TestCase):
    """本轮搜索结果里原样出现过的链接不查「疑似令牌或哈希」；其余静态规则和污点照查；只在用户消息里的链接全套检查。"""

    UUID = "https://www.ywcsb.vip/blog/01a148f3-80b5-7014-b1fb-dd1ef0865c78.html"
    SHA = "https://github.com/python/cpython/blob/3a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b/README.rst"
    CONTROL = "https://stackoverflow.com/questions/52456337/how-to-check-oomkilled-in-kubernetes-pod"

    def test_uuid_and_sha_links_from_search_results_pass(self):
        turn = turn_for("")
        egress.allow_urls(turn, [self.UUID, self.SHA, self.CONTROL])
        for url in (self.UUID, self.SHA, self.CONTROL):
            with self.subTest(url=url):
                self.assertEqual(egress.check_url(turn, url), url)

    def test_the_same_links_only_in_the_user_message_are_still_refused(self):
        turn = turn_for(f"帮我读一下 {self.UUID} 、{self.SHA} 和 {self.CONTROL}")
        for url in (self.UUID, self.SHA):
            with self.subTest(url=url):
                self.assertEqual(refused(egress.check_url, turn, url),
                                 "链接里含有疑似令牌或哈希，为防止内部信息外泄，已拒绝读取")
        self.assertEqual(egress.check_url(turn, self.CONTROL), self.CONTROL)

    def test_a_link_in_both_is_read_with_the_search_engines_spelling(self):
        mine = self.UUID.replace("https://", "http://")
        turn = turn_for(f"看下 {mine}")
        egress.allow_urls(turn, [self.UUID])
        self.assertEqual(egress.check_url(turn, mine), self.UUID)

    def test_other_static_rules_and_taint_still_apply_to_search_results(self):
        uuid = "01a148f3-80b5-7014-b1fb-dd1ef0865c78"
        cases = [(f"https://example.com/u/wang@example.com/{uuid}", "邮箱"),
                 (f"https://example.com/海右名家/{uuid}", "内部名词「海右名家」"),
                 (f"https://example.com/s?q=%E6%B5%B7%E5%8F%B3%E5%90%8D%E5%AE%B6&id={uuid}", "内部名词「海右名家」"),
                 (f"https://example.com/a?ip=10.0.0.1&id={uuid}", "IP 地址"),
                 (f"https://gitlab.corp/group/{uuid}", "内网域名"),
                 (f"https://example.com/hook?key=sk-abcdefghijklmnop&id={uuid}", "疑似密钥"),
                 (f"https://status.example.com/hosts/web01/{uuid}", "本轮查过的内部对象「web01」"),
                 (f"https://status.example.com/db/payroll-db07/{uuid}", "本轮数据里出现过的标识符「payroll-db07」")]
        with patch.object(egress, "WEB_SEARCH_BLOCKLIST", ["海右名家"]):
            turn = turn_for("")
            egress.allow_urls(turn, [url for url, _ in cases])
            egress.observe(turn, ENTITY_SCHEMA, {"name": "web01"}, "node payroll-db07 restarted")
            for url, label in cases:
                with self.subTest(url=url):
                    reason = refused(egress.check_url, turn, url)
                    self.assertIsNotNone(reason)
                    self.assertIn(label, reason)


# --- 接在真实的 Agent 循环里 ----------------------------------------------------------------

class FakeTool:
    def __init__(self, name, output):
        self.name, self.output, self.calls = name, output, []

    def invoke(self, args):
        self.calls.append(args)
        return self.output


def scripted(script, seen):
    rounds = iter(script)

    class Bound:
        def invoke(self, messages):
            seen.setdefault("system", messages[0].content)
            calls, content = next(rounds)
            return AIMessage(content=content, tool_calls=calls)

    class Model:
        def bind_tools(self, tools):
            seen["tools"] = [tool.name for tool in tools]
            return Bound()

        def invoke(self, messages):
            return Bound().invoke(messages)

    return Model()


def call(tool, cid, **args):
    return [{"name": tool, "args": args, "id": cid}]


LOGS = {"container_logs": {"desc": "看容器日志", "params": {
    "name": {"type": "str", "pattern": "name", "required": True, "desc": "容器名"}}}}
FOUND = [{"title": "官方文档", "url": "https://docs.example.com/oom", "snippet": "OOMKilled 的含义"}]


class LoopTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def run_agent(self, script, question="问题", output="", fetch_on=False, page=None):
        seen = {}
        tool = FakeTool("container_logs", output)
        with patch.object(agent_loop, "build_tools", return_value=[tool]), \
                patch.object(ops_client, "available_tools", return_value=LOGS), \
                patch.object(agent_loop, "chat_model", return_value=scripted(script, seen)), \
                patch.object(web_search, "enabled", return_value=True), \
                patch.object(web_fetch, "enabled", return_value=fetch_on), \
                patch.object(web_fetch, "fetch", side_effect=lambda url: dict(page or {}, url=url,
                                                                               final_url=url)) as fetch, \
                patch.object(web_search, "search", side_effect=lambda q: (q, FOUND)) as search:
            events = list(agent_loop.run(question, "片段", [], allow_web=True))
        return events, seen, search, fetch

    @staticmethod
    def results(events):
        return [p["preview"] for k, p in events if k == "tool_result"]

    def test_internal_names_from_data_calls_do_not_reach_the_search_engine(self):
        script = [(call("container_logs", "1", name="payroll-db"), ""),
                  (call("web_search", "2", query="payroll-db OOMKilled"), ""),
                  (call("web_search", "3", query="web01 OOMKilled"), ""),
                  ([], "完")]
        events, _, search, _ = self.run_agent(script, question="payroll-db 重启了，查一下",
                                              output="web01: payroll-db OOMKilled, exit code 137")
        results = self.results(events)
        self.assertTrue(results[1].startswith("[未搜索] 搜索词里含有本轮查过的内部对象「payroll-db」"))
        self.assertTrue(results[2].startswith("[未搜索] 搜索词里含有本轮数据里出现过的标识符「web01」"))
        search.assert_not_called()

    def test_public_terms_and_user_mentions_still_search(self):
        script = [(call("container_logs", "1", name="kb-app"), ""),
                  (call("web_search", "2", query="web01 OOMKilled exit code 137"), ""),
                  ([], "完")]
        events, _, search, _ = self.run_agent(script, question="web01 上的 kb-app 为什么被杀",
                                              output="web01: kb-app OOMKilled, exit code 137, mem 690MiB")
        self.assertEqual([c.args[0] for c in search.call_args_list], ["web01 OOMKilled exit code 137"])
        self.assertIn("[W1] 官方文档", self.results(events)[1])

    def test_taint_covers_what_the_model_sees_of_a_huge_output(self):
        """几十万字的日志压缩后给模型：留下的尾部里的标识符照样算污点（哪怕原文很长、出现在很后面）。"""
        output = "\n".join(f"line {i} ok" for i in range(60000)) + "\nnode payroll-db07 restarted"
        script = [(call("container_logs", "1", name="kb-app"), ""),
                  (call("web_search", "2", query="payroll-db07 restarted"), ""),
                  ([], "完")]
        events, _, search, _ = self.run_agent(script, output=output)
        self.assertGreater(len(output), egress.SCAN_CHARS)
        search.assert_not_called()
        self.assertIn("「payroll-db07」", self.results(events)[1])

    def test_strict_mode_goes_offline_after_a_data_call(self):
        script = [(call("web_search", "1", query="OOMKilled"), ""),
                  (call("container_logs", "2", name="kb-app"), ""),
                  (call("web_search", "3", query="OOMKilled 137"), ""),
                  ([], "完")]
        with patch.object(egress, "WEB_AFTER_DATA", "deny"):
            events, _, search, _ = self.run_agent(script, output="ok")
        self.assertEqual(search.call_count, 1)
        self.assertIn("WEB_AFTER_DATA=deny", self.results(events)[2])

    @staticmethod
    def search_results(events):
        return [p["preview"] for k, p in events if k == "tool_result" and p["tool"] == "web_search"]

    def test_a_parallel_search_sees_the_same_batch_in_either_order(self):
        """模型在同一条回复里并行发出搜索和数据类调用：不管谁排在前面，同批的 x-entity 实参都先登记成污点。"""
        search, data = call("web_search", "s", query="kb-app OOMKilled"), call("container_logs", "d", name="kb-app")
        for batch in (search + data, data + search):
            with self.subTest(order=[c["name"] for c in batch]), self.assertLogs("kb", level="INFO") as logged:
                events, _, searched, _ = self.run_agent([(batch, ""), ([], "完")], output="ok")
            searched.assert_not_called()
            self.assertTrue(self.search_results(events)[0].startswith(
                "[未搜索] 搜索词里含有本轮查过的内部对象「kb-app」"))
            # 被拒时记一行日志：规则类别和命中的词
            self.assertIn("web search refused by egress rule taint:entity: kb-app", "\n".join(logged.output))

    def test_strict_mode_covers_the_same_batch_in_either_order(self):
        search, data = call("web_search", "s", query="OOMKilled"), call("container_logs", "d", name="kb-app")
        with patch.object(egress, "WEB_AFTER_DATA", "deny"):
            for batch in (search + data, data + search):
                with self.subTest(order=[c["name"] for c in batch]):
                    events, _, searched, _ = self.run_agent([(batch, ""), ([], "完")], output="ok")
                    searched.assert_not_called()
                    self.assertIn("WEB_AFTER_DATA=deny", self.search_results(events)[0])
            # 同批没有数据类调用：照常搜
            _, _, searched, _ = self.run_agent([(search, ""), ([], "完")])
            self.assertEqual(searched.call_count, 1)

    def test_a_broken_taint_collector_fails_closed(self):
        script = [(call("container_logs", "1", name="kb-app"), ""),
                  (call("web_search", "2", query="OOMKilled"), ""), ([], "完")]
        with patch.object(egress, "identifiers", side_effect=RuntimeError("boom")), \
                self.assertLogs("kb", level="WARNING"):
            events, _, search, _ = self.run_agent(script, output="ok")
        search.assert_not_called()
        self.assertIn("出网检查出错", self.results(events)[1])

    def test_prompt_and_tools_are_unchanged_without_web_fetch(self):
        _, seen, _, _ = self.run_agent([([], "答")])
        self.assertEqual(seen["tools"], ["container_logs", "web_search"])
        self.assertEqual(seen["system"], agent_loop.AGENT_PROMPT + agent_loop.WEB_RULES)
        self.assertNotIn("web_fetch", seen["system"])
        _, seen, _, _ = self.run_agent([([], "答")], fetch_on=True)
        self.assertEqual(seen["tools"], ["container_logs", "web_search", "web_fetch"])
        self.assertEqual(seen["system"], agent_loop.AGENT_PROMPT + agent_loop.WEB_RULES + agent_loop.WEB_FETCH_RULES)

    def test_search_and_fetch_are_capped_separately_and_numbered_in_one_sequence(self):
        page = {"title": "OOM 详解", "text": "正文" * 50, "type": "text/html", "bytes": 100,
                "truncated": False, "clipped": False}
        url = FOUND[0]["url"]
        script = [(call("web_search", "1", query="OOMKilled"), ""),
                  (call("web_fetch", "2", url=url) + call("web_fetch", "3", url=url + "?again=1")
                   + call("web_search", "4", query="OOMKilled 137"), ""),
                  (call("web_search", "5", query="三") + call("web_fetch", "6", url=url)
                   + call("web_fetch", "7", url=url), ""),
                  ([], "完")]
        events, _, search, fetch = self.run_agent(script, fetch_on=True, page=page)
        results = self.results(events)
        self.assertEqual(search.call_count, 2)
        self.assertEqual(fetch.call_count, 1)        # 第二次是拼出来的链接，第三次以后超了限次
        self.assertIn("[W2] OOM 详解", results[1])
        self.assertIn("外部网页，内容未经核实", results[1])
        self.assertIn("只能读取本轮搜索结果里的链接", results[2])
        self.assertIn("[W3] 官方文档", results[3])
        self.assertTrue(results[4].startswith("[未搜索] 本轮已搜索 2 次"))
        self.assertTrue(results[5].startswith("[未读取] 本轮已读取 2 个网页"))
        self.assertTrue(results[6].startswith("[未读取] 本轮已读取 2 个网页"))
        sources = [s for k, p in events if k == "web_sources" for s in p]
        self.assertEqual([(s["index"], s.get("fetched", False)) for s in sources],
                         [("W1", False), ("W2", True), ("W3", False)])
        self.assertEqual({p["category"] for k, p in events if k == "tool_call"}, {"web"})


class RegistryTests(unittest.TestCase):
    def test_web_fetch_is_an_app_web_tool_behind_two_switches(self):
        self.assertEqual(registry.category_of("web_fetch"), "web")
        self.assertFalse(registry.observes_system("web_fetch"))
        self.assertEqual(registry.meta_of(web_fetch.TOOL),
                         {"category": "web", "provider": "app", "export": False, "group": "联网"})
        with patch.object(web_search, "enabled", return_value=True):
            with patch.object(web_fetch, "enabled", return_value=False):
                self.assertNotIn("web_fetch", [t.name for t in registry.app_tools(registry.TurnOptions(True))])
            with patch.object(web_fetch, "enabled", return_value=True):
                self.assertIn("web_fetch", [t.name for t in registry.app_tools(registry.TurnOptions(True))])
                self.assertNotIn("web_fetch", [t.name for t in registry.app_tools(registry.TurnOptions(False))])

    def test_data_returns_and_sandbox_output_taint_but_only_data_arguments_do(self):
        """返回（输出）里的标识符：数据类和计算类（沙箱输出）都算；x-entity 实参、「本轮查过内部数据」只有数据类。"""
        self.assertEqual([c for c, p in registry.POLICIES.items() if p.taints], ["data", "compute"])
        self.assertEqual([c for c, p in registry.POLICIES.items() if p.taint_args], ["data"])

    def test_per_tool_limits_keep_the_category_total_for_stats(self):
        turn = registry.Turn()
        for _ in range(2):
            self.assertIsNone(turn.admit("web", "web_search"))
            self.assertIsNone(turn.admit("web", "web_fetch", web_fetch.LIMIT_NOTE))
        self.assertEqual(turn.admit("web", "web_search"), "[未搜索] 本轮已搜索 2 次，请基于已有结果作答")
        self.assertEqual(turn.admit("web", "web_fetch", web_fetch.LIMIT_NOTE),
                         "[未读取] 本轮已读取 2 个网页，请基于已有结果作答")
        self.assertEqual(turn.usage["calls"], {"web": 4})
        # 其余类别照旧按类别合计
        for _ in range(3):
            self.assertIsNone(turn.admit("knowledge", "kb_search"))
        self.assertIsNotNone(turn.admit("knowledge", "kb_read"))


# --- 外部数据类工具：实参也是出网通道 -----------------------------------------------------------------

def external(entry):
    return {**entry, "_meta": {"doc2sop": {"category": "data", "provider": "ops", "external": True}},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}}


DATA_TOOLS = {
    **LOGS,
    "doc_search": external({"desc": "查公网上的产品文档", "params": {
        "query": {"type": "str", "pattern": "name", "required": True, "desc": "检索词"}}}),
    "holiday_calendar": external({"desc": "法定节假日", "params": {
        "year": {"type": "int", "required": True, "min": 2007, "max": 2035, "desc": "年份"}}}),
}


class ExternalToolTests(unittest.TestCase):
    """工具服务标了 external 的数据类工具：字符串实参照搜索词的规则检查，返回标成外部资料，实参和返回都不记污点。"""

    def setUp(self):
        clear_graph()

    def run_agent(self, script, question="问题", outputs=None, allow_web=False, tools=DATA_TOOLS):
        seen, messages = {}, []
        fakes = {name: FakeTool(name, (outputs or {}).get(name, f"{name} ok")) for name in tools}
        rounds = iter(script)

        class Bound:
            def invoke(self, view):
                seen.setdefault("system", view[0].content)
                messages.append(list(view))
                calls, content = next(rounds)
                return AIMessage(content=content, tool_calls=calls)

        class Model:
            def bind_tools(self, bound):
                seen["tools"] = [tool.name for tool in bound]
                return Bound()

        with patch.object(agent_loop, "build_tools", return_value=list(fakes.values())), \
                patch.object(ops_client, "available_tools", return_value=tools), \
                patch.object(agent_loop, "chat_model", return_value=Model()), \
                patch.object(web_search, "enabled", return_value=True), \
                patch.object(web_fetch, "enabled", return_value=False), \
                patch.object(egress, "start", wraps=egress.start) as started, \
                patch.object(web_search, "search", side_effect=lambda q: (q, FOUND)) as search:
            events = list(agent_loop.run(question, "片段", [], allow_web=allow_web))
        seen["started"] = started.call_count
        return events, seen, fakes, search, messages

    @staticmethod
    def results(events):
        return [(p["tool"], p["preview"]) for k, p in events if k == "tool_result"]

    def test_string_arguments_are_screened_and_checked_against_this_turns_taint(self):
        """联网关着也一样：外部工具本身就是出网通道。内部对象名、IP 发不出去，公开的通用词照常。"""
        script = [(call("container_logs", "1", name="payroll-db"), ""),
                  (call("doc_search", "2", query="payroll-db") + call("doc_search", "3", query="web01")
                   + call("doc_search", "4", query="10.0.0.5"), ""),
                  (call("doc_search", "5", query="OOMKilled"), ""),
                  ([], "完")]
        with self.assertLogs("kb", level="INFO") as logged:
            events, seen, fakes, _, _ = self.run_agent(script, outputs={"container_logs": "web01: payroll-db OOMKilled"})
        results = [preview for _, preview in self.results(events)]
        self.assertTrue(results[1].startswith("[未执行] 参数里含有本轮查过的内部对象「payroll-db」"), results[1])
        self.assertIn("已拒绝调用外部服务 doc_search", results[1])
        self.assertTrue(results[2].startswith("[未执行] 参数里含有本轮数据里出现过的标识符「web01」"), results[2])
        self.assertTrue(results[3].startswith("[未执行] 参数里含有IP 地址"), results[3])
        self.assertEqual(fakes["doc_search"].calls, [{"query": "OOMKilled"}])
        self.assertEqual(seen["started"], 1)
        self.assertIn("external tool doc_search refused by egress rule taint:entity: payroll-db", "\n".join(logged.output))

    def test_returns_are_external_material_and_add_no_taint(self):
        script = [(call("doc_search", "1", query="ingress-nginx"), ""),
                  (call("web_search", "2", query="ingress-nginx 504"), ""),
                  ([], "完")]
        events, seen, fakes, search, messages = self.run_agent(
            script, allow_web=True, outputs={"doc_search": "ingress-nginx 504 调大 proxy-read-timeout"})
        self.assertEqual(search.call_count, 1)        # 外部的实参、返回都不是内部数据，不记污点
        tool_message = messages[1][-1]
        self.assertTrue(tool_message.content.startswith(agent_loop.EXTERNAL_HEAD))
        self.assertEqual(self.results(events)[0], ("doc_search", "ingress-nginx 504 调大 proxy-read-timeout"))
        self.assertIn("**外部工具**（doc_search、holiday_calendar）", seen["system"])

    def test_integer_arguments_are_not_affected_even_in_strict_mode(self):
        """holiday_calendar 的 year 是整数：没有内容会被带出去，什么都不查，严格模式下也照常。"""
        script = [(call("container_logs", "1", name="kb-app"), ""),
                  (call("holiday_calendar", "2", year=2026), ""),
                  (call("doc_search", "3", query="OOMKilled"), ""),
                  ([], "完")]
        with patch.object(egress, "WEB_AFTER_DATA", "deny"):
            events, _, fakes, _, _ = self.run_agent(script)
        self.assertEqual(fakes["holiday_calendar"].calls, [{"year": 2026}])
        self.assertEqual(fakes["doc_search"].calls, [])
        self.assertIn("WEB_AFTER_DATA=deny", self.results(events)[2][1])

    def test_nothing_changes_without_external_tools(self):
        """没有外部工具、也没联网：不建出网状态，提示词一字不差。"""
        events, seen, fakes, _, _ = self.run_agent([(call("container_logs", "1", name="kb-app"), ""), ([], "完")],
                                                   tools=LOGS)
        self.assertEqual(seen["started"], 0)
        self.assertEqual(seen["system"], agent_loop.AGENT_PROMPT + agent_loop.NO_WEB_RULES)
        self.assertEqual(fakes["container_logs"].calls, [{"name": "kb-app"}])

    def test_the_registry_reads_the_mark_from_the_tool_service(self):
        with patch.object(ops_client, "available_tools", return_value=DATA_TOOLS):
            data = registry.data_tools()
        self.assertTrue(registry.is_external(data["doc_search"]))
        self.assertFalse(registry.is_external(data["container_logs"]))
        self.assertNotIn("external", registry.meta_of(data["container_logs"]))


if __name__ == "__main__":
    unittest.main()
