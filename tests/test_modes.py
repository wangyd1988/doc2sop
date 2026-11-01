"""页面上的两种回答模式：知识库模式（原来的行为）和智能模式（docs/工具.md「知识库模式与智能模式」）。

钉住几件事：
- 知识库模式、以及智能模式总开关关着时，发给模型的系统提示词和工具清单和原来一字不差；
- 智能模式只换掉「回答依据」那几句和检索方式，硬规则（本组织的事先查知识库、通用知识标 [💡]）都在；
- /api/ask 的开关：不可用就拒绝、不悄悄退回；「▶ 执行」沿用知识库模式的规则；每条消息记下模式；
- 标了通用知识的内容进不了 SOP 的结论和检查点，存进知识库时写明未经核实；
- 评测脚本的 --answer-mode 和模式指标。
"""
import json
import unittest
from unittest.mock import patch

from tests.support import FakeReply
from tests.test_grow import GROWN, TOOLS, SwitchedOn, investigation
from tests.test_kb_tools import AskCase, KbLoopCase, Scripted, hit, kb_call, run_eval

from app import conversations, playbooks, workbench
from app import main as app_main
from app.agent import grow, modes
from app.agent import loop as agent_loop

GK_ANSWER = "调休按公司规定计入请假天数 [1]。\n\n一般来说，补班日是为了凑齐连休而调整的工作日 [💡]。"


class ModeHelpersTests(unittest.TestCase):
    def test_general_marks_are_recognised_in_their_usual_forms(self):
        for text in ("一般来说如此 [💡]", "一般来说如此 [💡通用知识]", "一般来说如此 【💡】", "如此 [ 💡 通用知识，未经核实 ]"):
            self.assertTrue(modes.uses_general(text), text)
        for text in ("年假 5 天 [1]", "见 [W2]", "💡 小提示：先看文档", "", None):
            self.assertFalse(modes.uses_general(text), text)

    def test_strip_general_drops_whole_lines(self):
        text = "结论：kb-app 因 OOM 被杀 [1]。\n- 退出码 137 [💡]\n- 内存上限 256MB\n\n\n\n通常 OOM 是内存不够 [💡]"
        self.assertEqual(modes.strip_general(text), "结论：kb-app 因 OOM 被杀 [1]。\n- 内存上限 256MB")
        self.assertEqual(modes.strip_general("全是通用知识 [💡]"), "")

    def test_history_only_counts_the_assistant(self):
        self.assertFalse(modes.history_uses_general([("user", "[💡] 是什么"), ("assistant", "是标记 [1]")]))
        self.assertTrue(modes.history_uses_general([("user", "q"), ("assistant", GK_ANSWER)]))
        self.assertFalse(modes.history_uses_general([]))


class SmartPromptTests(unittest.TestCase):
    """智能模式的提示词 = 同一份基础提示词换掉几句；换回去就是知识库模式的原文。"""

    def test_swapping_back_gives_the_knowledge_mode_text(self):
        for key, base, smart in (("agent", agent_loop.AGENT_PROMPT, agent_loop.SMART_AGENT_PROMPT),
                                 ("web", agent_loop.WEB_RULES, agent_loop.SMART_WEB_RULES),
                                 ("no_web", agent_loop.NO_WEB_RULES, agent_loop.SMART_NO_WEB_RULES)):
            restored = smart
            for old, new in agent_loop.SMART_SWAPS[key]:
                self.assertEqual(smart.count(new), 1, new[:20])
                restored = restored.replace(new, old)
            self.assertEqual(restored, base, key)
        self.assertEqual(agent_loop.KNOWLEDGE, agent_loop.Basis(agent_loop.AGENT_PROMPT, "", agent_loop.WEB_RULES,
                                                                agent_loop.NO_WEB_RULES, agent_loop.NO_PREFETCH))

    def test_training_knowledge_sentences_are_kept_in_knowledge_mode_only(self):
        self.assertIn("不要用你自己的训练知识补充事实", agent_loop.WEB_RULES)
        self.assertIn("**也不要用你自己的训练知识补答案**", agent_loop.NO_WEB_RULES)
        self.assertNotIn("训练知识补充事实", agent_loop.SMART_WEB_RULES)
        self.assertNotIn("也不要用你自己的训练知识补答案", agent_loop.SMART_NO_WEB_RULES)
        for text in (agent_loop.SMART_WEB_RULES, agent_loop.SMART_NO_WEB_RULES, agent_loop.SMART_AGENT_PROMPT):
            self.assertIn("[💡]", text)
        self.assertIn("以知识库为准", agent_loop.SMART_WEB_RULES)

    def test_hard_rules_are_spelled_out(self):
        nudge = agent_loop.SMART_NO_PREFETCH
        for words in ("本组织的规定、流程、阈值、内部系统、内部名词", "必须先调用 kb_search 查到原文、按 [编号] 引用",
                      "联网开着就搜，关着就说明无法确定", "没调用过 kb_search，就不能说「知识库里没有」"):
            self.assertIn(words, nudge)
        rules = agent_loop.SMART_RULES
        for words in ("不能拿常识顶上", "句末标 [💡]", "通用知识，未经核实", "以知识库为准", "结论只依据工具数据和知识库",
                      "前几轮标了 [💡] 的内容仍是通用知识", "拿不准是不是本组织的问题，先查知识库"):
            self.assertIn(words, rules)
        self.assertTrue(modes.uses_general(agent_loop.GENERAL_TAG))
        self.assertIn("不能当依据", agent_loop.GENERAL_HISTORY_RULES)

    def test_rules_learned_from_the_production_eval(self):
        """生产评测里漏查的题：拿 SOP 检查点、或者常识（429）顶替知识库原文；还有没查过就说「知识库里没有」。"""
        nudge, rules = agent_loop.SMART_NO_PREFETCH, agent_loop.SMART_RULES
        for text in (nudge, rules):
            self.assertIn("检查点", text)
            self.assertIn("代替原文", text)
            self.assertIn("报错码、接口、配置项、系统名", text)
            self.assertIn("比如 429 可能是公司网关的限流", text)
            self.assertIn("明显与本组织无关的通用概念", text)
        self.assertIn("执行 SOP 时照它判断数据", rules)
        self.assertIn("依据原句也只是摘录", rules)
        self.assertIn("联网关着、又答不了的实时问题，只说明联网关着、无法确定", rules)
        self.assertIn("**没调用过 kb_search，就不能说「知识库里没有」「知识库里没有检索到」之类的话**", rules)
        self.assertIn("没调用过 kb_search 的（实时信息、公开资料），开头只说「以下内容来自网络搜索」，不要提知识库",
                      agent_loop.SMART_WEB_RULES)
        self.assertIn("本组织的问题先用 kb_search 查", agent_loop.SMART_WEB_RULES)
        self.assertIn("没调用过 kb_search 就不要提知识库", agent_loop.SMART_NO_WEB_RULES)
        self.assertIn("查过知识库也没有的，直说没有相关内容", agent_loop.SMART_NO_WEB_RULES)
        self.assertIn("查过知识库也没有的，直说没有", agent_loop.SMART_AGENT_PROMPT)

    def test_a_drifted_base_prompt_fails_loudly(self):
        with self.assertRaises(RuntimeError):
            agent_loop._swap("改过的提示词", agent_loop.SMART_SWAPS["agent"])
        with self.assertRaises(RuntimeError):
            agent_loop._swap("甲甲", [("甲", "乙")])


class SmartLoopTests(KbLoopCase):
    def test_knowledge_mode_prompts_are_unchanged(self):
        model = Scripted([([], "答")])
        self.run_loop(model, kb_tools=True)
        system, prompt = self.system_and_prompt(model)
        self.assertEqual(system, agent_loop.AGENT_PROMPT + agent_loop.KB_RULES + agent_loop.NO_WEB_RULES)
        self.assertIn("知识库片段：\n片段", prompt)
        model = Scripted([([], "答")])
        self.run_loop(model, context=None, kb_tools=True)
        self.assertIn(agent_loop.NO_PREFETCH, self.system_and_prompt(model)[1])

    def test_smart_mode_swaps_the_answer_basis_and_keeps_the_tools(self):
        kb_model, smart_model = Scripted([([], "答")]), Scripted([([], "答")])
        self.run_loop(kb_model, context=None, kb_tools=True)
        self.run_loop(smart_model, context=None, kb_tools=True, smart=True)
        system, prompt = self.system_and_prompt(smart_model)
        self.assertEqual(system, agent_loop.SMART_AGENT_PROMPT + agent_loop.KB_RULES + agent_loop.SMART_RULES
                         + agent_loop.SMART_NO_WEB_RULES)
        self.assertIn(agent_loop.SMART_NO_PREFETCH, prompt)
        self.assertNotIn(agent_loop.NO_PREFETCH, prompt)
        self.assertEqual(smart_model.binds, kb_model.binds)          # 工具清单一样：模式只改提示词和检索方式

    def test_smart_mode_with_web_uses_the_smart_web_rules(self):
        model = Scripted([([], "答")])
        with patch.object(agent_loop.web_search, "enabled", return_value=True):
            self.run_loop(model, context=None, kb_tools=True, smart=True, allow_web=True)
        system = self.system_and_prompt(model)[0]
        self.assertTrue(system.endswith(agent_loop.SMART_WEB_RULES))
        self.assertIn("web_search", model.binds[0]["tools"])

    def test_knowledge_mode_after_smart_turns_gets_the_history_rule(self):
        history = [("user", "调休怎么算"), ("assistant", GK_ANSWER)]
        model = Scripted([([], "答")])
        with patch.object(agent_loop, "build_tools", return_value=[]), \
                patch.object(agent_loop, "chat_model", return_value=model), \
                patch.object(agent_loop.kb.retrieval, "retrieve", return_value=[]):
            list(agent_loop.run("那病假呢", "片段", history, kb_tools=True))
        system = self.system_and_prompt(model)[0]
        self.assertEqual(system, agent_loop.AGENT_PROMPT + agent_loop.KB_RULES + agent_loop.NO_WEB_RULES
                         + agent_loop.GENERAL_HISTORY_RULES)
        # 智能模式本来就允许通用知识：规则写在 SMART_RULES 里，不再接这一段
        model = Scripted([([], "答")])
        with patch.object(agent_loop, "build_tools", return_value=[]), \
                patch.object(agent_loop, "chat_model", return_value=model), \
                patch.object(agent_loop.kb.retrieval, "retrieve", return_value=[]):
            list(agent_loop.run("那病假呢", None, history, kb_tools=True, smart=True))
        self.assertNotIn(agent_loop.GENERAL_HISTORY_RULES, self.system_and_prompt(model)[0])

    def test_smart_mode_lets_the_model_search_and_numbers_from_one(self):
        model = Scripted([(kb_call("调休 补班 请假天数"), ""), ([], "要计入 [1]")])
        events, retrieve = self.run_loop(model, context=None, kb_tools=True, smart=True,
                                         results=[[hit("p:3", 1, location="休假管理制度.md")]])
        self.assertEqual(retrieve.call_args.args, ("调休 补班 请假天数",))
        self.assertEqual([c["index"] for k, p in events if k == "kb_sources" for c in p], [1])
        self.assertEqual([p for k, p in events if k == "delta"], ["要计入 [1]"])


class SmartAskTests(AskCase):
    """/api/ask 的回答模式：answer_mode 字段，普通用户可用；智能模式不可用时拒绝。"""

    def smart_ask(self, body, **switches):
        defaults = {"SMART_MODE": True, "KB_TOOLS": True}
        defaults.update(switches)
        return self.ask(body, **defaults)

    def test_default_is_the_knowledge_mode_and_unchanged(self):
        response, retrieved = self.ask({"question": "年假几天"}, KB_TOOLS=True)
        events = self.events(response)
        self.assertEqual(sorted(events[0]), ["conversation", "execution_id", "model", "retrieval_mode"])
        self.assertEqual((retrieved, self.calls[0]["smart"]), (1, False))
        replay = self.client.get(f"/api/conversations/{events[0]['conversation']['id']}", auth=self.auth).json()
        self.assertEqual([m["mode"] for m in replay["messages"]], ["kb", "kb"])

    def test_refused_when_the_switch_is_off(self):
        response, retrieved = self.ask({"question": "调休怎么算", "answer_mode": "smart"}, KB_TOOLS=True)
        self.assertEqual(response.status_code, 409)
        self.assertIn("SMART_MODE", response.json()["detail"])
        self.assertEqual((retrieved, self.calls), (0, []))
        self.assertEqual(self.client.get("/api/conversations", auth=self.auth).json()["conversations"], [])

    def test_refused_without_what_it_needs(self):
        for switches, words in (({"AGENT_MODE": "off"}, "AGENT_MODE=off"), ({"KB_TOOLS": False}, "KB_TOOLS")):
            with self.subTest(switches=switches):
                response, _ = self.smart_ask({"question": "q", "answer_mode": "smart"}, **switches)
                self.assertEqual(response.status_code, 409)
                self.assertIn(words, response.json()["detail"])
        self.assertEqual(self.calls, [])

    def test_not_combined_with_the_eval_override(self):
        response, _ = self.smart_ask({"question": "q", "answer_mode": "smart", "retrieval_mode": "prefetch"},
                                     headers={"X-Eval-Token": "anything"})
        self.assertEqual(response.status_code, 400)
        response, _ = self.smart_ask({"question": "q", "answer_mode": "fancy"})
        self.assertEqual(response.status_code, 422)

    def test_smart_mode_lets_the_model_decide(self):
        response, retrieved = self.smart_ask({"question": "知识库里都有什么", "answer_mode": "smart"})
        self.assertEqual(response.status_code, 200)
        call = self.calls[0]
        self.assertEqual(retrieved, 0)                                     # 不预检索，也不走「概览」的捷径
        self.assertEqual((call["smart"], call["context"], call["hits"], call["force_search"], call["kb_tools"]),
                         (True, None, [], False, True))
        events = self.events(response)
        self.assertEqual((events[0]["answer_mode"], events[0]["retrieval_mode"]), ("smart", "agentic"))
        replay = self.client.get(f"/api/conversations/{events[0]['conversation']['id']}", auth=self.auth).json()
        self.assertEqual([m["mode"] for m in replay["messages"]], ["smart", "smart"])

    def test_switching_modes_inside_one_conversation(self):
        first, _ = self.smart_ask({"question": "调休怎么算", "answer_mode": "smart"},
                                  events=(("delta", GK_ANSWER),))
        conversation_id = self.events(first)[0]["conversation"]["id"]
        second, retrieved = self.smart_ask({"question": "那病假呢", "conversation_id": conversation_id})
        self.assertEqual((retrieved, self.calls[1]["smart"]), (1, False))      # 下一条按知识库模式：先检索
        self.assertEqual(self.events(second)[0]["answer_mode"], "kb")
        replay = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        self.assertEqual([m["mode"] for m in replay["messages"]], ["smart", "smart", "kb", "kb"])

    def test_knowledge_mode_keeps_its_retrieval_when_the_switch_is_on(self):
        """总开关打开后，知识库模式的这一轮和开关关着时一模一样（只多了首行的 answer_mode）。"""
        self.ask({"question": "年假几天"}, KB_TOOLS=True)
        self.smart_ask({"question": "年假几天", "answer_mode": "kb"})
        fixed = [{k: v for k, v in call.items() if k not in ("thread_id", "execution_id")} for call in self.calls]
        self.assertEqual(fixed[0], fixed[1])

    def test_playbook_runs_keep_the_knowledge_rules(self):
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        pid = playbooks.save(None, "巡检", "", [{"tool": "host_disk", "args": {}}], {"host_disk"})
        response, retrieved = self.smart_ask({"question": "执行 SOP《巡检》", "playbook_id": pid, "answer_mode": "smart"},
                                             ops=True)
        self.assertEqual((retrieved, self.calls[0]["smart"]), (1, False))     # 照知识库模式：先检索、不许通用知识
        events = self.events(response)
        self.assertEqual((events[0]["answer_mode"], events[0]["retrieval_mode"]), ("smart", "prefetch"))
        replay = self.client.get(f"/api/conversations/{events[0]['conversation']['id']}", auth=self.auth).json()
        self.assertEqual(replay["messages"][-1]["mode"], "smart")             # 仍记下当时选的模式

    def test_documents_report_whether_smart_mode_is_usable(self):
        with patch.object(app_main, "SMART_MODE", False):
            status = self.client.get("/api/documents", auth=self.auth).json()["smart_mode"]
        self.assertEqual(status["available"], False)
        self.assertIn("SMART_MODE", status["reason"])
        with patch.object(app_main, "SMART_MODE", True), patch.object(app_main, "KB_TOOLS", True), \
                patch.object(app_main, "AGENT_MODE", "auto"):
            status = self.client.get("/api/documents", auth=self.auth).json()["smart_mode"]
        self.assertEqual(status, {"available": True, "reason": ""})

    def test_old_messages_replay_as_knowledge_mode(self):
        conversation = conversations.create("老对话")
        with conversations.lock:
            conversations.db.execute(
                "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, 'assistant', '答', 't')",
                (conversation["id"],))
            conversations.db.commit()
        replay = self.client.get(f"/api/conversations/{conversation['id']}", auth=self.auth).json()
        self.assertEqual(replay["messages"][0]["mode"], "kb")
        self.assertEqual(conversations.modes_used(conversation["id"]), ["kb"])

    def test_workbench_does_not_call_smart_conversations_knowledge_only(self):
        """工作台「最近」原来没调数据工具的都写「只查了知识库」：智能模式的对话要标出来。"""
        smart, _ = self.smart_ask({"question": "Kafka 是什么", "answer_mode": "smart"})
        plain, _ = self.smart_ask({"question": "年假几天"})
        recent = {item["id"]: item for item in workbench._recent()}
        self.assertTrue(recent[self.events(smart)[0]["conversation"]["id"]]["smart"])
        self.assertFalse(recent[self.events(plain)[0]["conversation"]["id"]]["smart"])


class GeneralKnowledgeStaysOutTests(SwitchedOn):
    """标了 [💡] 的内容不能成为 SOP 的结论、检查点的依据。"""

    def propose(self, answer):
        execution, _ = investigation(answer=answer)
        with patch.object(grow, "chat_model") as factory:
            factory.return_value.invoke.return_value = FakeReply(GROWN)
            proposal = grow.propose(execution["id"], answer, TOOLS)
        return proposal, factory

    def test_marked_lines_never_reach_the_sop_model(self):
        answer = ("结论：kb-app 因 OOM 被杀——退出码 137，内存上限 256MB 远低于文档要求的 1GB [1]。\n"
                  "一般来说，Java 应用的堆最好设成容器内存的 75% [💡]。\n建议把 mem_limit 调到 1g 后观察。")
        proposal, factory = self.propose(answer)
        self.assertIsNotNone(proposal)
        fed = factory.return_value.invoke.call_args.args[0][1][1]
        self.assertIn("退出码 137", fed)
        self.assertNotIn("75%", fed)
        self.assertNotIn("💡", fed)

    def test_an_answer_that_is_only_general_knowledge_is_not_grown(self):
        proposal, factory = self.propose("一般来说容器重启多半是 OOM，把内存调大一点就行了，再观察一下看看 [💡]。")
        self.assertIsNone(proposal)
        factory.return_value.invoke.assert_not_called()


class WebNoteTests(unittest.TestCase):
    def test_general_marks_are_written_out_when_saved_to_the_knowledge_base(self):
        note = app_main.WebNote(title="t", question="q", answer="甲 [W1]。\n乙 [💡]。\n丙 [1]",
                                sources=[{"index": "W1", "location": "l", "url": "https://a.example/x"}])
        text = app_main.web_note_markdown(note, "tester", "2026-11-01")
        self.assertIn("乙 （💡 通用知识，未经核实）。", text)
        self.assertNotIn("[💡]", text)
        self.assertIn("甲 [W1]", text)


class EvalAnswerModeTests(unittest.TestCase):
    def lines(self, *events):
        return [json.dumps(e, ensure_ascii=False).encode() for e in events]

    def test_request_carries_the_page_mode_without_the_eval_token(self):
        self.assertEqual(run_eval.request_body("q", answer_mode="smart"),
                         {"question": "q", "web": False, "answer_mode": "smart"})
        env = {"EVAL_USER": "a", "EVAL_PASSWORD": "b"}
        self.assertEqual(run_eval.parse_args(["--answer-mode", "smart"], environ=env).answer_mode, "smart")
        with patch("sys.stderr"), self.assertRaises(SystemExit):
            run_eval.parse_args(["--answer-mode", "smart", "--mode", "agentic"], environ=env)

    def outcome(self, *events):
        return run_eval.read_events(self.lines({"conversation": {"id": "c"}, "answer_mode": "smart"}, *events),
                                    started=0, clock=lambda: 1.0)

    def test_events_record_the_mode_web_calls_and_sources(self):
        outcome = self.outcome({"sources": []},
                               {"tool_call": {"tool": "kb_search", "args": {"query": "调休"}, "category": "knowledge"}},
                               {"kb_sources": [{"index": 1, "location": "休假管理制度.md"}]},
                               {"tool_call": {"tool": "web_search", "args": {"query": "x"}, "category": "web"}},
                               {"web_sources": [{"index": "W1", "location": "w", "web": True}]},
                               {"delta": "要计入 [1]，另见 [W1]，常识上如此 [💡]，还有 [3] 和 [W4]"})
        self.assertEqual((outcome["answer_mode"], outcome["web_calls"]), ("smart", 1))
        self.assertEqual(run_eval.cited(outcome["answer"], outcome), ({"休假管理制度.md"}, ["[3]", "[W4]"]))
        self.assertTrue(run_eval.searched_kb(outcome))

    def check(self, kind, answer, answer_mode, sources=(), searched=True, web=0, expected=("休假管理制度.md",)):
        events = []
        if searched:
            events.append({"tool_call": {"tool": "kb_search", "args": {}, "category": "knowledge"}})
            events.append({"kb_sources": [{"index": i + 1, "location": s} for i, s in enumerate(sources)]})
        events += [{"tool_call": {"tool": "web_search", "args": {}, "category": "web"}}] * web
        events.append({"delta": answer})
        case = {"id": "x", "type": kind, "expected_sources": list(expected)}
        return run_eval.mode_checks(case, self.outcome(*events), answer_mode)

    def test_internal_questions_must_be_looked_up_and_cited(self):
        self.assertTrue(self.check("internal", "要计入 [1]", "smart", sources=["休假管理制度.md"])["passed"])
        missed = self.check("internal", "一般要计入 [💡]", "smart", searched=False)
        self.assertEqual((missed["passed"], missed["missed"], missed["mark"]), (False, True, "wrong"))
        wrong_doc = self.check("internal", "要计入 [1]", "kb", sources=["别的.md"])
        self.assertEqual((wrong_doc["passed"], wrong_doc["wrong_doc"]), (False, True))
        review = self.check("both", "10 天 [1]；法律也这么规定 [💡]", "smart", sources=["休假管理制度.md"])
        self.assertEqual((review["passed"], review["mark"]), (True, "review"))

    def test_general_questions_by_mode(self):
        self.assertTrue(self.check("general", "知识库里没有相关内容。", "kb", expected=())["passed"])
        leaked = self.check("general", "GIL 是全局解释器锁 [💡]", "kb", expected=())
        self.assertEqual((leaked["passed"], leaked["mark"]), (False, "wrong"))
        self.assertTrue(self.check("general", "GIL 是全局解释器锁 [💡]", "smart", expected=())["passed"])
        unmarked = self.check("general", "GIL 是全局解释器锁", "smart", expected=())
        self.assertEqual((unmarked["passed"], unmarked["mark"]), (False, "missing"))

    def test_realtime_questions_must_not_be_guessed(self):
        self.assertTrue(self.check("realtime", "联网关着，无法确定今天的天气。", "smart", expected=())["passed"])
        guessed = self.check("realtime", "今天北京晴，25 度 [💡]", "smart", expected=())
        self.assertEqual((guessed["passed"], guessed["mark"]), (False, "wrong"))
        self.assertTrue(self.check("realtime", "今天北京晴 [W1]", "smart", web=1, expected=())["passed"])

    def test_metrics_list_the_failures(self):
        records = [{"id": "a", "type": "internal", "checks": self.check("internal", "一般要计入 [💡]", "smart", searched=False)},
                   {"id": "b", "type": "general", "checks": self.check("general", "是锁 [💡]", "smart", expected=())},
                   {"id": "c", "type": "general", "checks": self.check("general", "是锁", "smart", expected=())},
                   {"id": "d", "failed": True}]
        metrics = run_eval.mode_metrics(records)
        self.assertEqual((metrics["missed"], metrics["wrong_marks"], metrics["missing_marks"]), (["a"], ["a"], ["c"]))
        self.assertEqual((metrics["general_marked"], metrics["general"]), (1, 2))
        self.assertEqual(metrics["passed"], {"internal": (0, 1), "general": (1, 2)})

    def test_coverage_skips_what_has_no_points(self):
        self.assertFalse(run_eval.coverage_counts({"type": "realtime", "expected_points": []}, "smart"))
        self.assertFalse(run_eval.coverage_counts({"type": "general", "expected_points": ["x"]}, "kb"))
        self.assertTrue(run_eval.coverage_counts({"type": "general", "expected_points": ["x"]}, "smart"))
        self.assertTrue(run_eval.coverage_counts({"type": "fact", "expected_points": ["x"]}))

    def test_the_mode_dataset_is_well_formed(self):
        cases = [json.loads(line) for line in (run_eval.Path(run_eval.__file__).parent / "modes.jsonl")
                 .read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(10 <= len(cases) <= 20)
        self.assertEqual(len({c["id"] for c in cases}), len(cases))
        kinds = {c["type"] for c in cases}
        self.assertEqual(kinds, set(run_eval.MODE_TYPES))
        for case in cases:
            self.assertEqual(bool(case["expected_sources"]), case["type"] in ("internal", "both"), case["id"])


if __name__ == "__main__":
    unittest.main()
