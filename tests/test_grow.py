"""从一次自由排查长出 SOP：什么时候提、生成后怎么把关、怎么去重、批准后怎么落地。

安全线不变：长出来的 SOP 也只能引用已有工具，过不了 playbooks.validate 就不会成为提议。
"""
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import FakeReply, clear_graph

from app import config, conversations, graph, playbooks
from app.agent import grow
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app

NAME = {"name": {"type": "str", "pattern": "name", "required": True}}
TOOLS = {"container_inspect": {"desc": "容器配置", "params": NAME},
         "container_logs": {"desc": "容器日志", "params": {**NAME, "lines": {"type": "int"}}},
         "host_resources": {"desc": "宿主机内存", "params": {}},
         "host_disk": {"desc": "磁盘用量", "params": {}}}
ANSWER = "结论：kb-app 因 OOM 被杀——退出码 137，内存上限 256MB 远低于文档要求的 1GB。建议把 mem_limit 调到 1g 后观察。"
CALLS = [("container_inspect", {"name": "kb-app"}, "镜像=kb:1\n重启次数=5\n内存上限=268435456"),
         ("container_logs", {"name": "kb-app", "lines": 100}, "... worker exited with code 137 (OOMKilled)")]

GROWN = json.dumps([{
    "name": "容器 OOM 排查", "trigger": "容器反复重启、怀疑内存不足",
    "steps": [
        {"tool": "container_inspect", "args": {"name": ""},
         "checkpoint": "重启次数 > 3 且内存上限远低于文档值",
         "evidence": "第 1 次调用 container_inspect 的返回：重启次数=5 内存上限=268435456"},
        {"tool": "container_logs", "args": {"name": "", "pod": "猜的键"},
         "checkpoint": "日志出现 exit code 137 / OOMKilled",
         "evidence": "第 2 次调用 container_logs 的返回：exited with code 137 (OOMKilled)"}]}],
    ensure_ascii=False)


def clear_playbooks():
    with playbooks.lock:
        playbooks.db.execute("DELETE FROM steps")
        playbooks.db.execute("DELETE FROM playbooks")
        playbooks.db.commit()


def investigation(answer=ANSWER, calls=CALLS, playbook_id=None, conversation_id="conv", message_id=1):
    """造一次已经收口的「自由排查」：几次工具调用 + 一个回答。返回 (execution, answer)。"""
    run = graph.start_execution(conversation_id, "kb-app 为什么重启了", playbook_id=playbook_id)
    for tool, args, output in calls:
        graph.record_tool_call(run, tool, args, output, not output.startswith("[执行失败]"), 5,
                               params=TOOLS.get(tool, {}).get("params"))
    graph.finish_execution(run, answer, message_id=message_id)
    return graph.execution(run), answer


def step(tool, **args):
    return {"tool": tool, "args": args, "checkpoint": "看是否异常"}


class SwitchedOn(unittest.TestCase):
    def setUp(self):
        clear_graph()
        clear_playbooks()
        for name, value in (("AUTO_SOP_PROPOSALS", True), ("SOP_PROPOSALS_PER_DAY", 10)):
            p = patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)


class TriggerTests(SwitchedOn):
    def decide(self, execution, answer):
        return grow.should_propose(execution, answer, playbooks.list_all(only_enabled=True))

    def test_free_investigation_with_two_tools_and_a_conclusion_is_proposed(self):
        self.assertEqual(self.decide(*investigation()), (True, ""))

    def test_not_when_switched_off(self):
        with patch.object(config, "AUTO_SOP_PROPOSALS", False):
            self.assertFalse(self.decide(*investigation())[0])

    def test_not_when_the_turn_was_an_sop_run(self):
        self.assertFalse(self.decide(*investigation(playbook_id="pb1"))[0])

    def test_not_when_the_turn_failed_or_observed_nothing(self):
        self.assertFalse(self.decide(*investigation(answer=""))[0])                      # failed
        self.assertFalse(self.decide(*investigation(calls=[("web_search", {"query": "q"}, "x")]))[0])  # unknown
        failed = [(t, a, "[执行失败] 超时") for t, a, _ in CALLS]
        self.assertFalse(self.decide(*investigation(calls=failed))[0])

    def test_not_with_fewer_than_two_distinct_tools(self):
        same = [CALLS[1], ("container_logs", {"name": "kb-app", "lines": 500}, "更多日志")]
        wanted, reason = self.decide(*investigation(calls=same))
        self.assertFalse(wanted)
        self.assertIn("不同工具", reason)

    def test_not_without_a_conclusion(self):
        for answer in ("没查到。", "知识库里没有相关内容，请提供容器名和时间范围，我再帮您查实际数据。" + "详" * 100,
                       "无法判断是否异常" + "，" * 50):
            with self.subTest(answer=answer[:20]):
                self.assertFalse(self.decide(*investigation(answer=answer))[0])

    def test_not_when_the_answer_declares_an_sop(self):
        self.assertFalse(self.decide(*investigation(answer="按 SOP《重启排查》执行\n" + ANSWER))[0])

    def test_not_when_an_enabled_sop_was_followed(self):
        """工具序列按顺序覆盖了某个启用 SOP 的步骤 = 套用了它；停用的不算。"""
        pid = playbooks.save(None, "重启排查", "", [step("container_inspect"), step("container_logs")],
                             set(TOOLS), source="手册.docx")
        wanted, reason = self.decide(*investigation())
        self.assertFalse(wanted)
        self.assertIn("重启排查", reason)
        playbooks.set_enabled(pid, False)
        self.assertTrue(self.decide(*investigation())[0])
        # 顺序反了不算套用
        playbooks.save(pid, "反着来", "", [step("container_logs"), step("container_inspect")], set(TOOLS))
        self.assertTrue(self.decide(*investigation())[0])

    def test_not_when_the_same_trajectory_was_ignored_recently(self):
        execution, answer = investigation()
        pid = graph.add_proposal("new_sop", {"name": "x"}, ["tool_call:1"],
                                 signature="container_inspect>container_logs")
        graph.decide_proposal(pid, "rejected")
        wanted, reason = self.decide(execution, answer)
        self.assertFalse(wanted)
        self.assertIn("忽略", reason)

    def test_not_when_the_same_trajectory_is_already_pending(self):
        graph.add_proposal("new_sop", {"name": "x"}, ["tool_call:1"], signature="container_inspect>container_logs")
        self.assertFalse(self.decide(*investigation())[0])
        # 不同轨迹不受影响
        other = CALLS + [("host_disk", {}, "41%")]
        self.assertTrue(self.decide(*investigation(calls=other))[0])

    def test_daily_cap(self):
        with patch.object(config, "SOP_PROPOSALS_PER_DAY", 1):
            graph.add_proposal("new_sop", {"name": "x"}, ["tool_call:1"], signature="other")
            wanted, reason = self.decide(*investigation())
        self.assertFalse(wanted)
        self.assertIn("上限", reason)

    def test_signature_and_similarity(self):
        self.assertEqual(grow.signature(["a", "a", "b", "a"]), "a>b>a")
        self.assertEqual(grow.similarity("a>b>c", "a>b>c"), 1.0)
        self.assertAlmostEqual(grow.similarity("a>b>c", "a>b"), 0.8)
        self.assertEqual(grow.similarity("", "a"), 0.0)


class GenerateTests(SwitchedOn):
    def grow_with(self, reply, execution=None, answer=ANSWER, tools=TOOLS):
        execution = execution or investigation()[0]
        with patch.object(grow, "chat_model") as factory:
            factory.return_value.invoke.return_value = FakeReply(reply)
            return grow.generate(execution, answer, tools)

    def test_valid_reply_becomes_a_validated_candidate(self):
        got = self.grow_with(GROWN)
        self.assertEqual(got["name"], "容器 OOM 排查")
        self.assertEqual(got["trigger"], "容器反复重启、怀疑内存不足")
        self.assertEqual([s["tool"] for s in got["steps"]], ["container_inspect", "container_logs"])
        self.assertEqual(got["steps"][1]["args"], {"name": ""})            # 猜错的键被丢掉
        self.assertTrue(got["steps"][0]["evidence"].startswith("第 1 次调用 container_inspect"))
        self.assertNotIn("⚠", got["steps"][1]["evidence"])

    def test_invented_tools_are_dropped(self):
        reply = GROWN.replace("container_inspect", "docker_exec")
        got = self.grow_with(reply)
        self.assertEqual([s["tool"] for s in got["steps"]], ["container_logs"])
        only_bad = json.dumps([{"name": "坏", "trigger": "", "steps": [
            {"tool": "rm_rf", "args": {}, "checkpoint": "x", "evidence": ""}]}])
        self.assertIsNone(self.grow_with(only_bad))

    def test_evidence_that_does_not_match_the_trajectory_is_flagged(self):
        cases = {
            "第 5 次调用 container_logs 的返回：x": "⚠ 对不上的依据",   # 没有第 5 次
            "第 1 次调用 container_logs 的返回：x": "⚠ 对不上的依据",   # 第 1 次是 inspect
            "日志里有 OOMKilled": "⚠ 对不上的依据",                     # 不是轨迹引用
            "": "⚠ 未给出依据",
        }
        for quote, expected in cases.items():
            with self.subTest(quote=quote):
                reply = json.dumps([{"name": "甲", "trigger": "", "steps": [
                    {"tool": "container_logs", "args": {}, "checkpoint": "看 137", "evidence": quote}]}],
                    ensure_ascii=False)
                got = self.grow_with(reply)
                self.assertTrue(got["steps"][0]["evidence"].startswith(expected), got["steps"][0]["evidence"])

    def test_model_failure_or_garbage_returns_none(self):
        execution = investigation()[0]
        with patch.object(grow, "chat_model") as factory:
            factory.return_value.invoke.side_effect = RuntimeError("网关超时")
            self.assertIsNone(grow.generate(execution, ANSWER, TOOLS))
        self.assertIsNone(self.grow_with("这不是 JSON", execution))
        self.assertIsNone(self.grow_with("[]", execution))
        self.assertIsNone(self.grow_with('[{"name": "没步骤", "steps": []}]', execution))
        self.assertIsNone(self.grow_with(GROWN, execution, tools={}))

    def test_empty_reply_is_retried_once(self):
        execution = investigation()[0]
        with patch.object(grow, "chat_model") as factory:
            factory.return_value.invoke.side_effect = [FakeReply(""), FakeReply(GROWN)]
            got = grow.generate(execution, ANSWER, TOOLS)
        self.assertEqual(got["name"], "容器 OOM 排查")
        self.assertEqual(factory.return_value.invoke.call_count, 2)

    def test_trajectory_numbers_ops_calls_and_skips_web_search(self):
        calls = [CALLS[0], ("web_search", {"query": "OOMKilled 137"}, "网上说……"), CALLS[1]]
        execution, answer = investigation(calls=calls)
        text = grow.trajectory(execution, answer)
        self.assertIn("第 1 次调用 container_inspect（name=kb-app）的返回：", text)
        self.assertIn("第 2 次调用 container_logs（name=kb-app，lines=100）的返回：", text)
        self.assertNotIn("web_search", text)
        self.assertNotIn("第 3 次", text)
        self.assertIn("最终结论：\n" + ANSWER, text)
        self.assertLessEqual(len(text), grow.TRAJECTORY_CHARS + 200)

    def test_long_outputs_are_condensed_to_fit_the_budget(self):
        huge = "\n".join(f"INFO line {i}" for i in range(3000))
        execution, answer = investigation(calls=[(t, a, huge) for t, a, _ in CALLS] * 2)
        text = grow.trajectory(execution, answer)
        self.assertLessEqual(len(text), grow.TRAJECTORY_CHARS + 500)
        self.assertIn("最终结论", text)


class ProposeTests(SwitchedOn):
    def propose_with(self, reply, execution, answer=ANSWER):
        with patch.object(grow, "chat_model") as factory:
            factory.return_value.invoke.return_value = FakeReply(reply)
            return grow.propose(execution["id"], answer, TOOLS)

    def test_new_sop_proposal_cites_the_tool_calls(self):
        execution, _ = investigation()
        pid = self.propose_with(GROWN, execution)
        proposal = graph.get_proposal(pid)
        self.assertEqual(proposal["kind"], "new_sop")
        self.assertEqual(proposal["execution_id"], execution["id"])
        self.assertEqual(proposal["signature"], "container_inspect>container_logs")
        self.assertEqual(proposal["evidence_refs"], [f"tool_call:{c['id']}" for c in execution["tool_calls"]])
        payload = proposal["payload"]
        self.assertEqual((payload["name"], payload["source"]), ("容器 OOM 排查", "从实践沉淀"))
        self.assertEqual(payload["summary"], {"tools": 2, "calls": 2})
        self.assertEqual(len(payload["steps"]), 2)

    def test_similar_existing_sop_turns_it_into_an_extension(self):
        """候选 [inspect, logs, host_disk] 和已有 [inspect, logs] 相似度 0.8：只提补充 host_disk。"""
        target = playbooks.save(None, "重启排查", "", [step("container_inspect"), step("container_logs")],
                                set(TOOLS), source="手册.docx", enabled=False)
        execution, _ = investigation(calls=CALLS + [("host_disk", {}, "/ 41%")])
        grown = json.loads(GROWN)
        grown[0]["steps"].append({"tool": "host_disk", "args": {}, "checkpoint": "磁盘 < 90%",
                                  "evidence": "第 3 次调用 host_disk 的返回：41%"})
        pid = self.propose_with(json.dumps(grown, ensure_ascii=False), execution)
        proposal = graph.get_proposal(pid)
        self.assertEqual(proposal["kind"], "extend_sop")
        self.assertEqual(proposal["payload"]["target"], {"id": target, "name": "重启排查"})
        self.assertEqual([s["tool"] for s in proposal["payload"]["steps"]], ["host_disk"])
        self.assertGreaterEqual(proposal["payload"]["similarity"], 0.7)

    def test_fully_covered_candidate_is_not_proposed(self):
        playbooks.save(None, "重启排查", "", [step("container_inspect"), step("container_logs"),
                                           step("host_resources")], set(TOOLS), enabled=False)
        execution, _ = investigation()
        self.assertIsNone(self.propose_with(GROWN, execution))
        self.assertEqual(graph.list_proposals(), [])

    def test_nothing_is_proposed_when_the_trigger_says_no(self):
        execution, _ = investigation(playbook_id="pb1")
        with patch.object(grow, "chat_model") as factory:
            self.assertIsNone(grow.propose(execution["id"], ANSWER, TOOLS))
            factory.assert_not_called()     # 连模型都不该调

    def test_schedule_runs_in_the_background_and_swallows_errors(self):
        with patch.object(grow, "propose", side_effect=RuntimeError("炸了")) as propose:
            future = grow.schedule("run", "答", lambda: TOOLS)
            future.result(timeout=5)
        propose.assert_called_once_with("run", "答", TOOLS)
        with patch.object(config, "AUTO_SOP_PROPOSALS", False):
            self.assertIsNone(grow.schedule("run", "答", TOOLS))


class ProposalApiTests(SwitchedOn):
    def setUp(self):
        super().setUp()
        with conversations.lock:
            conversations.db.execute("DELETE FROM messages")
            conversations.db.execute("DELETE FROM conversations")
            conversations.db.commit()
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        tools = patch("app.main.usable_tools", return_value={n: m["desc"] for n, m in TOOLS.items()})
        tools.start()
        self.addCleanup(tools.stop)

    def pending(self, execution, kind="new_sop", **extra):
        payload = {"name": "容器 OOM 排查", "trigger": "容器反复重启", "source": "从实践沉淀",
                   "summary": {"tools": 2, "calls": 2},
                   "steps": [{"tool": "container_inspect", "args": {"name": ""},
                              "checkpoint": "重启次数 > 3", "evidence": "第 1 次调用 container_inspect 的返回：重启次数=5"},
                             {"tool": "container_logs", "args": {"name": ""},
                              "checkpoint": "出现 137", "evidence": "第 2 次调用 container_logs 的返回：137"}],
                   **extra}
        return graph.add_proposal(kind, payload, [f"tool_call:{c['id']}" for c in execution["tool_calls"]],
                                  execution_id=execution["id"], signature="container_inspect>container_logs")

    def test_list_expands_evidence_into_the_actual_tool_output(self):
        execution, _ = investigation()
        pid = self.pending(execution)
        data = self.client.get(f"/api/proposals?execution_id={execution['id']}", auth=self.auth).json()
        self.assertEqual(data["pending"], 1)
        item = data["proposals"][0]
        self.assertEqual((item["id"], item["kind"], item["name"]), (pid, "new_sop", "容器 OOM 排查"))
        self.assertEqual([(e["n"], e["tool"]) for e in item["evidence"]],
                         [(1, "container_inspect"), (2, "container_logs")])
        self.assertIn("重启次数=5", item["evidence"][0]["preview"])
        self.assertEqual(self.client.get("/api/proposals?execution_id=other", auth=self.auth).json()["proposals"], [])

    def test_approve_new_sop_saves_it_disabled_under_the_practice_source(self):
        execution, _ = investigation()
        pid = self.pending(execution)
        response = self.client.post(f"/api/proposals/{pid}/approve", auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        saved = response.json()["playbook"]
        self.assertEqual((saved["source"], saved["enabled"], saved["name"]), ("从实践沉淀", False, "容器 OOM 排查"))
        self.assertEqual([s["tool"] for s in saved["steps"]], ["container_inspect", "container_logs"])
        self.assertEqual(graph.get_proposal(pid)["status"], "approved")
        self.assertEqual(self.client.post(f"/api/proposals/{pid}/approve", auth=self.auth).status_code, 409)
        board = self.client.get("/api/playbooks", auth=self.auth).json()
        self.assertEqual(board["origins"], {"doc": 0, "practice": 1, "manual": 0})
        self.assertEqual(board["pending"], 0)
        self.assertIn("从实践沉淀", [g["name"] for g in board["groups"]])

    def test_approve_extension_appends_only_the_missing_steps(self):
        target = playbooks.save(None, "重启排查", "服务反复重启", [step("container_inspect")],
                                set(TOOLS), source="手册.docx")
        execution, _ = investigation()
        pid = self.pending(execution, kind="extend_sop", target={"id": target, "name": "重启排查"})
        response = self.client.post(f"/api/proposals/{pid}/approve", auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        got = playbooks.get(target)
        self.assertEqual([s["tool"] for s in got["steps"]], ["container_inspect", "container_logs"])
        self.assertEqual((got["source"], got["enabled"], got["trigger"]), ("手册.docx", True, "服务反复重启"))

    def test_approve_fails_cleanly_when_a_tool_is_gone(self):
        execution, _ = investigation()
        pid = self.pending(execution)
        with patch("app.main.usable_tools", return_value={"host_disk": "磁盘"}):
            response = self.client.post(f"/api/proposals/{pid}/approve", auth=self.auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn("不存在的工具", response.json()["detail"])
        self.assertEqual(graph.get_proposal(pid)["status"], "pending")
        self.assertEqual(playbooks.list_all(), [])

    def test_reject_silences_the_same_trajectory(self):
        execution, answer = investigation()
        pid = self.pending(execution)
        self.assertEqual(self.client.post(f"/api/proposals/{pid}/reject", auth=self.auth).json()["status"], "rejected")
        self.assertEqual(self.client.post(f"/api/proposals/{pid}/reject", auth=self.auth).status_code, 409)
        self.assertEqual(self.client.post("/api/proposals/nope/reject", auth=self.auth).status_code, 404)
        again, _ = investigation()
        self.assertFalse(grow.should_propose(again, answer, [])[0])

    def test_replay_carries_the_pending_proposal(self):
        conversation = conversations.create("kb-app 为什么重启了")
        conversations.add_message(conversation["id"], "user", "kb-app 为什么重启了")
        message_id = conversations.add_message(conversation["id"], "assistant", ANSWER)
        execution, _ = investigation(conversation_id=conversation["id"], message_id=message_id)
        pid = self.pending(execution)
        replay = self.client.get(f"/api/conversations/{conversation['id']}", auth=self.auth).json()
        self.assertEqual(replay["messages"][-1]["proposal"]["id"], pid)
        self.assertNotIn("proposal", replay["messages"][0])
        graph.decide_proposal(pid, "rejected")
        replay = self.client.get(f"/api/conversations/{conversation['id']}", auth=self.auth).json()
        self.assertNotIn("proposal", replay["messages"][-1])

    def test_ask_schedules_growth_only_after_an_agent_turn_that_used_tools(self):
        hits = [{"index": 1, "location": "手册.pdf 第 2 页", "text": "内存上限 1GB。", "score": 0.6}]

        def fake_run(question, context, history, **kwargs):
            yield "tool_call", {"tool": "container_inspect", "args": {"name": "kb-app"}}
            yield "tool_result", {"tool": "container_inspect", "preview": "重启次数=5", "lines": 1, "chars": 6}
            yield "delta", ANSWER

        with patch("app.main.retrieve", return_value=hits), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch("app.main.AGENT_MODE", "auto"), \
             patch("app.main.ops_client.enabled", return_value=True), \
             patch("app.main.agent_loop.run", side_effect=fake_run), \
             patch("app.main.grow.schedule") as schedule:
            response = self.client.post("/api/ask", json={"question": "kb-app 为什么重启了"}, auth=self.auth)
        events = [json.loads(line) for line in response.text.splitlines() if line]
        schedule.assert_called_once()
        execution_id, answer, known = schedule.call_args[0]
        self.assertEqual(execution_id, events[0]["execution_id"])
        self.assertEqual(answer, ANSWER)
        self.assertTrue(callable(known))

        def plain(question, context, history, **kwargs):
            yield "delta", "纯知识库回答"

        with patch("app.main.retrieve", return_value=hits), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch("app.main.AGENT_MODE", "auto"), \
             patch("app.main.ops_client.enabled", return_value=True), \
             patch("app.main.agent_loop.run", side_effect=plain), \
             patch("app.main.grow.schedule") as schedule:
            self.client.post("/api/ask", json={"question": "年假几天"}, auth=self.auth)
        schedule.assert_not_called()

    def test_documents_report_whether_growth_is_on(self):
        self.assertFalse(self.client.get("/api/documents", auth=self.auth).json()["sop_growth"])  # AGENT_MODE=off
        with patch("app.main.AGENT_MODE", "auto"):
            self.assertTrue(self.client.get("/api/documents", auth=self.auth).json()["sop_growth"])
            with patch.object(config, "AUTO_SOP_PROPOSALS", False):
                self.assertFalse(self.client.get("/api/documents", auth=self.auth).json()["sop_growth"])


if __name__ == "__main__":
    unittest.main()
