"""组织运行图谱：工具完整返回落盘、零成本播种、两条铁律。

铁律一：没有出处的事实 / 没有证据的提议不进图谱。
铁律二：事实只追加不覆盖，撤回只改状态。
"""
import sqlite3
import unittest
from unittest.mock import patch

from tests.support import clear_graph  # noqa: F401  隔离 DATA_DIR

from app import graph

NAME = {"name": {"type": "str", "pattern": "name", "required": True}, "lines": {"type": "int"}}
KUBE = {"resource": {"type": "str", "pattern": "resource"},
        "name": {"type": "str", "pattern": "k8s_name"},
        "namespace": {"type": "str", "pattern": "k8s_name"}}
clear = clear_graph


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        clear()

    def test_tool_call_keeps_the_full_output(self):
        """预览只给前 1500 字、超过 120 行会被压缩；图谱里存的必须是原样全文。"""
        run = graph.start_execution("conv", "kb-app 内存有问题吗")
        output = "\n".join(f"第 {i} 行 日志内容" for i in range(500))
        graph.record_tool_call(run, "container_logs", {"name": "kb-app", "lines": 500},
                               output, True, 12, params=NAME)
        got = graph.execution(run)
        self.assertEqual(got["question"], "kb-app 内存有问题吗")
        call = got["tool_calls"][0]
        self.assertEqual(call["output"], output)
        self.assertEqual(call["args"], {"name": "kb-app", "lines": 500})
        self.assertEqual((call["seq"], call["ok"], call["duration_ms"]), (1, True, 12))

    def test_calls_are_numbered_in_order(self):
        run = graph.start_execution("conv", "巡检")
        for tool in ("host_disk", "host_resources", "container_stats"):
            graph.record_tool_call(run, tool, {}, "ok", True, 1)
        self.assertEqual([(c["seq"], c["tool"]) for c in graph.execution(run)["tool_calls"]],
                         [(1, "host_disk"), (2, "host_resources"), (3, "container_stats")])

    def test_named_arguments_become_entities(self):
        run = graph.start_execution("conv", "排查")
        graph.record_tool_call(run, "container_logs", {"name": "kb-app", "lines": 100},
                               "ok", True, 1, params=NAME)
        graph.record_tool_call(run, "kube_describe",
                               {"resource": "pod", "name": "web-0", "namespace": "prod"},
                               "ok", True, 1, params=KUBE)
        self.assertIsNotNone(graph.entity("container", "kb-app"))
        self.assertIsNotNone(graph.entity("namespace", "prod"))
        self.assertEqual(graph.entity("k8s_object", "web-0")["attrs"]["resources"], ["pod"])
        # 资源类型、行数不是对象名，不成为实体
        with graph.lock:
            names = {r[0] for r in graph.db.execute("SELECT name FROM entities").fetchall()}
        self.assertNotIn("pod", names)
        self.assertNotIn("100", names)
        facts = graph.facts_of("container", "kb-app")
        self.assertEqual([(f["predicate"], f["object"]) for f in facts],
                         [("checked_by", ("tool", "container_logs"))])
        self.assertTrue(facts[0]["source_ref"].startswith("tool_call:"))
        self.assertEqual(facts[0]["source_kind"], "tool")

    def test_execution_links_to_every_tool_it_called(self):
        run = graph.start_execution("conv", "巡检")
        graph.record_tool_call(run, "host_disk", {}, "ok", True, 1)
        graph.record_tool_call(run, "host_resources", {}, "ok", True, 1)
        called = [f["object"][1] for f in graph.facts_of("execution", run, "called")]
        self.assertEqual(called, ["host_disk", "host_resources"])

    def test_last_seen_moves_but_first_seen_stays(self):
        run = graph.start_execution("conv", "排查")
        with patch.object(graph, "now_iso", return_value="2026-01-01T00:00:00+00:00"):
            graph.record_tool_call(run, "container_logs", {"name": "kb-app"}, "ok", True, 1, params=NAME)
        with patch.object(graph, "now_iso", return_value="2026-01-02T00:00:00+00:00"):
            graph.record_tool_call(run, "container_inspect", {"name": "kb-app"}, "ok", True, 1, params=NAME)
        seen = graph.entity("container", "kb-app")
        self.assertEqual(seen["first_seen"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(seen["last_seen"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(len(graph.facts_of("container", "kb-app")), 2)

    def test_failed_calls_are_recorded_but_do_not_seed_objects(self):
        """打错的容器名不能变成一个「实体」；调用本身还是要记下来。"""
        run = graph.start_execution("conv", "排查")
        graph.record_tool_call(run, "container_logs", {"name": "typo-app"},
                               "[执行失败] 没有这个容器", False, 3, params=NAME)
        self.assertIsNone(graph.entity("container", "typo-app"))
        self.assertFalse(graph.execution(run)["tool_calls"][0]["ok"])
        self.assertEqual(graph.facts_of("execution", run, "called")[0]["object"],
                         ("tool", "container_logs"))

    def test_finish_fills_outcome_time_and_message(self):
        run = graph.start_execution("conv", "巡检", playbook_id="pb1")
        graph.record_tool_call(run, "host_disk", {}, "41%", True, 1)
        self.assertEqual(graph.finish_execution(run, "磁盘正常", message_id=7), "ok")
        got = graph.execution(run)
        self.assertEqual((got["outcome"], got["message_id"], got["playbook_id"]), ("ok", 7, "pb1"))
        self.assertIsNotNone(got["finished_at"])
        self.assertEqual(graph.executions_by_message("conv"), {7: {"execution_id": run, "outcome": "ok",
                                                                   "playbook_id": "pb1"}})

    def test_outcome_rules(self):
        ok = [("container_stats", True)]
        cases = [
            (("结论：内存正常", False, ok), "ok"),
            (("⚠️ 告警：内存 92%", False, ok), "anomaly"),
            (("❌ 严重：容器反复重启", False, [("a", True), ("b", False)]), "anomaly"),
            (("", False, ok), "failed"),                       # 没有回答
            (("有回答但出错了", True, ok), "failed"),            # error 事件
            (("工具都失败了", False, [("a", False), ("b", False)]), "failed"),
            (("纯知识库回答", False, []), "unknown"),           # 没观察系统
            (("只搜了网", False, [("web_search", True)]), "unknown"),
        ]
        for (answer, failed, calls), expected in cases:
            with self.subTest(answer=answer, failed=failed, calls=calls):
                self.assertEqual(graph._outcome(answer, failed, calls), expected)


class FactTests(unittest.TestCase):
    def setUp(self):
        clear()

    def test_fact_without_source_is_refused(self):
        with self.assertRaises(ValueError):
            graph.add_fact(("container", "a"), "status", "tool", "", value="running")
        # 绕过 Python 校验直接写库也不行：表上有 CHECK
        with graph.lock:
            subject = graph._touch("container", "a")
            with self.assertRaises(sqlite3.IntegrityError):
                graph.db.execute("INSERT INTO facts (subject, predicate, object_value, source_kind,"
                                 " source_ref, observed_at) VALUES (?, 'p', 'v', 'tool', '', 'now')",
                                 (subject,))
            graph.db.rollback()

    def test_fact_needs_an_object(self):
        with self.assertRaises(ValueError):
            graph.add_fact(("container", "a"), "status", "tool", "tool_call:1")

    def test_facts_are_appended_not_overwritten(self):
        graph.add_fact(("container", "a"), "mem_limit", "doc", "doc:手册.docx", value="512MB")
        graph.add_fact(("container", "a"), "mem_limit", "tool", "tool_call:9", value="256MB")
        facts = graph.facts_of("container", "a", "mem_limit")
        self.assertEqual([(f["value"], f["source_kind"]) for f in facts],
                         [("512MB", "doc"), ("256MB", "tool")])

    def test_retract_changes_status_and_keeps_the_row(self):
        graph.add_fact(("sop", "p1"), "checks", "sop", "sop:p1", obj=("tool", "host_disk"))
        self.assertEqual(graph.retract_source("sop:p1"), 1)
        self.assertEqual(graph.facts_of("sop", "p1"), [])
        kept = graph.facts_of("sop", "p1", include_retracted=True)
        self.assertEqual([f["status"] for f in kept], ["retracted"])
        self.assertEqual(graph.retract_source("sop:p1"), 0)


class SeedTests(unittest.TestCase):
    def setUp(self):
        clear()

    def test_playbook_seeds_checks_origin_and_thresholds(self):
        graph.seed_playbook("pb1", "重启排查", "运维手册.docx", [
            {"tool": "container_logs", "args": {"name": ""}, "checkpoint": "看是否有 OOM"},
            {"tool": "container_stats", "args": {}, "checkpoint": "内存使用率超过 80% 告警"},
            {"tool": "container_logs", "args": {"name": ""}, "checkpoint": "再看一遍"}])
        facts = graph.facts_of("sop", "pb1")
        self.assertEqual(sorted(f["object"][1] for f in facts if f["predicate"] == "checks"),
                         ["container_logs", "container_stats"])
        self.assertEqual([f["object"] for f in facts if f["predicate"] == "defined_in"],
                         [("doc", "运维手册.docx")])
        self.assertEqual([f["object"] for f in facts if f["predicate"] == "threshold"],
                         [("threshold", "container_stats:80%")])
        self.assertEqual(graph.entity("sop", "pb1")["attrs"]["name"], "重启排查")
        self.assertEqual(graph.entity("threshold", "container_stats:80%")["attrs"]["value"], "80%")

    def test_manual_or_practice_playbooks_have_no_document(self):
        for source in ("", "手工创建", "从实践沉淀"):
            graph.seed_playbook("pb-" + (source or "none"), "甲", source,
                                [{"tool": "host_disk", "args": {}, "checkpoint": ""}])
            with self.subTest(source=source):
                self.assertEqual(graph.facts_of("sop", "pb-" + (source or "none"), "defined_in"), [])

    def test_reseeding_retracts_the_previous_version(self):
        graph.seed_playbook("pb1", "甲", "a.docx", [{"tool": "host_disk", "args": {}, "checkpoint": ""}])
        graph.seed_playbook("pb1", "甲改", "a.docx", [{"tool": "host_resources", "args": {}, "checkpoint": ""}])
        active = graph.facts_of("sop", "pb1", "checks")
        self.assertEqual([f["object"][1] for f in active], ["host_resources"])
        history = graph.facts_of("sop", "pb1", "checks", include_retracted=True)
        self.assertEqual([(f["object"][1], f["status"]) for f in history],
                         [("host_disk", "retracted"), ("host_resources", "active")])
        self.assertEqual(graph.entity("sop", "pb1")["attrs"]["name"], "甲改")

    def test_threshold_parser_only_takes_what_it_can_trust(self):
        cases = {
            "内存使用率超过 80% 告警": ["80%"],
            "重启次数 > 3 说明在崩溃循环": ["3"],
            "RestartCount>=5 需要跟进": ["5"],
            "剩余内存低于 512MB": ["512MB"],
            "响应时间大于 500ms 或 P95 超过 2s": ["500ms", "2s"],
            "退出码 137 且内存上限远低于文档值": [],       # 裸数字不是阈值
            "k8s 集群里 Pod 处于 Running": [],             # 8s 不是 8 秒
            "2026 年 10 月的事件，HTTP 502": [],
            "": [],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(graph.thresholds(text), expected)


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        clear()

    def test_feedback_becomes_a_human_fact(self):
        run = graph.start_execution("conv", "执行 SOP《巡检》", playbook_id="pb1")
        feedback_id = graph.record_feedback(run, "false_alarm", "阈值定低了")
        judged = graph.facts_of("execution", run, "judged")
        self.assertEqual([(f["value"], f["source_kind"], f["source_ref"]) for f in judged],
                         [("false_alarm", "human", f"feedback:{feedback_id}")])
        # 按 SOP 执行的，SOP 自己也记一笔
        self.assertEqual([f["value"] for f in graph.facts_of("sop", "pb1", "judged")], ["false_alarm"])

    def test_feedback_without_playbook_only_marks_the_execution(self):
        run = graph.start_execution("conv", "自由提问")
        graph.record_feedback(run, "correct")
        with graph.lock:
            sops = graph.db.execute("SELECT COUNT(*) FROM entities WHERE kind = 'sop'").fetchone()[0]
        self.assertEqual(sops, 0)

    def test_unknown_execution_or_verdict_is_refused(self):
        with self.assertRaises(graph.UnknownExecution):
            graph.record_feedback("nope", "correct")
        run = graph.start_execution("conv", "q")
        with self.assertRaises(ValueError):
            graph.record_feedback(run, "meh")


class ProposalTests(unittest.TestCase):
    def setUp(self):
        clear()

    def test_proposal_needs_evidence(self):
        for refs in ([], [""], None):
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                graph.add_proposal("new_sop", {"name": "x"}, refs)
        with self.assertRaises(ValueError):
            graph.add_proposal("rewrite_everything", {}, ["tool_call:1"])
        with graph.lock, self.assertRaises(sqlite3.IntegrityError):
            graph.db.execute("INSERT INTO proposals (id, kind, payload, evidence_refs, created_at)"
                             " VALUES ('p', 'new_sop', '{}', '[]', 'now')")
        graph.db.rollback()

    def test_lifecycle_and_dedup_helpers(self):
        run = graph.start_execution("conv", "q")
        pid = graph.add_proposal("new_sop", {"name": "重启排查"}, ["tool_call:1", "tool_call:2"],
                                 execution_id=run, signature="container_inspect>container_logs")
        pending = graph.list_proposals(status="pending", execution_id=run)
        self.assertEqual([p["id"] for p in pending], [pid])
        self.assertEqual(pending[0]["payload"], {"name": "重启排查"})
        self.assertEqual(pending[0]["evidence_refs"], ["tool_call:1", "tool_call:2"])
        self.assertEqual(graph.count_proposals_since("2000-01-01T00:00:00+00:00"), 1)

        self.assertTrue(graph.decide_proposal(pid, "rejected"))
        self.assertFalse(graph.decide_proposal(pid, "approved"))   # 已决定过的不再改
        self.assertEqual(graph.get_proposal(pid)["status"], "rejected")
        self.assertEqual(graph.list_proposals(status="pending"), [])
        self.assertTrue(graph.recently_rejected("container_inspect>container_logs", days=30))
        self.assertFalse(graph.recently_rejected("host_disk", days=30))
        self.assertFalse(graph.recently_rejected("", days=30))
        with self.assertRaises(ValueError):
            graph.decide_proposal(pid, "maybe")


if __name__ == "__main__":
    unittest.main()
