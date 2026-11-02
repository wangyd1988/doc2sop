"""SOP 执行记录（app/runs.py）：按 SOP 输出格式解析结论、判等级、和上次比、对话里「▶ 执行」留记录、接口、导出、回滚兼容。"""
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph

from app import conversations, graph, playbooks, runs
from app.config import DATA_DIR, WEB_PASSWORD, WEB_USER
from app.main import app

TABLE = """按 SOP《每日资源巡检》执行

| 步骤 | 查看 | 实际数据 | 结论 |
|---|---|---|---|
| 1 | 宿主机磁盘 | / 85%，/data 40% | ⚠️ 告警：根分区超过 80% |
| 2 | 内存 | 可用 1.2G / 共 2G | ✅ 正常：可用超过 20% |
| 3 | 容器状态 | 5 个都在运行 | ✅ 正常 |

**需要跟进**
- 清理根分区的旧日志，或者扩容
"""

ALL_OK = """按 SOP《每日资源巡检》执行

| 步骤 | 查看 | 实际数据 | 结论 |
|---|---|---|---|
| 1 | 宿主机磁盘 | / 70%，/data 40% | ✅ 正常：都没超过 80% |
| 2 | 内存 | 可用 1.0G / 共 2G | ✅ 正常 |
| 3 | 容器状态 | 5 个都在运行 | ✅ 正常 |

需要跟进：无
"""

STEPS = [{"tool": "host_disk", "args": {}, "checkpoint": "根分区超过 80% 告警"},
         {"tool": "host_resources", "args": {}, "checkpoint": "可用内存低于 20% 告警"},
         {"tool": "list_containers", "args": {}, "checkpoint": "有容器不在运行就告警"}]
TOOLS = {"host_disk", "host_resources", "list_containers"}
ALL_CALLS = [("host_disk", True), ("host_resources", True), ("list_containers", True)]


def judge(answer, calls=ALL_CALLS, failure=None, steps=STEPS):
    return runs.judge(runs.parse(answer), steps, calls, answer, failure)


class ParseTests(unittest.TestCase):
    def test_reads_the_step_table_and_followups(self):
        parsed = runs.parse(TABLE)
        self.assertEqual([(r["n"], r["check"], r["mark"]) for r in parsed["rows"]],
                         [(1, "宿主机磁盘", "warn"), (2, "内存", "ok"), (3, "容器状态", "ok")])
        self.assertEqual(parsed["rows"][0]["value"], "/ 85%，/data 40%")
        self.assertEqual(parsed["rows"][0]["note"], "告警：根分区超过 80%")
        self.assertEqual(parsed["followups"], ["清理根分区的旧日志，或者扩容"])
        self.assertEqual(judge(TABLE), ("anomaly", ""))
        self.assertEqual([f["check"] for f in runs.findings(parsed["rows"])], ["宿主机磁盘"])

    def test_all_green_with_every_tool_called_is_ok(self):
        self.assertEqual(judge(ALL_OK), ("ok", ""))
        self.assertEqual(runs.parse(ALL_OK)["followups"], [])

    def test_followup_phrasings_seen_in_real_answers(self):
        cases = [
            ("**需要跟进**\n\n- 先看日志\n- 核对镜像地址\n", ["先看日志", "核对镜像地址"]),
            ("需要跟进：\n1. **修正 selector**：改成 order-web\n2. 顺带核对 user-api\n", ["修正 selector：改成 order-web", "顺带核对 user-api"]),
            ("## ⚠️ 需要跟进的事项\n\n**容器 `kb-app` 刚启动**\n\n别的段落\n", ["容器 kb-app 刚启动"]),
            ("需要跟进的事项如下：\n- a\n\n- b\n\n结束语\n", ["a", "b"]),
            ("需要跟进（2 项）：\n- a\n- b\n", ["a", "b"]),
            ("**需要跟进**：先清理根分区\n", ["先清理根分区"]),
            ("**需要跟进**：无。\n\n补充一点观察：kb-app 刚重启过\n", []),
            ("需要跟进：无，各项均在阈值内。\n\n- 另外顺带一提\n", []),
            ("目前没有需要跟进的地方。\n", []),
            ("需要跟进：无法访问 registry，先查 DNS\n", ["无法访问 registry，先查 DNS"]),
        ]
        for text, want in cases:
            with self.subTest(text=text):
                self.assertEqual(runs.followups(text), want)

    def test_table_variants(self):
        """不带首尾竖线、表头加粗、对齐冒号、单元格里转义的竖线、❌ 严重、多张表合起来，都认。"""
        answer = ("**步骤** | **查看** | **实际数据** | **结论**\n:--- | :---: | --- | ---:\n"
                  "第 1 步 | 磁盘 | a \\| b | ❌ 严重：满了\n\n另一段话\n\n"
                  "| 步骤 | 查看 | 实际数据 | 结论 |\n|-|-|-|-|\n| 2 | 内存 | 50% | ✅ 正常 |\n")
        rows = runs.parse(answer)["rows"]
        self.assertEqual([(r["n"], r["check"], r["value"], r["mark"]) for r in rows],
                         [(1, "磁盘", "a | b", "bad"), (2, "内存", "50%", "ok")])

    def test_tables_without_a_verdict_column_are_not_the_report(self):
        self.assertEqual(runs.parse("| 名字 | 值 |\n|---|---|\n| a | 1 |\n")["rows"], [])

    def test_no_table_is_unknown_never_ok(self):
        level, reason = judge("都检查过了，一切正常 ✅")
        self.assertEqual(level, "unknown")
        self.assertIn("没有 SOP 输出格式要求的逐步表格", reason)

    def test_verdicts_without_the_four_symbols_are_unknown(self):
        """「正常」两个字不算：只认 ✅ ⚠️ ❌ ❓（「不正常」里也有「正常」）。"""
        answer = TABLE.replace("✅ 正常：可用超过 20%", "正常").replace("⚠️ 告警：根分区超过 80%", "不正常")
        answer = answer.replace("| ✅ 正常 |", "| 正常 |")
        level, reason = judge(answer)
        self.assertEqual(level, "unknown")
        self.assertIn("没有用 ✅ ⚠️ ❌ ❓ 标出结论", reason)

    def test_question_marks_make_it_unknown(self):
        answer = ALL_OK.replace("| 5 个都在运行 | ✅ 正常 |", "| 未执行：工具超时 | ❓ 无法判断 |")
        level, reason = judge(answer)
        self.assertEqual(level, "unknown")
        self.assertIn("第 3 步", reason)

    def test_missing_steps_are_unknown(self):
        answer = "\n".join(line for line in ALL_OK.splitlines() if not line.startswith("| 3 "))
        level, reason = judge(answer)
        self.assertEqual(level, "unknown")
        self.assertIn("第 3 步没有出现在表格里", reason)

    def test_green_table_without_tool_calls_has_no_basis(self):
        """表格说正常，可第 2 步的工具根本没调成功过：没有依据，不能当正常。"""
        level, reason = judge(ALL_OK, calls=[("host_disk", True), ("host_resources", False), ("list_containers", True)])
        self.assertEqual(level, "unknown")
        self.assertIn("第 2 步的工具没有调用成功过", reason)
        self.assertEqual(judge(ALL_OK, calls=[])[0], "unknown")

    def test_failures(self):
        self.assertEqual(judge(TABLE, failure="模型调用失败：超时"), ("failed", "模型调用失败：超时"))
        self.assertEqual(judge("  ")[0], "failed")
        self.assertEqual(judge(ALL_OK, calls=[("host_disk", False), ("host_resources", False)]),
                         ("failed", "数据工具都没有调用成功"))
        answer = ("| 步骤 | 查看 | 实际数据 | 结论 |\n|---|---|---|---|\n| 1 | 磁盘 | 未执行：工具失败 | ❓ |\n"
                  "| 2 | 内存 | 未执行：工具失败 | ❓ |\n| 3 | 容器 | 未执行：工具失败 | ❓ |\n")
        self.assertEqual(judge(answer, calls=[]), ("failed", "每一步都没有执行"))

    def test_anomalies_win_over_unknowns(self):
        answer = TABLE.replace("| 5 个都在运行 | ✅ 正常 |", "| 未执行：超时 | ❓ |")
        self.assertEqual(judge(answer)[0], "anomaly")


class CompareTests(unittest.TestCase):
    def run_of(self, answer, level=None):
        parsed = runs.parse(answer)
        return {"id": "x", "level": level or judge(answer)[0], "report": {"rows": parsed["rows"]},
                "started_at": "2026-11-01T01:00:00+00:00", "trigger": "schedule", "summary": ""}

    def test_new_recovered_and_numbers(self):
        before = self.run_of(TABLE)
        after = self.run_of(TABLE.replace("| / 85%，/data 40% | ⚠️ 告警：根分区超过 80% |", "| / 70%，/data 41% | ✅ 正常 |")
                            .replace("| 可用 1.2G / 共 2G | ✅ 正常：可用超过 20% |", "| 可用 0.3G / 共 2G | ⚠️ 告警：不到 20% |"))
        diff = runs.compare(after, before)
        self.assertEqual([i["step"] for i in diff["recovered"]], ["第 1 步 宿主机磁盘"])
        self.assertEqual([i["step"] for i in diff["new"]], ["第 2 步 内存"])
        self.assertEqual(diff["still"], [])
        changed = {i["step"]: i["deltas"] for i in diff["changed"]}
        self.assertEqual(changed["第 1 步 宿主机磁盘"], ["85% → 70%（-15）", "40% → 41%（+1）"])
        self.assertEqual(changed["第 2 步 内存"], ["1.2G → 0.3G（-0.9）"])

    def test_still_open_and_signature_ignores_values(self):
        before, after = self.run_of(TABLE), self.run_of(TABLE.replace("85%", "91%"))
        diff = runs.compare(after, before)
        self.assertEqual([i["step"] for i in diff["still"]], ["第 1 步 宿主机磁盘"])
        self.assertEqual(diff["new"], [])
        self.assertEqual(runs.signature(before), runs.signature(after))
        self.assertNotEqual(runs.signature(before), runs.signature(self.run_of(ALL_OK)))
        self.assertEqual(runs.signature(self.run_of(ALL_OK)), "")

    def test_nothing_to_compare_with(self):
        self.assertIsNone(runs.compare(self.run_of(TABLE), None))
        failed = {"id": "y", "level": "failed", "report": {}, "started_at": "t", "trigger": "web", "summary": ""}
        self.assertIn("没法逐项比较", runs.compare(self.run_of(TABLE), failed)["note"])

    def test_params_from_the_execute_question(self):
        book = {"steps": [{"tool": "container_logs", "args": {"name": "", "lines": 100}}]}
        self.assertEqual(runs.params_from_question(book, "执行 SOP《容器排查》（name：kb-app）"), {"name": "kb-app"})
        self.assertEqual(runs.params_from_question(book, "执行 SOP《容器排查》"), {})
        self.assertEqual(runs.params_from_question(book, "执行 SOP《容器排查》（就查 kb-app 吧）"), {"补充": "就查 kb-app 吧"})


class ExecuteButtonTests(unittest.TestCase):
    """对话里的「▶ 执行」：同一个 id 留一条执行记录，回答结束后解析；问答本身（事件、消息）和以前一样。"""

    def setUp(self):
        clear_graph()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        with conversations.lock:
            conversations.db.execute("DELETE FROM messages")
            conversations.db.execute("DELETE FROM conversations")
            conversations.db.commit()
        self.pid = playbooks.save(None, "每日资源巡检", "每天上班后", STEPS, TOOLS)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def ask(self, answer, question="执行 SOP《每日资源巡检》", playbook=True, failing=None):
        def fake_run(q, context, history, **kwargs):
            for tool, ok in ALL_CALLS:
                graph.record_tool_call(kwargs["execution_id"], tool, {}, f"{tool} 的返回", ok, 3)
                yield "tool_call", {"tool": tool, "args": {}, "category": "data"}
                yield "tool_result", {"tool": tool, "preview": "ok", "lines": 1, "chars": 2}
            if failing:
                yield "error", failing
            yield "delta", answer

        body = {"question": question}
        if playbook:
            body["playbook_id"] = self.pid
        with patch("app.main.retrieve", return_value=[]), \
             patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
             patch("app.main.AGENT_MODE", "auto"), \
             patch("app.main.ops_client.enabled", return_value=True), \
             patch("app.main.grow.schedule"), \
             patch("app.main.agent_loop.run", side_effect=fake_run):
            response = self.client.post("/api/ask", json=body, auth=self.auth)
        self.assertEqual(response.status_code, 200, response.text)
        return [json.loads(line) for line in response.text.splitlines() if line]

    def test_execute_leaves_a_run_record_with_the_same_id(self):
        events = self.ask(TABLE)
        execution_id = events[0]["execution_id"]
        self.assertEqual(set(events[0]), {"conversation", "model", "execution_id"})   # 首行和以前一样
        run = runs.get(execution_id)
        self.assertEqual((run["trigger"], run["status"], run["level"]), ("web", "done", "anomaly"))
        self.assertEqual(run["conversation_id"], events[0]["conversation"]["id"])
        self.assertEqual(run["execution_id"], execution_id)
        self.assertEqual(len(run["report"]["steps"]), 3)
        self.assertEqual(run["report"]["findings"][0]["check"], "宿主机磁盘")
        self.assertIn("1 项异常", run["summary"])

    def test_free_questions_leave_no_run_record(self):
        self.ask(TABLE, question="磁盘怎么样", playbook=False)
        self.assertEqual(runs.listing()[1], 0)

    def test_failed_turn_is_recorded_as_failed(self):
        events = self.ask("", failing="模型调用失败：超时")
        run = runs.get(events[0]["execution_id"])
        self.assertEqual(run["level"], "failed")
        self.assertIn("超时", run["summary"])

    def test_api_list_detail_compare_export_delete(self):
        first = self.ask(TABLE)[0]["execution_id"]
        second = self.ask(ALL_OK)[0]["execution_id"]
        graph.record_feedback(second, "false_alarm", "其实没问题")
        listed = self.client.get("/api/runs", params={"playbook_id": self.pid}, auth=self.auth).json()
        self.assertEqual([r["id"] for r in listed["runs"]], [second, first])
        self.assertNotIn("answer", listed["runs"][0])
        detail = self.client.get(f"/api/runs/{second}", auth=self.auth).json()
        self.assertEqual(detail["level"], "ok")
        self.assertEqual(detail["compare"]["previous"]["id"], first)
        self.assertEqual([i["step"] for i in detail["compare"]["recovered"]], ["第 1 步 宿主机磁盘"])
        self.assertEqual([s["tool"] for s in detail["steps"]], ["host_disk", "host_resources", "list_containers"])
        self.assertEqual(detail["steps"][0]["calls"][0]["output"], "host_disk 的返回")
        self.assertEqual(detail["feedback"][0]["verdict"], "false_alarm")
        self.assertEqual(detail["question"], "执行 SOP《每日资源巡检》")
        summary = self.client.get("/api/runs/summary", auth=self.auth).json()["playbooks"][self.pid]
        self.assertEqual((summary["runs"], summary["last"]["id"]), (2, second))

        exported = self.client.get(f"/api/runs/{first}/report.md", auth=self.auth)
        self.assertEqual(exported.status_code, 200)
        self.assertIn("text/markdown", exported.headers["content-type"])
        self.assertIn("filename*=UTF-8''", exported.headers["content-disposition"])
        self.assertIn("| 1 | 宿主机磁盘 | / 85%，/data 40% | ⚠️ 告警：根分区超过 80% |", exported.text)
        self.assertIn("## 异常项", exported.text)
        self.assertIn("host_disk 的返回", exported.text)

        self.assertEqual(self.client.delete(f"/api/runs/{first}", auth=self.auth).status_code, 200)
        self.assertEqual(self.client.get(f"/api/runs/{first}", auth=self.auth).status_code, 404)
        self.assertIsNone(graph.execution(first))
        self.assertEqual(self.client.delete(f"/api/runs/{first}", auth=self.auth).status_code, 404)
        # 删的是执行记录，对话还在
        self.assertTrue(conversations.exists(runs.get(second)["conversation_id"]))

    def test_export_fences_survive_backticks_in_tool_output(self):
        run = self.ask(TABLE)[0]["execution_id"]
        with graph.lock:
            graph.db.execute("UPDATE tool_calls SET output_full = ? WHERE execution_id = ? AND seq = 1",
                             ("```\n不该截断\n````", run))
            graph.db.commit()
        text = runs.markdown(run)
        self.assertIn("`````\n```\n不该截断\n````\n`````", text)

    def test_requires_authentication(self):
        self.assertEqual(self.client.get("/api/runs").status_code, 401)


class RollbackTests(unittest.TestCase):
    """回滚到旧镜像：旧代码（f5ef285）打开新库照常读写。只加了表，老表的结构一列都没动。"""

    OLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, message_id INTEGER,
  playbook_id TEXT, question TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'unknown', started_at TEXT NOT NULL,
  finished_at TEXT);
CREATE INDEX IF NOT EXISTS executions_by_conversation ON executions(conversation_id, started_at);
CREATE TABLE IF NOT EXISTS tool_calls (id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE, seq INTEGER NOT NULL, tool TEXT NOT NULL,
  args TEXT NOT NULL DEFAULT '{}', output_full TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL DEFAULT 1,
  duration_ms INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, UNIQUE (execution_id, seq));
CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE, verdict TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
"""

    def test_old_code_opens_and_uses_the_new_database(self):
        clear_graph()
        book = {"id": "pb1", "name": "巡检", "steps": STEPS}
        web = graph.start_execution("c1", "执行 SOP《巡检》", "pb1")
        runs.create(book, "web", run_id=web, execution_id=web, conversation_id="c1", status="running")
        auto = graph.start_execution("auto:x", "执行 SOP《巡检》。这是定时自动执行", "pb1", channel="schedule")
        graph.record_tool_call(auto, "host_disk", {}, "/ 40%", True, 3)
        graph.record_feedback(auto, "unhelpful")
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "graph.db"
            with graph.lock:
                graph.db.execute("PRAGMA wal_checkpoint(FULL)")
            shutil.copy(DATA_DIR / "graph.db", copy)
            old = sqlite3.connect(copy)
            old.row_factory = sqlite3.Row
            old.executescript(self.OLD_SCHEMA)                        # 旧代码启动时建表：都已存在，什么也不做
            try:
                old.execute("ALTER TABLE executions ADD COLUMN channel TEXT NOT NULL DEFAULT 'web'")
            except sqlite3.OperationalError:
                pass                                                  # 旧代码的 _migrate：列已在
            # 旧代码的读写：回放对话时的执行身份、记新的一轮、记反馈
            old.execute("UPDATE executions SET message_id = 7 WHERE id = ?", (web,))
            rows = old.execute("SELECT id, message_id, outcome, playbook_id FROM executions"
                               " WHERE conversation_id = ? AND message_id IS NOT NULL", ("c1",)).fetchall()
            self.assertEqual([r["id"] for r in rows], [web])
            old.execute("INSERT INTO executions (id, conversation_id, playbook_id, question, started_at, channel)"
                        " VALUES ('new', 'c2', NULL, 'q', 't', 'web')")
            old.execute("INSERT INTO feedback (execution_id, verdict, note, created_at) VALUES ('new', 'correct', '', 't')")
            old.commit()
            # 老表的结构一列都没变：和旧代码建出来的一模一样
            fresh = sqlite3.connect(":memory:")
            fresh.executescript(self.OLD_SCHEMA)
            fresh.execute("ALTER TABLE executions ADD COLUMN channel TEXT NOT NULL DEFAULT 'web'")
            try:
                for table in ("executions", "tool_calls", "feedback"):
                    self.assertEqual([tuple(r) for r in old.execute(f"PRAGMA table_info({table})").fetchall()],
                                     [tuple(r) for r in fresh.execute(f"PRAGMA table_info({table})").fetchall()], table)
            finally:
                old.close()
                fresh.close()

    def test_new_tables_only(self):
        """新加的东西全是表（CREATE TABLE IF NOT EXISTS）：没有 ALTER、没有 DROP。"""
        self.assertNotIn("ALTER", graph.AUTOMATION_SCHEMA.upper())
        self.assertNotIn("DROP", graph.AUTOMATION_SCHEMA.upper())
        self.assertEqual(graph.AUTOMATION_SCHEMA.count("CREATE TABLE IF NOT EXISTS"), 9)   # 第 9 张：automation_changes


if __name__ == "__main__":
    unittest.main()
