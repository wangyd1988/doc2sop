"""云上协同的推送（app/chat_push.py）和页面接口（app/chat_api.py：状态、测试推送、推送设置）。"""
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量
from tests.support import clear_graph
from tests.test_chat_channel import CONFIG, FakeBridge, clear_chat, message

from app import autorun, chat_api, chat_bridge, chat_config, chat_push, chat_store, conversations, gaps, graph
from app import playbooks, runs, schedules
from app import main as app_main
from app.chat_bridge import BridgeError
from app.config import CHAT_FILE, WEB_PASSWORD, WEB_USER

ROW = {"step": "1", "n": 1, "check": "根分区", "value": "87%", "mark": "warn", "note": "超过 85%",
       "verdict": "⚠️ 超过 85%", "marked": True}
MONDAY_0930 = datetime(2026, 11, 2, 1, 30, tzinfo=timezone.utc)       # 北京时间周一 09:30


class PushCase(unittest.TestCase):
    def setUp(self):
        chat_store.ensure()
        clear_chat()
        clear_graph()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        CHAT_FILE.write_text(CONFIG, encoding="utf-8")
        chat_config.reset()
        self.addCleanup(lambda: (CHAT_FILE.unlink(missing_ok=True), chat_config.reset()))
        self.bridge = FakeBridge()
        chat_bridge._current["bridge"] = self.bridge
        self.addCleanup(chat_bridge.reset)
        self.book = playbooks.get(playbooks.save(None, "磁盘巡检", "每天", [{"tool": "host_disk", "args": {}}],
                                                 {"host_disk"}))

    def run_record(self, level, rows=(), source_id="s1", trigger="schedule"):
        run_id = runs.create(self.book, trigger, source_id=source_id, note="每天 09:00", status="running")
        report = {"steps": [{"tool": "host_disk", "args": {}}], "rows": list(rows), "findings": runs.findings(list(rows)),
                  "followups": ["清理日志"] if rows else [], "reason": ""}
        with graph.lock:
            graph.db.execute("UPDATE sop_runs SET status = 'done', level = ?, summary = ?, report = ?,"
                             " finished_at = started_at WHERE id = ?",
                             (level, "1 项异常" if rows else "", json.dumps(report, ensure_ascii=False), run_id))
            graph.db.commit()
        return runs.get(run_id)

    def log(self):
        return [(r["kind"], r["target"], r["status"]) for r in reversed(chat_store.push_recent(50))]


class AfterRunTests(PushCase):
    def test_without_a_bridge_nothing_happens(self):
        chat_bridge.reset()
        chat_store.notify_set("schedule", "s1", "运维值班群", "always", "always")
        self.assertIsNone(chat_push.after_run(self.run_record("anomaly", [ROW])))
        self.assertEqual(self.log(), [])

    def test_pushes_follow_the_mail_rules(self):
        chat_store.notify_set("schedule", "s1", "运维值班群", "problems", "daily")
        first = chat_push.after_run(self.run_record("anomaly", [ROW]))
        self.assertEqual((first["kind"], first["status"]), ("problem", "sent"))
        target, text = self.bridge.pushes[0]
        self.assertEqual(target, "运维值班群")
        self.assertTrue(text.startswith("【有异常】SOP《磁盘巡检》"), text)
        self.assertIn("• 清理日志", text)
        again = chat_push.after_run(self.run_record("anomaly", [ROW]))
        self.assertEqual((again["kind"], again["status"]), (None, "skipped"))       # 同一个问题 24 小时内提醒过
        fixed = chat_push.after_run(self.run_record("ok"))
        self.assertEqual(fixed["kind"], "recovered")
        self.assertTrue(self.bridge.pushes[1][1].startswith("【已恢复】"))
        self.assertEqual(chat_push.after_run(self.run_record("ok"))["status"], "skipped")
        self.assertEqual(len(self.bridge.pushes), 2)
        self.assertEqual(self.log(), [("run", "运维值班群", "sent"), ("run", "运维值班群", "skipped"),
                                      ("run", "运维值班群", "sent"), ("run", "运维值班群", "skipped")])

    def test_failed_push_is_tried_again_and_held_counts_as_sent(self):
        chat_store.notify_set("rule", "r1", "运维值班群", "problems", "never")
        with patch.object(self.bridge, "push", side_effect=BridgeError("平台 5xx", status=502)):
            failed = chat_push.after_run(self.run_record("anomaly", [ROW], source_id="r1", trigger="alert"))
        self.assertEqual(failed["status"], "failed")
        with patch.object(self.bridge, "push", return_value={"ok": True, "held": True}):
            held = chat_push.after_run(self.run_record("anomaly", [ROW], source_id="r1", trigger="alert"))
        self.assertEqual((held["kind"], held["status"]), ("problem", "held"))
        self.assertEqual(chat_push.after_run(self.run_record("anomaly", [ROW], source_id="r1",
                                                             trigger="alert"))["status"], "skipped")

    def test_runs_without_a_push_setting_are_ignored(self):
        self.assertIsNone(chat_push.after_run(self.run_record("anomaly", [ROW])))
        chat_store.notify_set("schedule", "s1", "运维值班群", "always", "always")
        self.assertIsNone(chat_push.after_run(self.run_record("anomaly", [ROW], trigger="web")))
        self.assertEqual(self.bridge.pushes, [])

    def test_autorun_pushes_after_the_mail(self):
        run_id = runs.create(self.book, "schedule", source_id="gone", status="queued")
        with patch.object(chat_push, "after_run") as push:
            done = autorun.execute(run_id)          # 测试环境 AGENT_MODE=off：记一条没跑成，照样走通知
        push.assert_called_once()
        self.assertEqual((push.call_args.args[0]["id"], done["level"]), (run_id, "failed"))


class DigestTests(PushCase):
    def gap(self, n, question, conversation_id):
        gaps._upsert(f"msg:{n}", question, "kb_missing", "回答说知识库里没有", "2026-11-01T01:00:00+00:00",
                     conversation_id=conversation_id, message_id=n)

    def test_digest_goes_to_people_or_only_covers_its_own_group(self):
        CHAT_FILE.write_text(CONFIG + """digest:
  - {target: 王某某, weekday: 1, hour: 9}
  - {target: 运维值班群, weekday: 1, hour: 9}
  - {target: 运维值班群, weekday: 1, hour: 9, group: "1001"}
""", encoding="utf-8")
        chat_config.reset()
        web = conversations.create("如何申请 VPN 权限")
        group = conversations.create("云上协同·运维值班群：值班交接表在哪")
        chat_store.thread_open(message("值班交接表在哪"), "运维值班群", group["id"])
        self.gap(1, "如何申请 VPN 权限", web["id"])
        self.gap(2, "值班交接表在哪", group["id"])
        self.assertEqual(chat_push.maybe_digest(datetime(2026, 11, 2, 3, 0, tzinfo=timezone.utc)), [])   # 不到点
        self.assertEqual(chat_push.maybe_digest(MONDAY_0930), ["sent", "skipped", "sent"])
        (person, everything), (team, own) = self.bridge.pushes
        self.assertEqual((person, team), ("王某某", "运维值班群"))
        self.assertIn("如何申请 VPN 权限", everything)
        self.assertIn("值班交接表在哪", everything)
        self.assertNotIn("VPN", own)                            # 发到群：只汇总这个群自己的问题
        self.assertIn("本周「运维值班群」里大家常问", own)
        self.assertEqual(chat_push.maybe_digest(MONDAY_0930), [])  # 每周一次
        self.assertEqual(self.log(), [("digest", "王某某", "sent"), ("digest", "运维值班群", "skipped"),
                                      ("digest", "运维值班群", "sent")])


class ApiTests(PushCase):
    def setUp(self):
        super().setUp()
        app = FastAPI(dependencies=[Depends(app_main.require_auth)])
        app.include_router(chat_api.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        self.schedule = schedules.create({"playbook_id": self.book["id"], "kind": "daily", "at": "09:00"}, {})
        chat_api._tests["times"].clear()
        chat_api._tests["by_target"].clear()

    def test_push_settings_only_accept_targets_the_bridge_knows(self):
        url = f"/api/chat/notify/schedule/{self.schedule['id']}"
        got = self.client.get("/api/chat/notify", auth=self.auth).json()
        self.assertEqual((got["targets"], got["items"]), (["王某某", "运维值班群"], []))
        refused = self.client.put(url, json={"target": "外面的群"}, auth=self.auth)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("targets.yaml", refused.json()["detail"])
        saved = self.client.put(url, json={"target": "运维值班群", "when": "always", "repeat": "never"}, auth=self.auth)
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual({k: saved.json()[k] for k in ("kind", "target", "when", "repeat")},
                         {"kind": "schedule", "target": "运维值班群", "when": "always", "repeat": "never"})
        self.assertEqual(self.client.get("/api/chat/notify", auth=self.auth).json()["items"][0]["id"], self.schedule["id"])
        self.assertEqual(self.client.put(url, json={"target": "运维值班群", "when": "sometimes"},
                                         auth=self.auth).status_code, 400)
        self.assertEqual(self.client.put("/api/chat/notify/schedule/nope", json={"target": "运维值班群"},
                                         auth=self.auth).status_code, 404)
        self.assertEqual(self.client.put("/api/chat/notify/mail/x", json={}, auth=self.auth).status_code, 404)
        with patch.object(self.bridge, "status", side_effect=BridgeError("连不上转接程序：ConnectionRefusedError")):
            self.assertEqual(self.client.put(url, json={"target": "运维值班群"}, auth=self.auth).status_code, 503)
        self.assertEqual(self.client.put(url, json={"target": ""}, auth=self.auth).json()["target"], "")
        self.assertIsNone(chat_store.notify_get("schedule", self.schedule["id"]))

    def test_test_push_is_rate_limited_and_only_by_name(self):
        ok = self.client.post("/api/chat/test-push", json={"target": "王某某"}, auth=self.auth)
        self.assertEqual(ok.json(), {"sent": True, "held": False, "target": "王某某"})
        self.assertIn("测试消息", self.bridge.pushes[0][1])
        self.assertEqual(self.client.post("/api/chat/test-push", json={"target": "王某某"},
                                          auth=self.auth).status_code, 429)
        self.assertEqual(self.client.post("/api/chat/test-push", json={"target": "外面"}, auth=self.auth).status_code, 400)
        self.assertEqual(self.log(), [("test", "王某某", "sent"), ("test", "外面", "failed")])

    def test_status_shows_problems_and_paste_ready_lines(self):
        chat_store.unknown_record(message("问一下", chat_id="9999"))
        status = self.client.get("/api/chat/status", auth=self.auth).json()
        self.assertTrue(status["bridge"]["reachable"])
        self.assertEqual(status["bridge"]["target_kinds"], {"运维值班群": "chat", "王某某": "user"})
        self.assertEqual([g["name"] for g in status["config"]["groups"]], ["运维值班群", "研发交流群"])
        self.assertIn("「运维值班群」开的工具 host_disk、container_stats 现在不可用", status["problems"][0])
        paste = status["unknown"][0]["paste"]
        self.assertEqual(paste, {"chat_yaml": 'groups:\n  "9999": {name: "群里的名字"}',
                                 "targets_yaml": 'targets:\n  "群里的名字": {chat_id: "9999"}'})


if __name__ == "__main__":
    unittest.main()
