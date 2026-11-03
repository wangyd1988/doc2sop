"""kb-app 接钉钉（chat.yaml 写 platform: dingtalk）：钉钉的会话 ID、按平台隔离白名单和推送、markdown、平台名。

问答走真实的公共核心，转接程序用 test_chat_channel 的进程内假对象，换成「钉钉的」：/status 报 platform 和 formats。
云上协同那条路不变由 test_chat_ccwork_unchanged 和原有的 test_chat_* 管着。
"""
import json
import sqlite3
import unittest

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量
from tests.test_ask_golden import Scenario
from tests.test_chat_channel import ChatTestCase, FakeBridge, message
from tests.test_chat_push import ROW, PushCase

from app import chat_api, chat_bridge, chat_channel, chat_config, chat_format, chat_push, chat_store, conversations
from app import main as app_main
from app.config import WEB_PASSWORD, WEB_USER

GROUP = "cidGroupConversationX7Q1=="
DINGTALK = f"""
platform: dingtalk
robot_name: doc2sop
contact: 王某某
groups:
  "{GROUP}": {{name: 钉钉值班群}}
people:
  "manager1234": {{name: 老板}}
"""


class DingTalkBridge(FakeBridge):
    """钉钉的转接程序：/status 报平台和格式；reply_text、push 多收一个 fmt。"""

    def __init__(self, platform="dingtalk", send=True):
        super().__init__()
        self.platform, self.send = platform, send
        self.formats = []

    def reply_text(self, handle, text, mention=False, fmt=None):
        self.formats.append(("text", fmt))
        return super().reply_text(handle, text, mention)

    def push(self, target, text, fmt=None):
        self.formats.append(("push", fmt))
        return super().push(target, text)

    def status(self):
        return {**super().status(), "platform": self.platform, "formats": ["text", "markdown"], "send": self.send}


def ding(text, chat_type="group", chat_id=GROUP, sender_id="staff58c3", **kwargs):
    event = message(text, chat_type=chat_type, chat_id=chat_id, sender_id=sender_id, **kwargs)
    event["platform"] = "dingtalk"
    if chat_type == "single":
        event["chat_id"] = "cidSingleChatY9Z2=="
    return event


class DingTalkConfigTests(unittest.TestCase):
    def parse(self, text):
        chat_config.CHAT_FILE.write_text(text, encoding="utf-8")
        chat_config.reset()
        self.addCleanup(lambda: (chat_config.CHAT_FILE.unlink(missing_ok=True), chat_config.reset()))
        return chat_config.load()

    def test_dingtalk_ids(self):
        cfg = self.parse(DINGTALK.replace("people:", '  "1001": {name: 数字群}\npeople:'))
        self.assertEqual(cfg.platform, "dingtalk")
        self.assertEqual(sorted(cfg.groups), [GROUP])                   # 钉钉下数字 ID 不认
        self.assertEqual(len(cfg.problems), 1)
        self.assertIsNotNone(cfg.scope("single", "", "manager1234"))
        self.assertEqual(chat_config.public(cfg)["platform_name"], "钉钉")

    def test_a_misspelled_platform_opens_nothing(self):
        cfg = self.parse(DINGTALK.replace("platform: dingtalk", "platform: dingding"))
        self.assertEqual((cfg.platform, cfg.paused, cfg.groups, cfg.people), ("", True, {}, {}))
        self.assertIn("platform 只能是", cfg.problems[0])


class DingTalkChannelTests(ChatTestCase):
    def setUp(self):
        super().setUp()
        self.write(DINGTALK)
        self.bridge = DingTalkBridge()
        self.channel = chat_channel.Channel(self.bridge, app_main.start_chat_turn, app_main.turn_events)
        self.addCleanup(self.channel.stop)

    def test_group_question_is_answered_with_dingtalk_wording(self):
        with Scenario(self) as s:
            event = ding("kb-app 内存高怎么办")
            self.send(event)
        self.assertIn("答案第一段", self.final(event))
        system = s.record["plain_model"][0][0]
        self.assertTrue(system[1].endswith(chat_format.chat_rules("dingtalk")))
        self.assertIn("发到钉钉的群聊或私聊里", system[1])
        self.assertNotIn("云上协同", system[1])
        title = conversations.list_conversations()[0]["title"]
        self.assertTrue(title.startswith("钉钉·钉钉值班群："), title)
        self.assertNotIn("format", json.dumps([p for _, p in self.bridge.packets]))      # 没写 markdown: true

    def test_markdown_only_when_asked_and_declared(self):
        self.write(DINGTALK + "markdown: true\n")
        with Scenario(self):
            event = ding("kb-app 内存高怎么办")
            self.send(event)
            self.send(ding("帮助"))
        self.assertEqual({p.get("format") for h, p in self.bridge.packets if h == event["handle"]}, {"markdown"})
        self.assertEqual(self.bridge.formats, [("text", "markdown")])

    def test_help_says_where_the_data_goes(self):
        event = ding("帮助", chat_type="single", sender_id="manager1234")
        self.send(event)
        text = self.texts(event)[0]
        self.assertIn("经钉钉服务器", text)
        self.assertNotIn("云上协同", text)

    def test_messages_from_the_other_platform_are_dropped(self):
        self.send(message("@doc2sop 问一下", chat_id="1001"))           # 云上协同的消息，chat.yaml 是钉钉的
        self.assertEqual((self.bridge.packets, self.bridge.texts, chat_store.unknown_list()), ([], [], []))
        self.assertEqual(self.channel.counters["platform_mismatch"], 1)

    def test_a_ccwork_allowlist_never_opens_dingtalk_users(self):
        """换了钉钉的转接程序、chat.yaml 没改：旧白名单里同 ID 的人在钉钉里也不能用。"""
        self.write("groups:\n  \"1001\": {name: 旧群}\npeople:\n  \"staff58c3\": {name: 同名的人}\n")
        self.send(ding("问一下", chat_type="single"))
        self.assertEqual((self.bridge.packets, self.bridge.texts), ([], []))
        self.assertIn("转接程序是钉钉的，chat.yaml 是云上协同的", self.channel._hold())

    def test_receive_only_bridge_holds_polling(self):
        self.assertEqual(self.channel._hold(), "")
        self.bridge.send = False
        self.bridge._chat_described = None
        self.assertIn("只收不发", self.channel._hold())
        ccwork = FakeBridge()                         # 云上协同的转接程序只收不发时照旧取（行为不变）
        self.write("groups:\n  \"1001\": {name: 群}\n")
        self.assertEqual(chat_channel.Channel(ccwork, None, None)._hold(), "")

    def test_web_follow_up_is_refused_with_the_right_name(self):
        with Scenario(self):
            self.send(ding("kb-app 内存高怎么办"))
        conversation = conversations.list_conversations()[0]["id"]
        self.assertTrue(chat_api.readonly(conversation))
        self.assertEqual(chat_api.readonly_reason(conversation),
                         "这是钉钉里的对话，网页上只能查看；要接着问请新建对话")
        self.assertEqual(chat_api.readonly_reason("not-a-chat"),
                         "这是云上协同里的对话，网页上只能查看；要接着问请新建对话")


class DingTalkPushTests(PushCase):
    def setUp(self):
        super().setUp()
        chat_config.CHAT_FILE.write_text(DINGTALK, encoding="utf-8")
        chat_config.reset()
        self.bridge = DingTalkBridge()
        chat_bridge._current["bridge"] = self.bridge

    def test_settings_saved_for_ccwork_are_not_pushed_to_dingtalk(self):
        chat_store.notify_set("schedule", "s1", "运维值班群", "always", "always")            # 换平台之前存的
        result = chat_push.after_run(self.run_record("anomaly", [ROW]))
        self.assertEqual(result["status"], "skipped")
        self.assertIn("请重新选推送目标", result["reason"])
        self.assertEqual(self.bridge.pushes, [])
        chat_store.notify_set("schedule", "s1", "运维值班群", "always", "always", "dingtalk")
        self.assertEqual(chat_push.after_run(self.run_record("anomaly", [ROW]))["status"], "sent")
        self.assertEqual(self.bridge.formats, [("push", None)])            # 推送是排好版的纯文本

    def test_a_dingtalk_setting_is_not_pushed_through_a_ccwork_bridge(self):
        chat_store.notify_set("schedule", "s1", "运维值班群", "always", "always", "dingtalk")
        chat_bridge._current["bridge"] = FakeBridge()         # 又换回了云上协同的转接程序，chat.yaml 还是钉钉的
        result = chat_push.after_run(self.run_record("anomaly", [ROW]))
        self.assertEqual(result["status"], "skipped")
        self.assertIn("转接程序是云上协同的，chat.yaml 是钉钉的", result["reason"])

    def test_test_push_and_api(self):
        app = FastAPI(dependencies=[Depends(app_main.require_auth)])
        app.include_router(chat_api.router)
        client = TestClient(app)
        self.addCleanup(client.close)
        auth = (WEB_USER, WEB_PASSWORD)
        chat_api._tests["times"].clear()
        chat_api._tests["by_target"].clear()
        self.assertEqual(client.post("/api/chat/test-push", json={"target": "王某某"}, auth=auth).status_code, 200)
        self.assertIn("钉钉的推送能用", self.bridge.pushes[0][1])
        status = client.get("/api/chat/status", auth=auth).json()
        self.assertEqual((status["bridge"]["platform"], status["config"]["platform"]), ("dingtalk", "dingtalk"))
        chat_store.notify_set("schedule", "s9", "运维值班群", "always", "always")         # 云上协同时存的
        item = [i for i in client.get("/api/chat/notify", auth=auth).json()["items"] if i["id"] == "s9"][0]
        self.assertEqual((item["target"], item["stale"]), ("", "运维值班群"))
        chat_config.CHAT_FILE.write_text("groups: {}\n", encoding="utf-8")                # chat.yaml 忘了改
        chat_config.reset()
        chat_api._tests["by_target"].clear()
        refused = client.post("/api/chat/test-push", json={"target": "运维值班群"}, auth=auth)
        self.assertEqual(refused.status_code, 409)
        self.assertIn("转接程序是钉钉的", client.get("/api/chat/status", auth=auth).json()["problems"][0])

    def test_weekly_digest_keys_are_per_platform(self):
        from tests.test_chat_push import MONDAY_0930
        chat_config.CHAT_FILE.write_text(DINGTALK + "digest: {target: 王某某, weekday: 1, hour: 9}\n", encoding="utf-8")
        chat_config.reset()
        chat_push.maybe_digest(MONDAY_0930)
        self.assertEqual(chat_store.state_get("digest:王某某:"), "")
        self.assertEqual(chat_store.state_get("digest:dingtalk:王某某:"), "2026-W45")


class StoreMigrationTests(unittest.TestCase):
    def test_old_tables_get_a_platform_column(self):
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript("CREATE TABLE chat_notify (source_kind TEXT NOT NULL, source_id TEXT NOT NULL, target TEXT"
                         " NOT NULL, send_when TEXT NOT NULL, send_repeat TEXT NOT NULL, state TEXT NOT NULL DEFAULT"
                         " '{}', updated_at TEXT NOT NULL, PRIMARY KEY (source_kind, source_id));"
                         "INSERT INTO chat_notify VALUES ('schedule', 's1', '群', 'always', 'always', '{}', 'x');")
        original = conversations.db
        conversations.db = db
        try:
            chat_store.ensure()
            chat_store.ensure()
            self.assertEqual(chat_store.notify_get("schedule", "s1")["platform"], "ccwork")
            chat_store.push_log("test", "群", "sent")
            self.assertEqual(chat_store.push_recent(1)[0]["platform"], "ccwork")
        finally:
            conversations.db = original


class BridgeClientTests(unittest.TestCase):
    def test_ccwork_request_bodies_are_unchanged(self):
        bridge = chat_bridge.Bridge("http://127.0.0.1:9", "t" * 40)
        sent = []
        bridge._call = lambda method, path, body=None, timeout=None: sent.append((path, body)) or {}
        bridge.reply_text("h", "答", True)
        bridge.push("群", "推")
        bridge.reply_text("h", "答", fmt="markdown")
        bridge.push("群", "推", fmt="markdown")
        self.assertEqual(sent, [("/reply", {"handle": "h", "text": "答", "mention": True}),
                                ("/push", {"target": "群", "text": "推"}),
                                ("/reply", {"handle": "h", "text": "答", "mention": False, "format": "markdown"}),
                                ("/push", {"target": "群", "text": "推", "format": "markdown"})])

    def test_describe_defaults_old_bridges_to_ccwork(self):
        self.assertEqual(chat_bridge.describe(FakeBridge()), {"platform": "ccwork", "formats": ("text",), "send": None})
        self.assertEqual(chat_bridge.describe(DingTalkBridge())["formats"], ("text", "markdown"))


if __name__ == "__main__":
    unittest.main()
