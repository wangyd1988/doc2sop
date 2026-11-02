"""云上协同的聊天线程（app/chat_channel.py）：白名单、命令、限频、对话对应、流式回复、收件表、执行 SOP。

问答走真实的公共核心（main.start_chat_turn / turn_events）：模型、检索、工具服务用 test_ask_golden 的替身，
转接程序用进程内的假对象（FakeBridge），记下收到的每一包、每一条。
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import tests.support  # noqa: F401  隔离 DATA_DIR 和环境变量
from tests import test_route_auth as route_auth
from tests.support import clear_graph
from tests.test_ask_golden import SOP_TABLE, TOOLS, Scenario, call

from app import autorun, chat_api, chat_channel, chat_config, chat_format, chat_store, conversations, graph, playbooks
from app import runs
from app import main as app_main
from app.chat_bridge import BridgeError
from app.config import CHAT_FILE, WEB_PASSWORD, WEB_USER

CONFIG = """
robot_name: doc2sop
contact: 王某某
groups:
  "1001": {name: 运维值班群, tools: [host_disk, container_stats]}
  "1002": {name: 研发交流群}
people:
  "u_boss": {name: 老板}
"""
CHAT_TABLES = ("chat_threads", "chat_turns", "chat_inbox", "chat_unknown", "chat_notify", "chat_push_log", "chat_state")


class FakeBridge:
    """进程内的转接程序：记下每一包流式消息、每一条文字、每一次推送。stream_errors 里放依次要抛的异常（None 是成功）。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.packets, self.attempts, self.texts, self.pushes = [], [], [], []
        self.stream_errors = []
        self.targets = {"运维值班群": "chat", "王某某": "user"}

    def reply_stream(self, handle, packet):
        with self.lock:
            self.attempts.append((handle, dict(packet)))
            error = self.stream_errors.pop(0) if self.stream_errors else None
            if error is not None:
                raise error
            self.packets.append((handle, dict(packet)))
        return {"ok": True}

    def reply_text(self, handle, text, mention=False):
        with self.lock:
            self.texts.append((handle, text, mention))
        return {"ok": True}

    def push(self, target, text):
        if target not in self.targets:
            raise BridgeError("没有这个推送目标", status=404, definite=True)
        with self.lock:
            self.pushes.append((target, text))
        return {"ok": True}

    def status(self):
        return {"state": "connected", "targets": sorted(self.targets), "target_kinds": dict(self.targets)}

    def events(self, epoch, after, wait=25.0):
        time.sleep(min(wait, 0.05))
        return epoch or "e1", []


_seq = [0]


def message(text, chat_type="group", chat_id="1001", sender_id="u_zhang", sender_name="张三", kind="text", key=None):
    _seq[0] += 1
    return {"id": _seq[0], "handle": f"h{_seq[0]}", "kind": kind, "platform": "ccwork", "chat_type": chat_type,
            "chat_id": chat_id if chat_type != "single" else "0", "chat_name": "群里的名字", "sender_id": sender_id,
            "sender_name": sender_name, "sender_type": 0, "msg_key": key or f"key-{_seq[0]}", "text": text,
            "received_at": "2026-11-02T01:00:00Z"}


def clear_chat():
    with conversations.lock:
        conversations.db.execute("DELETE FROM messages")
        conversations.db.execute("DELETE FROM conversations")
        for table in CHAT_TABLES:
            conversations.db.execute(f"DELETE FROM {table}")
        conversations.db.commit()


class ChatTestCase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        chat_store.ensure()
        clear_chat()
        clear_graph()
        with playbooks.lock:
            playbooks.db.execute("DELETE FROM steps")
            playbooks.db.execute("DELETE FROM playbooks")
            playbooks.db.commit()
        self.write(CONFIG)
        self.addCleanup(lambda: (CHAT_FILE.unlink(missing_ok=True), chat_config.reset()))
        self.bridge = FakeBridge()
        self.channel = chat_channel.Channel(self.bridge, app_main.start_chat_turn, app_main.turn_events)
        self.addCleanup(self.channel.stop)
        retry = patch.object(chat_channel.Streamer, "RETRY_WAIT", (0.0, 0.0, 0.0))
        retry.start()
        self.addCleanup(retry.stop)

    def write(self, text):
        CHAT_FILE.write_text(text, encoding="utf-8")
        chat_config.reset()

    def send(self, *events):
        for event in events:
            self.channel.receive(event)
        self.assertTrue(self.channel.wait_idle(20), "聊天线程没有在 20 秒内做完")

    def stream(self, event):
        return [packet for handle, packet in self.bridge.packets if handle == event["handle"]]

    def final(self, event):
        packets = self.stream(event)
        self.assertEqual([p["type"] for p in packets[-2:]], ["delta", "done"])
        self.assertEqual(packets[-1]["content"], packets[-2]["content"])
        return packets[-1]["content"]

    def texts(self, event):
        return [text for handle, text, _ in self.bridge.texts if handle == event["handle"]]

    def threads(self):
        with conversations.lock:
            return [dict(r) for r in conversations.db.execute("SELECT * FROM chat_threads ORDER BY id").fetchall()]


class AnswerTests(ChatTestCase):
    def test_group_question_streams_and_lands_in_a_chat_conversation(self):
        with Scenario(self) as s:
            event = message("@doc2sop kb-app 内存高怎么办")
            self.send(event)
        packets = self.stream(event)
        self.assertEqual([p["seq"] for p in packets], list(range(1, len(packets) + 1)))
        self.assertEqual({p["request_id"] for p in packets}, {packets[0]["request_id"]})
        self.assertEqual({p["message_type"] for p in packets}, {"cover"})
        final = "↪ 回复 张三：kb-app 内存高怎么办\n答案第一段，第二段 [1]\n\n出处：[1] 退款制度.md"
        self.assertEqual(self.final(event), final)
        # 第一包是「正在查」；替身模型太快、答案先出来了时，第一包就是答案
        self.assertIn(packets[0]["content"], ("↪ 回复 张三：kb-app 内存高怎么办\n" + chat_format.STATUS_SEARCH, final))
        # 群聊的提示：只接在系统提示词末尾
        system = s.record["plain_model"][0][0]
        self.assertEqual(system[0], "system")
        self.assertTrue(system[1].endswith(chat_format.CHAT_RULES))
        # 普通对话：标题带来源；图谱里渠道是 chat
        items = conversations.list_conversations()
        self.assertEqual([c["title"] for c in items], ["云上协同·运维值班群：kb-app 内存高怎么办"[:40]])
        self.assertEqual([m["role"] for m in conversations.messages_of(items[0]["id"])], ["user", "assistant"])
        with graph.lock:
            channels = [r[0] for r in graph.db.execute("SELECT channel FROM executions").fetchall()]
        self.assertEqual(channels, ["chat"])
        thread = self.threads()[0]
        self.assertEqual((thread["platform"], thread["chat_type"], thread["chat_id"], thread["sender_id"],
                          thread["conversation_id"], thread["closed"]),
                         ("ccwork", "group", "1001", "u_zhang", items[0]["id"], 0))
        self.assertEqual(thread["last_message_id"], chat_store.last_message_id(items[0]["id"]))
        # 收件表：处理完，正文清掉
        item = chat_store.inbox_get(event["msg_key"])
        self.assertEqual((item["status"], item["event"]["text"]), ("done", ""))

    def test_follow_ups_continue_until_new_topic_or_someone_else_writes(self):
        with Scenario(self) as s:
            self.send(message("kb-app 内存高怎么办"))
            self.send(message("那 B 机器呢"))
            self.assertEqual(len(conversations.list_conversations()), 1)
            self.assertEqual(s.record["rewrite"][1]["history"][0], ["user", "kb-app 内存高怎么办"])   # 带着上文改写
            self.send(message("新话题"))
            self.send(message("退款多久到账"))
            self.assertEqual(len(conversations.list_conversations()), 2)
            # 回滚到旧版本期间有人在网页上续问过：最后一条对不上，另开
            latest = self.threads()[-1]["conversation_id"]
            conversations.add_message(latest, "user", "网页上补问的")
            self.send(message("还有呢"))
            self.assertEqual(len(conversations.list_conversations()), 3)
            # 别人在同一个群里问：是他自己的对话
            self.send(message("我也问一个", sender_id="u_li", sender_name="李四"))
        self.assertEqual(len(conversations.list_conversations()), 4)

    def test_private_chat_has_no_reply_line(self):
        with Scenario(self):
            event = message("退款多久到账", chat_type="single", sender_id="u_boss", sender_name="老板")
            self.send(event)
        self.assertEqual(self.final(event), "答案第一段，第二段 [1]\n\n出处：[1] 退款制度.md")

    def test_only_the_allowlisted_data_tools_are_bound(self):
        self.write(CONFIG.replace("tools: [host_disk, container_stats]", "tools: [host_disk]"))
        script = [([call("host_disk")], ""), ([], "根分区 87%。")]
        with Scenario(self, script=script, ops=True) as s:
            self.send(message("磁盘满了吗"))
            self.assertEqual(s.record["agent_model"][0]["tools"], ["host_disk"])
            system = s.record["agent_model"][0]["messages"][0]
            self.assertTrue(system["content"].endswith(chat_format.CHAT_RULES))
            # 没开数据工具的群：工具服务在线也不绑，走纯知识库问答
            self.send(message("退款多久到账", chat_id="1002"))
            self.assertEqual(len(s.record["agent_model"]), 2)
            self.assertEqual(len(s.record["plain_model"]), 1)

    def test_categories_narrow_the_prefetch(self):
        self.write(CONFIG.replace("{name: 研发交流群}", "{name: 研发交流群, categories: [运维]}"))
        with Scenario(self) as s:
            self.send(message("值班怎么交接", chat_id="1002"))
        self.assertEqual(s.record["retrieve"][0]["within"], frozenset({"值班手册.pdf"}))

    def test_failure_is_reported_in_the_group(self):
        with Scenario(self, retrieve_fails=RuntimeError("chroma down")):
            event = message("退款多久到账")
            self.send(event)
        self.assertEqual(self.final(event), "↪ 回复 张三：退款多久到账\n这次没答出来（知识库检索出错），请稍后再问。")
        self.assertEqual(conversations.list_conversations(), [])        # 新对话没答出来：和网页一样不留空对话


class StreamTests(ChatTestCase):
    def test_abandoning_mid_stream_still_wraps_up_in_this_thread(self):
        finished = []
        real = app_main.finish_root_run

        def finish(root, **kwargs):
            finished.append(threading.current_thread().name)
            return real(root, **kwargs)

        script = [([call("host_disk"), call("container_stats", name="kb-app")], ""), ([], SOP_TABLE)]
        with Scenario(self, {"PLAN_TOOL": True}, script=script, ops=True), \
                patch.object(autorun, "AGENT_MODE", "auto"), \
                patch.object(app_main, "finish_root_run", side_effect=finish), \
                patch.object(chat_channel, "EXECUTE_TIMEOUT", -1.0):
            pid = playbooks.save(None, "每日巡检", "每天上班后", [
                {"tool": "host_disk", "args": {}}, {"tool": "container_stats", "args": {"name": ""}}], set(TOOLS))
            event = message("执行 每日巡检 name=kb-app")
            self.send(event)
        # 消费到一半就放弃了：收尾照常在聊天的工作线程里做完——根 run 收了、图谱的执行收了、执行记录收了、空对话删了
        self.assertEqual(len(finished), 1)
        self.assertTrue(finished[0].startswith("chat"), finished)
        run = runs.listing(pid)[0][0]
        self.assertEqual((run["status"], run["trigger"], run["level"]), ("done", "chat", "failed"))
        self.assertIsNotNone(graph.execution(run["id"])["finished_at"])
        self.assertEqual(conversations.list_conversations(), [])
        self.assertEqual(self.final(event), "↪ 回复 张三：执行 每日巡检 name=kb-app\n这次没答出来（模型超时），请稍后再问。")

    def test_rejected_stream_falls_back_to_one_plain_text_with_a_real_mention(self):
        self.bridge.stream_errors = [BridgeError("参数不对", status=502, definite=True)]
        with Scenario(self):
            event = message("退款多久到账")
            self.send(event)
        self.assertEqual(self.stream(event), [])
        self.assertEqual(self.bridge.texts, [(event["handle"], "↪ 回复 张三：退款多久到账\n答案第一段，第二段 [1]\n\n"
                                                               "出处：[1] 退款制度.md", True)])

    def test_uncertain_results_resend_the_same_packet(self):
        self.bridge.stream_errors = [BridgeError("超时", status=0), BridgeError("平台 5xx", status=502), None]
        with Scenario(self):
            event = message("退款多久到账")
            self.send(event)
        first = [packet for _, packet in self.bridge.attempts[:3]]
        self.assertEqual(first, [first[0]] * 3)                         # 同一个 seq、同样的内容
        self.assertEqual([p["seq"] for p in self.stream(event)], list(range(1, len(self.stream(event)) + 1)))
        self.assertIn("答案第一段", self.final(event))

    def test_giving_up_after_retries_sends_nothing_more(self):
        self.bridge.stream_errors = [BridgeError("超时", status=0)] * 4
        with Scenario(self):
            event = message("退款多久到账")
            self.send(event)
        self.assertEqual(self.stream(event), [])
        self.assertEqual(len(self.bridge.attempts), 4)
        self.assertEqual(self.bridge.texts, [])                         # 结果不明：不另发整段，免得出现两遍
        self.assertEqual(len(conversations.list_conversations()), 1)    # 回答照常记下（网页上看得到）

    def test_streamer_paces_packets_and_keeps_the_last_two_for_the_end(self):
        clock = {"now": 0.0}
        sent = []

        class Bridge:
            def reply_stream(self, handle, packet):
                sent.append(dict(packet))

        def wait_for(count, timeout=5.0):
            deadline = time.monotonic() + timeout
            while len(sent) < count and time.monotonic() < deadline:
                time.sleep(0.01)
            time.sleep(0.05)
            return len(sent)

        streamer = chat_channel.Streamer(Bridge(), "h", lambda text, status: f"{text}|{status}",
                                         clock=lambda: clock["now"])
        streamer.MAX_PACKETS = 5
        streamer.start()
        self.assertEqual(wait_for(1), 1)
        self.assertEqual(sent[0]["content"], f"|{chat_format.STATUS_SEARCH}")      # 第一包马上发
        clock["now"] = 1.0
        streamer.update("短", "")                   # 状态变了，可前 15 秒要隔 1.5 秒
        self.assertEqual(wait_for(2, 0.3), 1)
        clock["now"] = 1.6
        streamer.update()
        self.assertEqual(wait_for(2), 2)
        self.assertEqual(sent[1]["content"], "短|")
        clock["now"] = 3.2
        streamer.update("短一点点", "")              # 新增不到 20 个字、状态没变：不发
        self.assertEqual(wait_for(3, 0.3), 2)
        clock["now"] = 4.8
        streamer.update("长" * 40, "")
        self.assertEqual(wait_for(3), 3)
        clock["now"] = 9.0
        streamer.update("长" * 80, "")              # 最多 MAX_PACKETS - 2 个中间包：最后两包留给正文和 done
        self.assertEqual(wait_for(4, 0.3), 3)
        self.assertTrue(streamer.finish("全文"))
        self.assertEqual([(p["seq"], p["type"], p["content"]) for p in sent[3:]],
                         [(4, "delta", "全文"), (5, "done", "全文")])

class GateTests(ChatTestCase):
    def test_unknown_chats_are_counted_without_content_and_told_once(self):
        with Scenario(self) as s:
            first, second = message("机密问题一", chat_id="9999"), message("机密问题二", chat_id="9999")
            self.send(first, second)
            private = message("你好", chat_type="single", sender_id="u_stranger", sender_name="路人")
            self.send(private)
        self.assertEqual(s.record["plain_model"], [])
        self.assertEqual(self.texts(first), ["↪ 回复 张三：机密问题一\n这个群还没有开通 doc2sop，需要的话请联系 王某某。"])
        self.assertEqual(self.texts(second), [])                        # 24 小时内只回一次
        self.assertEqual(self.texts(private), ["私聊还没有开通 doc2sop，需要的话请联系 王某某。"])
        unknown = {u["ident"]: u for u in chat_store.unknown_list()}
        self.assertEqual((unknown["9999"]["count"], unknown["9999"]["sender_name"]), (2, "张三"))
        self.assertIn("u_stranger", unknown)
        with conversations.lock:
            stored = json.dumps([dict(r) for r in conversations.db.execute("SELECT * FROM chat_unknown").fetchall()]
                                + [dict(r) for r in conversations.db.execute("SELECT * FROM chat_inbox").fetchall()],
                                ensure_ascii=False)
        self.assertNotIn("机密问题", stored)                             # 没开通的：不记内容、不进收件表
        self.assertEqual(conversations.list_conversations(), [])

    def test_silent_mode_records_but_does_not_reply(self):
        self.write(CONFIG + "unknown_reply: silent\n")
        self.send(message("问一下", chat_id="9999"))
        self.assertEqual(self.bridge.texts, [])
        self.assertEqual(len(chat_store.unknown_list()), 1)

    def test_paused_answers_nothing_but_says_so_once(self):
        self.write(CONFIG + "paused: true\n")
        with Scenario(self) as s:
            first, second = message("问题一"), message("问题二")
            self.send(first, second)
        self.assertEqual(s.record["plain_model"], [])
        self.assertEqual(self.texts(first), ["↪ 回复 张三：问题一\ndoc2sop 暂停服务中，请稍后再问，或联系 王某某。"])
        self.assertEqual(self.texts(second), [])
        self.assertEqual(chat_store.inbox_get(second["msg_key"])["status"], "done")

    def test_per_person_and_per_group_limits(self):
        self.write(CONFIG + "limits: {person_per_hour: 1, group_per_hour: 2}\n")
        with Scenario(self) as s:
            events = [message("问题一"), message("问题二"), message("问题三"),
                      message("李四的问题", sender_id="u_li", sender_name="李四"),
                      message("王五的问题", sender_id="u_wang", sender_name="王五")]
            for event in events:
                self.send(event)
        self.assertEqual(len(s.record["plain_model"]), 2)              # 张三一个、李四一个；王五碰到了群的上限
        self.assertEqual(self.texts(events[1]), ["↪ 回复 张三：问题二\n你这一小时问得太多了（最多 1 个），请稍后再问。"])
        self.assertEqual(self.texts(events[2]), [])                     # 提示每人 10 分钟最多一次
        self.assertEqual(self.texts(events[4]), ["↪ 回复 王五：王五的问题\n这里这一小时问得太多了（最多 2 个），请稍后再问。"])

    def test_one_question_at_a_time_per_person(self):
        self.channel._busy.add(("ccwork", "group", "1001", "u_zhang"))
        with Scenario(self) as s:
            event = message("问题")
            self.send(event)
        self.assertEqual(s.record["plain_model"], [])
        self.assertEqual(self.texts(event), ["↪ 回复 张三：问题\n上一个问题还在回答，答完再问。"])

    def test_duplicates_and_malformed_messages_are_dropped(self):
        with Scenario(self) as s:
            event = message("问题", key="same")
            self.send(event, {**event, "id": 99, "handle": "h-again"}, {"kind": "text"}, "不是对象")
        self.assertEqual(len(s.record["plain_model"]), 1)
        self.assertEqual(self.channel.status()["counters"], {"duplicate": 1, "malformed": 2})

    def test_non_text_messages_get_one_explanation_a_day(self):
        image, again = message("", kind="unsupported"), message("", kind="unsupported")
        locked = message("", chat_type="single", sender_id="u_boss", kind="undecryptable")
        self.send(image, again, locked)
        self.assertIn("目前只能看文字消息", self.texts(image)[0])
        self.assertEqual(self.texts(again), [])
        self.assertEqual(self.texts(locked), ["这条消息解不开（加密方式不认识），请换成普通文字再发一次。"])

    def test_restart_resumes_recent_messages_and_reports_interrupted_ones(self):
        now = datetime.now(timezone.utc)
        recent, old = now.isoformat(timespec="seconds"), (now - timedelta(minutes=30)).isoformat(timespec="seconds")
        rows = [(message("答到一半的"), "processing", recent), (message("还没开始的"), "received", recent),
                (message("太早的"), "received", old)]
        with conversations.lock:
            for event, status, at in rows:
                conversations.db.execute("INSERT INTO chat_inbox (msg_key, platform, event, status, received_at,"
                                         " updated_at) VALUES (?, 'ccwork', ?, ?, ?, ?)",
                                         (event["msg_key"], json.dumps(event, ensure_ascii=False), status, at, at))
            conversations.db.commit()
        with Scenario(self) as s:
            self.channel.start()
            self.assertTrue(self.channel.wait_idle(20))
        (cut, _, _), (pending, _, _), (stale, _, _) = rows
        self.assertEqual(self.texts(cut), ["↪ 回复 张三：答到一半的\n刚才服务重启，这个问题没答完，请再问一次。"])
        self.assertEqual(chat_store.inbox_get(cut["msg_key"])["status"], "interrupted")
        self.assertIn("答案第一段", self.final(pending))                    # 收到了还没开始答的照常答
        self.assertEqual(len(s.record["plain_model"]), 1)               # 答到一半的不重答（至多一次）
        self.assertEqual((chat_store.inbox_get(stale["msg_key"])["status"], self.stream(stale), self.texts(stale)),
                         ("expired", [], []))


class CommandTests(ChatTestCase):
    def test_help_new_topic_more_and_unhelpful(self):
        self.write(CONFIG + "limits: {max_chars: 500}\n")
        long_answer = ("第一段。" * 100 + "\n\n" + "第二段。" * 100 + "\n\n" + "第三段。" * 100,)
        with Scenario(self, plain=long_answer):
            self.send(message("没答好"))
            ask = message("讲讲值班制度")
            self.send(ask)
            self.assertIn(chat_format.MORE_HINT, self.final(ask))
            more, again, bad = message("全文"), message("全文"), message("没答好 漏了交接班的部分")
            self.send(more, again, bad)
        self.assertEqual(self.texts(more), ["↪ 回复 张三：全文\n" + "第二段。" * 100, "↪ 回复 张三：全文\n" + "第三段。" * 100])
        self.assertEqual(self.texts(again), ["↪ 回复 张三：全文\n没有没发完的部分。"])
        execution = self.threads()[-1]["last_execution_id"]
        with graph.lock:
            feedback = [tuple(r) for r in graph.db.execute("SELECT execution_id, verdict, note FROM feedback").fetchall()]
        self.assertEqual(feedback, [(execution, "unhelpful", "漏了交接班的部分")])
        helped = message("帮助")
        self.send(helped)
        self.assertIn("执行 / 执行 2", self.texts(helped)[0])
        self.send(message("新话题"))
        self.assertEqual(self.threads()[-1]["closed"], 1)

    def test_verdicts_only_apply_to_an_execution(self):
        with Scenario(self):
            self.send(message("讲讲值班制度"))
            verdict = message("误报")
            self.send(verdict)
        self.assertEqual(self.texts(verdict), ["↪ 回复 张三：误报\n「误报」只对你上一次的 SOP 执行有效；你上一条不是 SOP 执行。"])


class ExecuteTests(ChatTestCase):
    def setUp(self):
        super().setUp()
        mode = patch.object(autorun, "AGENT_MODE", "auto")      # 测试环境的 AGENT_MODE 是 off；执行前的检查和 main 用同一个值
        mode.start()
        self.addCleanup(mode.stop)

    def book(self):
        return playbooks.save(None, "每日巡检", "每天上班后", [
            {"tool": "host_disk", "args": {}}, {"tool": "container_stats", "args": {"name": ""}}], set(TOOLS))

    def test_execute_checks_parameters_runs_and_takes_a_verdict(self):
        script = [([call("host_disk"), call("container_stats", name="kb-app")], ""), ([], SOP_TABLE)]
        with Scenario(self, {"PLAN_TOOL": True}, script=script, ops=True) as s:
            pid = self.book()
            missing, unknown, ok = message("执行 每日巡检"), message("执行 每日巡检 host=a"), \
                message("@doc2sop 执行 每日巡检 name=kb-app")
            for event in (missing, unknown, ok):
                self.send(event)            # 同一个人：一个一个来（上一个没答完时会被挡回去）
            verdict = message("误报 其实是日志")
            self.send(verdict)
        self.assertEqual(self.texts(missing), ["↪ 回复 张三：执行 每日巡检\n这个 SOP 需要：name。请回：执行 每日巡检 name=…"])
        self.assertEqual(self.texts(unknown), ["↪ 回复 张三：执行 每日巡检 host=a\n这个 SOP 没有参数 host，要填的是：name。"
                                                "请回：执行 每日巡检 name=…"])
        run = runs.listing(pid)[0][0]
        self.assertEqual((run["trigger"], run["trigger_name"], run["note"], run["params"], run["level"]),
                         ("chat", "群聊", "云上协同·运维值班群·张三", {"name": "kb-app"}, "anomaly"))
        self.assertEqual(s.record["agent_model"][0]["tools"], ["container_stats", "host_disk", "plan"])
        final = self.final(ok)
        self.assertTrue(final.startswith("↪ 回复 张三：执行 每日巡检 name=kb-app\n按 SOP《每日巡检》执行：\n\n1. 宿主机磁盘"), final)
        self.assertIn("结论：⚠️ 有异常", final)
        self.assertIn(f"执行记录 {run['id'][:6]}（网页：SOP → 执行记录）", final)
        self.assertIn(chat_format.FEEDBACK_HINT, final)
        self.assertEqual(self.texts(verdict), ["↪ 回复 张三：误报 其实是日志\n已记下：误报。"])
        with graph.lock:
            feedback = [tuple(r) for r in graph.db.execute("SELECT execution_id, verdict, note FROM feedback").fetchall()]
        self.assertEqual(feedback, [(run["id"], "false_alarm", "其实是日志")])

    def test_candidates_from_the_answer_can_be_executed_by_number(self):
        script = [([], "可以按 SOP《每日巡检》查一遍。"),
                  ([call("host_disk"), call("container_stats", name="kb-app")], ""), ([], SOP_TABLE)]
        with Scenario(self, {"PLAN_TOOL": True}, script=script, ops=True):
            self.book()
            asked = message("kb-app 内存高怎么办")
            self.send(asked)
            self.assertIn("相关 SOP：① 每日巡检——回「执行 1」", self.final(asked))
            run = message("执行 1 name=kb-app")
            self.send(run)
        self.assertIn("结论：⚠️ 有异常", self.final(run))

    def test_refusals(self):
        with Scenario(self, ops=True) as s:
            self.book()
            nowhere, question, nothing = (message("执行 每日巡检 name=a", chat_id="1002"),
                                          message("执行 SOP 时报错怎么办", chat_id="1002"), message("执行"))
            for event in (nowhere, question, nothing):
                self.send(event)
        self.assertEqual(self.texts(nowhere), ["↪ 回复 张三：执行 每日巡检 name=a\n"
                                                "这里没有开通查实际数据，SOP 要在开通了数据工具的群或私聊里执行。"])
        self.assertIn("答案第一段", self.final(question))                # 对不上任何 SOP 的「执行……」是普通问题
        self.assertEqual(len(s.record["plain_model"]), 1)
        self.assertEqual(self.texts(nothing), ["↪ 回复 张三：执行\n先问一个问题，回答末尾会列出相关 SOP；"
                                                "也可以直接回「执行 SOP 名」。"])


class PageTests(ChatTestCase):
    def test_chat_conversations_are_labelled_filterable_and_readonly(self):
        client = TestClient(app_main.app)
        self.addCleanup(client.close)
        auth = (WEB_USER, WEB_PASSWORD)
        with Scenario(self), patch.object(app_main, "chat", chat_api):
            self.send(message("kb-app 内存高怎么办"))
            web = conversations.create("网页上的问题")
            conversations.add_message(web["id"], "user", "网页上的问题")
            listed = client.get("/api/conversations", auth=auth).json()
            self.assertEqual((listed["chat"], listed["source"]), (True, "all"))
            chat_id = next(c["id"] for c in listed["conversations"] if "source" in c)
            self.assertEqual(next(c for c in listed["conversations"] if c["id"] == chat_id)["source"],
                             {"platform": "ccwork", "chat_type": "group", "chat_name": "运维值班群", "sender_name": "张三"})
            self.assertEqual([c["id"] for c in client.get("/api/conversations?source=web", auth=auth).json()
                              ["conversations"]], [web["id"]])
            self.assertEqual([c["id"] for c in client.get("/api/conversations?source=chat", auth=auth).json()
                              ["conversations"]], [chat_id])
            detail = client.get(f"/api/conversations/{chat_id}", auth=auth).json()
            self.assertEqual((detail["readonly"], detail["source"]["chat_name"]), (True, "运维值班群"))
            self.assertNotIn("readonly", client.get(f"/api/conversations/{web['id']}", auth=auth).json())
            refused = client.post("/api/ask", json={"question": "接着问", "conversation_id": chat_id}, auth=auth)
            self.assertEqual(refused.status_code, 409)
            self.assertIn("网页上只能查看", refused.json()["detail"])
            self.assertEqual(client.delete(f"/api/conversations/{chat_id}", auth=auth).status_code, 200)
            self.assertEqual(self.threads()[0]["closed"], 1)
            self.send(message("再问一个"))
            self.assertNotEqual(self.threads()[-1]["conversation_id"], chat_id)

    def test_with_chat_on_every_route_still_needs_the_web_login(self):
        """开关打开时再跑一遍路由鉴权：云上协同只加经过登录的页面接口，不加任何不经登录的路由。"""
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, dependencies=[Depends(app_main.require_auth)])
        app.router.routes.extend(app_main.app.router.routes)
        self.addCleanup(chat_api._state.update, problem="", channel=None)
        with patch.object(chat_api, "CHAT_BRIDGE_URL", ""), patch.object(chat_api, "CHAT_BRIDGE_TOKEN", ""):
            chat_api.install(app, app_main.start_chat_turn, app_main.turn_events, app_main.smart_status)
        client = route_auth.RouteAuthTests.assert_login_everywhere(self, app, {"/api/alerts/hook", "/api/alerts/hook/"})
        client.close()
        paths = sorted({path for path, _ in route_auth.leaves(app.router.routes) if path.startswith("/api/chat")})
        self.assertEqual(paths, ["/api/chat/notify", "/api/chat/notify/{kind}/{source_id}", "/api/chat/status",
                                 "/api/chat/test-push"])
        self.assertEqual(chat_api._state["problem"], "没有配 CHAT_BRIDGE_URL")      # 地址没配：不起线程，页面上写明


class LogTests(ChatTestCase):
    def test_logs_have_no_content_names_or_full_ids(self):
        self.write(CONFIG.replace('"1001"', '"1234567890123"').replace('"u_boss"', '"u_boss_000042"')
                   + "digest:\n  - {target: 王某某, weekday: 9}\n")
        with Scenario(self), self.assertLogs("kb", level="INFO") as logs:
            self.send(message("机密问题：工资表在哪", chat_id="1234567890123", sender_id="u_zhangsan_007"))
            self.send(message("机密问题二", chat_id="9876543210987", sender_id="u_lisi_000008", sender_name="李四"))
            self.send(message("帮助", chat_type="single", sender_id="u_boss_000042", sender_name="老板"))
            self.send(message("没答好 机密补充", chat_id="1234567890123", sender_id="u_zhangsan_007"))
        text = "\n".join(logs.output)
        self.assertIn("chat ccwork 运维值班群 user=…_007", text)
        self.assertIn("refused (not enabled)", text)
        for secret in ("机密", "张三", "李四", "老板", "王某某", "1234567890123", "9876543210987", "u_zhangsan_007",
                       "u_lisi_000008", "u_boss_000042"):
            self.assertNotIn(secret, text)


class SwitchOffTests(unittest.TestCase):
    def test_switch_off_leaves_the_app_as_it_was(self):
        """开关空着：不导入、不挂路由、不建表，对话列表的形状不变。另起一个进程，用一个全新的数据目录。"""
        code = """
import json, sqlite3, sys
import tests.support
from fastapi.testclient import TestClient
from app import main
from app.config import CHAT_DB_PATH, WEB_PASSWORD, WEB_USER
tables = [r[0] for r in sqlite3.connect(CHAT_DB_PATH).execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
routes = [r.path for r in main.app.routes if getattr(r, "path", "").startswith("/api/chat")]
listed = TestClient(main.app).get("/api/conversations?source=chat", auth=(WEB_USER, WEB_PASSWORD)).json()
print(json.dumps({"chat": main.chat is None, "modules": "app.chat_api" in sys.modules or "app.chat_channel" in sys.modules,
                  "tables": sorted(t for t in tables if t.startswith("chat_")), "routes": routes, "keys": sorted(listed)}))
"""
        env = {**os.environ, "CHAT_BRIDGE_URL": "", "CHAT_BRIDGE_TOKEN": ""}
        with tempfile.TemporaryDirectory() as folder:
            env["DATA_DIR"] = folder
            done = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parent.parent, env=env,
                                  capture_output=True, text=True, encoding="utf-8", timeout=300)
        lines = [line for line in done.stdout.splitlines() if line.startswith("{")]
        self.assertTrue(lines, done.stderr[-2000:])
        result = json.loads(lines[-1])
        self.assertEqual(result, {"chat": True, "modules": False, "tables": [], "routes": [], "keys": ["conversations"]})


if __name__ == "__main__":
    unittest.main()
