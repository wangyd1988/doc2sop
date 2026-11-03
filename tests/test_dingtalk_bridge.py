"""钉钉转接程序（deploy/dingtalk/dingtalk_bridge.py）的离线部分：地址核对、消息过滤、待取队列和去重、发送（webhook 改走
机器人接口、流式缓冲的状态机）、配置和部署文件。网络部分（假的钉钉、Stream、本地接口、命令）在 test_dingtalk_bridge_net.py。
"""
import threading
import time
import unittest
from pathlib import Path

from tests.ccwork_fakes import Clock
from tests.dingtalk_fakes import CORP, GROUP, STAFF, bot_message, bridge

DEPLOY = Path(__file__).resolve().parent.parent / "deploy" / "dingtalk"
HOOK = "https://oapi.dingtalk.com/robot/sendBySession?session=abc"


class UrlTests(unittest.TestCase):
    def test_dingtalk_addresses_pass(self):
        self.assertEqual(bridge.check_url(HOOK, "webhook"), ("oapi.dingtalk.com", 443, "/robot/sendBySession?session=abc"))
        self.assertEqual(bridge.check_url("https://oapi.dingtalk.com:443/robot/sendBySession?session=abc", "webhook")[2],
                         "/robot/sendBySession?session=abc")
        self.assertEqual(bridge.check_url("wss://wss-open-connection.dingtalk.com:443/connect", "endpoint"),
                         ("wss-open-connection.dingtalk.com", 443, "/connect"))
        self.assertEqual(bridge.check_url("https://api.dingtalk.com/v1.0/robot/groupMessages/send", "api")[0],
                         "api.dingtalk.com")

    def test_lookalikes_and_tricks_are_refused(self):
        bad_hooks = (
            "https://evildingtalk.com/robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com.evil.com/robot/sendBySession?session=abc",
            "https://dingtalk.com/robot/sendBySession?session=abc",
            "https://user@oapi.dingtalk.com/robot/sendBySession?session=abc",
            "https://user:pw@oapi.dingtalk.com/robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com:443@evil.com/robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com:8443/robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com:80/robot/sendBySession?session=abc",
            "http://oapi.dingtalk.com/robot/sendBySession?session=abc",
            "https://OAPI.dingtalk.com/robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com./robot/sendBySession?session=abc",
            "https://oapi.dingtalk.com/robot/send?access_token=abc",
            "https://oapi.dingtalk.com/robot/sendBySessionX?session=abc",
            "https://oapi.dingtalk.com/robot/sendBySession/../send?session=abc",
            "https://oapi.dingtalk.com/robot/sendBySession",
            "https://oapi.dingtalk.com/robot/sendBySession?session=abc#x",
            "https://oapi.dingtalk.com\\@evil.com/robot/sendBySession?session=abc",
            "https://127.0.0.1/robot/sendBySession?session=abc",
            " https://oapi.dingtalk.com/robot/sendBySession?session=abc",
            None, 42,
        )
        for url in bad_hooks:
            with self.subTest(url=url):
                self.assertIsNone(bridge.check_url(url, "webhook"))
        for url in ("wss://evildingtalk.com/connect", "wss://wss-open-connection.dingtalk.com.evil.com/connect",
                    "wss://wss-open-connection.dingtalk.com:8443/connect", "ws://wss-open-connection.dingtalk.com/connect",
                    "https://wss-open-connection.dingtalk.com/connect", "wss://x@wss-open-connection.dingtalk.com/connect",
                    "wss://wss-open-connection.dingtalk.com/connect?ticket=old"):
            with self.subTest(url=url):
                self.assertIsNone(bridge.check_url(url, "endpoint"))
        for host in ("evildingtalk.com", "dingtalk.com.evil.com", "dingtalk.com", "", "a..dingtalk.com",
                     ".dingtalk.com", "API.dingtalk.com"):
            self.assertFalse(bridge.dingtalk_host(host), host)
        self.assertTrue(bridge.dingtalk_host("wss-open-connection.dingtalk.com"))


class InterpretTests(unittest.TestCase):
    def test_group_mention_and_private_text_are_forwarded(self):
        outcome, event, reply = bridge.interpret(bot_message())
        self.assertEqual(outcome, "forwarded")
        self.assertEqual((event["platform"], event["chat_type"], event["chat_id"], event["sender_id"], event["kind"]),
                         ("dingtalk", "group", GROUP, STAFF, "text"))
        self.assertEqual(event["text"], "问题金丝雀 kb-app 内存高怎么办")
        self.assertEqual((event["msg_key"], event["chat_name"]), ("dingtalk:msg-1", "运维值班群"))
        self.assertTrue(reply["webhook"].startswith("https://oapi.dingtalk.com/robot/sendBySession"))
        self.assertNotIn("sessionWebhook", event)
        self.assertNotIn("webhook", event)
        outcome, event, _ = bridge.interpret(bot_message(group=False))
        self.assertEqual((outcome, event["chat_type"], event["chat_name"]), ("forwarded", "single", ""))

    def test_what_is_dropped(self):
        cases = {"not_at": bot_message(at=False), "other_corp": bot_message(corp="dingother"),
                 "no_staff_id": bot_message(staff=""), "malformed": bot_message(chat="12345"),
                 "chat_type": bot_message(conversationType="3")}
        for expected, data in cases.items():
            with self.subTest(expected):
                outcome, event, _ = bridge.interpret(data)
                self.assertEqual((outcome, event), (expected, None))
        self.assertEqual(bridge.interpret("x")[0], "malformed")
        self.assertEqual(bridge.interpret(bot_message(msgId=None))[0], "malformed")
        missing_corp = bot_message()
        del missing_corp["senderCorpId"]          # 缺一个字段只算不知道，不丢
        self.assertEqual(bridge.interpret(missing_corp)[0], "forwarded")

    def test_other_content(self):
        outcome, event, _ = bridge.interpret(bot_message(msgtype="richText", text="图文里的字"))
        self.assertEqual((outcome, event["text"]), ("forwarded", "图文里的字"))
        for kind in ("picture", "audio", "file", "video"):
            outcome, event, _ = bridge.interpret(bot_message(msgtype=kind))
            self.assertEqual((outcome, event["kind"], event["text"]), ("unsupported", "unsupported", ""))
        outcome, event, _ = bridge.interpret(bot_message(text="   "))
        self.assertEqual(event["kind"], "unsupported")

    def test_long_text_and_bad_webhook(self):
        _, event, _ = bridge.interpret(bot_message(text="汉" * 5000))
        self.assertTrue(event["truncated"])
        self.assertLessEqual(len(event["text"].encode()), bridge.TEXT_MAX)
        _, _, reply = bridge.interpret(bot_message(webhook="https://evildingtalk.com/robot/sendBySession?session=x"))
        self.assertEqual(reply["webhook"], "")
        _, _, reply = bridge.interpret(bot_message(sessionWebhookExpiredTime="soon"))
        self.assertEqual(reply["webhook_expires"], 0.0)


def event(n=1, chat=GROUP, sender=STAFF):
    return {"kind": "text", "platform": "dingtalk", "chat_type": "group", "chat_id": chat, "chat_name": "",
            "sender_id": sender, "sender_name": "", "msg_key": f"dingtalk:msg-{n}", "text": f"q{n}"}


class InboxTests(unittest.TestCase):
    def test_claim_and_fetch(self):
        inbox = bridge.Inbox(Clock(), lambda: 0)
        self.assertTrue(inbox.claim("k1"))
        self.assertFalse(inbox.claim("k1"))
        self.assertEqual(inbox.offer(event(1)), "queued")
        got = inbox.fetch("", 0, 0)
        self.assertEqual([e["id"] for e in got["events"]], [1])
        inbox.fetch(got["epoch"], 1, 0)
        self.assertEqual(inbox.size()[0], 0)
        with self.assertRaises(bridge.EpochMismatch):
            inbox.fetch("other", 0, 0)
        self.assertEqual(inbox.counters["duplicate"], 1)

    def test_rates_and_crowding(self):
        clock = Clock()
        inbox = bridge.Inbox(clock, lambda: 0)
        results = [inbox.offer(event(n, sender=f"s{n}")) for n in range(35)]
        self.assertEqual(results.count("queued"), bridge.CHAT_PER_MINUTE)
        self.assertEqual(results.count("chat_rate"), 5)
        clock.now += 61
        self.assertEqual([inbox.offer(event(100 + n, chat="cidOtherGroup1==")) for n in range(11)].count("sender_rate"), 1)

    def test_concurrent_claims_from_two_connections(self):
        """disconnect 时新旧两条连接并存：同一条消息两边同时到，只能交给 kb-app 一次。"""
        cfg, _ = bridge.load_config({"DINGTALK_CLIENT_ID": "x", "DINGTALK_CLIENT_SECRET": "y"})
        for _ in range(20):
            b = bridge.Bridge(cfg, net=object())
            start = threading.Barrier(8)
            data = [bot_message(n) for n in range(1, 6)]

            def deliver():
                start.wait()
                for item in data:
                    b.on_callback(item)

            threads = [threading.Thread(target=deliver) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            got = b.inbox.fetch("", 0, 0)["events"]
            self.assertEqual(sorted(e["msg_key"] for e in got), [f"dingtalk:msg-{n}" for n in range(1, 6)])
            self.assertEqual(b.inbox.counters["duplicate"], 35)


class FakePlatform:
    """Outbox 用的假发送：记下每次调用；errors 里按方法名放要抛的 PlatformError。"""

    def __init__(self, delay=0.0):
        self.calls, self.errors, self.delay = [], {}, delay
        self.lock = threading.Lock()

    def _call(self, name, *args):
        time.sleep(self.delay)
        with self.lock:
            self.calls.append((name, *args))
            queue = self.errors.get(name) or []
            if queue:
                raise queue.pop(0)
        return {"message_id": f"m{len(self.calls)}"} if name != "webhook" else {}

    def send_webhook(self, webhook, text, fmt="text", at=()):
        return self._call("webhook", text, fmt, tuple(at))

    def send_group(self, chat_id, text, fmt="text"):
        return self._call("group", chat_id, text, fmt)

    def send_user(self, user_id, text, fmt="text"):
        return self._call("user", user_id, text, fmt)


def info(group=True, expires=None):
    return {"chat_type": "group" if group else "single", "chat_id": GROUP if group else "", "sender_id": STAFF,
            "webhook": HOOK, "webhook_expires": time.time() + 5400 if expires is None else expires}


def packet(seq, kind="delta", content="", request_id="r1"):
    return {"request_id": request_id, "seq": seq, "type": kind, "message_type": "cover", "content": content,
            "format": "text"}


class FakeTargets:
    def __init__(self, targets):
        self.targets = targets

    def load(self):
        return self


class ReplyTests(unittest.TestCase):
    def outbox(self, platform, hint_delay=0.2, targets=None):
        return bridge.Outbox(platform, FakeTargets(targets or {}), hint_delay=hint_delay)

    def test_webhook_first_and_real_mention_in_groups(self):
        p = FakePlatform()
        out = self.outbox(p)
        self.assertEqual(out.reply(info(), "答", mention=True)[0], 200)
        self.assertEqual(out.reply(info(group=False), "答", mention=True)[0], 200)
        self.assertEqual(p.calls, [("webhook", "答", "text", (STAFF,)), ("webhook", "答", "text", ())])

    def test_dead_or_expired_webhook_falls_back_to_the_robot_api(self):
        p = FakePlatform()
        out = self.outbox(p)
        p.errors["webhook"] = [bridge.PlatformError("sessionWebhook 发送失败", status=200, code="300001")]
        self.assertEqual(out.reply(info(), "答", "markdown", mention=True)[0], 200)
        self.assertEqual([c[0] for c in p.calls], ["webhook", "group"])
        self.assertEqual(p.calls[1], ("group", GROUP, "答", "markdown"))
        out.reply(info(), "再答")                       # 记住了它不能用：不再试
        self.assertEqual([c[0] for c in p.calls], ["webhook", "group", "group"])
        p.calls.clear()
        out.reply(info(group=False, expires=time.time() + 30), "答")     # 快过期了：直接走单聊接口
        self.assertEqual(p.calls, [("user", STAFF, "答", "text")])

    def test_uncertain_webhook_failures_are_not_resent(self):
        p = FakePlatform()
        out = self.outbox(p)
        p.errors["webhook"] = [bridge.PlatformError("钉钉没有回应", definite=False)]
        status, body = out.reply(info(), "答")
        self.assertEqual((status, body["definite"]), (502, False))
        self.assertEqual([c[0] for c in p.calls], ["webhook"])
        p.errors["webhook"] = [bridge.PlatformError("钉钉限流", throttled=True)]
        self.assertEqual(out.reply(info(), "答")[0], 429)

    def test_per_chat_limit(self):
        out = self.outbox(FakePlatform())
        statuses = [out.reply(info(), f"{n}")[0] for n in range(bridge.CHAT_SEND_PER_MINUTE + 2)]
        self.assertEqual(statuses.count(429), 2)

    def test_quick_answer_is_one_message(self):
        p = FakePlatform()
        out = self.outbox(p, hint_delay=0.5)
        self.assertEqual(out.reply_stream(info(), packet(1, content="↪ 回复 张三\n🔎 正在查知识库…"))[0], 200)
        self.assertEqual(out.reply_stream(info(), packet(2, content="部分"))[0], 200)
        self.assertEqual(out.reply_stream(info(), packet(3, content="最终"))[0], 200)
        status, body = out.reply_stream(info(), packet(4, "done", "最终"))
        self.assertEqual(status, 200)
        time.sleep(0.7)
        self.assertEqual(p.calls, [("webhook", "最终", "text", (STAFF,))])
        self.assertTrue(out.reply_stream(info(), packet(4, "done", "最终"))[1]["cached"])
        self.assertEqual(out.reply_stream(info(), packet(5, "done", "又一次"))[0], 200)
        self.assertEqual(len(p.calls), 1)

    def test_slow_answer_gets_a_hint_first(self):
        p = FakePlatform()
        out = self.outbox(p, hint_delay=0.05)
        out.reply_stream(info(), packet(1, content="↪ 回复 张三\n🔎 正在查知识库…"))
        time.sleep(0.3)
        out.reply_stream(info(), packet(2, content="正文"))
        out.reply_stream(info(), packet(3, "done", "正文\n出处"))
        self.assertEqual(p.calls, [("webhook", "↪ 回复 张三\n🔎 正在查知识库…", "text", ()),
                                   ("webhook", "正文\n出处", "text", (STAFF,))])

    def test_hint_and_done_race_never_sends_three_or_out_of_order(self):
        for delay in (0.0, 0.001, 0.003, 0.01):
            for _ in range(10):
                p = FakePlatform(delay=0.002)
                out = self.outbox(p, hint_delay=delay)
                out.reply_stream(info(), packet(1, content="hint"))
                out.reply_stream(info(), packet(2, "done", "final"))
                time.sleep(delay + 0.05)
                texts = [c[1] for c in p.calls]
                self.assertIn(texts, (["final"], ["hint", "final"]))

    def test_error_packet_ends_it_and_definite_unsent_can_be_retried(self):
        p = FakePlatform()
        out = self.outbox(p, hint_delay=5)
        out.reply_stream(info(), packet(1, content="hint", request_id="r2"))
        out._chat_hits[f"group:{GROUP}"] = __import__("collections").deque([out.clock()] * bridge.CHAT_SEND_PER_MINUTE)
        self.assertEqual(out.reply_stream(info(), packet(2, "error", "这次没答出来", request_id="r2"))[0], 429)
        out._chat_hits.clear()
        self.assertEqual(out.reply_stream(info(), packet(2, "error", "这次没答出来", request_id="r2"))[0], 200)
        self.assertEqual([c[1] for c in p.calls], ["这次没答出来"])

    def test_push_by_name_only(self):
        p = FakePlatform()
        out = self.outbox(p, targets={"值班群": ("chat", GROUP), "王": ("user", "u1")})
        self.assertEqual(out.push("值班群", "巡检", "markdown")[0], 200)
        self.assertEqual(out.push("王", "巡检")[0], 200)
        self.assertEqual(out.push(GROUP, "巡检")[0], 404)
        self.assertEqual(p.calls, [("group", GROUP, "巡检", "markdown"), ("user", "u1", "巡检", "text")])


class BridgeGateTests(unittest.TestCase):
    def test_send_off_and_bad_requests(self):
        cfg, _ = bridge.load_config({"DINGTALK_ENABLED": "true", "DINGTALK_CLIENT_ID": "x", "DINGTALK_CLIENT_SECRET": "y"})
        b = bridge.Bridge(cfg, net=object())
        self.assertEqual(b.reply({"handle": "h", "text": "x"})[0], 403)
        self.assertEqual(b.push({"target": "t", "text": "x"})[0], 403)
        cfg, _ = bridge.load_config({"DINGTALK_ENABLED": "true", "DINGTALK_SEND": "on", "DINGTALK_CLIENT_ID": "x",
                                     "DINGTALK_CLIENT_SECRET": "y"})
        b = bridge.Bridge(cfg, net=object())
        self.assertEqual(b.reply({"handle": "nope", "text": "x"})[0], 410)
        b.on_callback(bot_message())
        handle = b.inbox.fetch("", 0, 0)["events"][0]["handle"]
        self.assertEqual(b.reply({"handle": handle, "text": "x", "format": "html"})[0], 400)
        self.assertEqual(b.reply({"handle": handle, "stream": {"request_id": "r", "seq": 0}})[0], 400)
        self.assertEqual(bridge.check_packet(packet(1))[0]["format"], "text")


class ConfigTests(unittest.TestCase):
    def test_defaults_are_off(self):
        cfg, problems = bridge.load_config({})
        self.assertEqual(problems, [])
        self.assertFalse(cfg.enabled or cfg.send)
        self.assertEqual(cfg.listen, ("127.0.0.1", 8795))
        status = bridge.Bridge(cfg, net=object()).status()
        self.assertEqual((status["platform"], status["formats"], status["state"]), ("dingtalk", ["text", "markdown"],
                                                                                  "disabled"))

    def test_refusals_and_secrets(self):
        cfg, problems = bridge.load_config({"DINGTALK_LISTEN": "0.0.0.0:8795", "CHAT_BRIDGE_TOKEN": "short",
                                            "DINGTALK_SEND": "maybe", "DINGTALK_CLIENT_ID": "id-1",
                                            "DINGTALK_CLIENT_SECRET": "secret-canary"})
        self.assertEqual(len(problems), 3)
        self.assertIsNone(cfg.listen)
        self.assertEqual(cfg.robot_code, "id-1")
        self.assertNotIn("secret-canary", repr(cfg) + str(cfg))
        status = bridge.Bridge(cfg, net=object()).status()
        self.assertNotIn("secret-canary", str(status))


class DeployFileTests(unittest.TestCase):
    def test_unit_keeps_the_bridge_boxed_in(self):
        unit = (DEPLOY / "doc2sop-dingtalk.service.example").read_text(encoding="utf-8")
        settings = [line.strip() for line in unit.splitlines() if line.strip() and not line.startswith("#")]
        for expected in ("User=doc2sop-dingtalk", "EnvironmentFile=/etc/doc2sop-dingtalk.env", "NoNewPrivileges=yes",
                         "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "CapabilityBoundingSet=",
                         "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "MemoryMax=100M",
                         "ExecStart=/usr/bin/python3 -I /opt/doc2sop-dingtalk/dingtalk_bridge.py serve"):
            self.assertIn(expected, settings)
        hidden = " ".join(line for line in settings if line.startswith("InaccessiblePaths="))
        for path in ("/opt/kb-app", "/etc/ops-readonly.env", "/etc/doc2sop-sandbox.env", "/etc/doc2sop-ccwork.env",
                     "/etc/doc2sop-dingtalk.env", "/run/docker.sock"):
            self.assertIn(f"-{path}", hidden)
        self.assertFalse(any(line.startswith(("ReadWritePaths=", "StateDirectory=", "SupplementaryGroups="))
                             for line in settings))

    def test_env_example_starts_off(self):
        env = (DEPLOY / "dingtalk.env.example").read_text(encoding="utf-8")
        values = dict(line.split("=", 1) for line in env.splitlines() if line and not line.startswith("#"))
        self.assertEqual((values["DINGTALK_ENABLED"], values["DINGTALK_SEND"]), ("false", "off"))
        self.assertNotIn("DINGTALK_CLIENT_SECRET", values)
        cfg, problems = bridge.load_config(values)
        self.assertEqual(problems, [])
        self.assertFalse(cfg.enabled or cfg.send)

    def test_targets_example_loads(self):
        targets = bridge.Targets(DEPLOY / "targets.yaml.example").load()
        self.assertEqual((targets.targets, targets.problems), ({}, ()))


if __name__ == "__main__":
    unittest.main()
