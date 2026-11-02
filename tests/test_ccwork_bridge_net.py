"""云上协同转接程序的网络部分：平台接口（假的 HTTPS 开放平台）、本地接口、MQTT（假的 broker，经 paho）、端到端、
check / set-credentials 两个命令。离线部分在 test_ccwork_bridge.py。证书现生成在临时目录里。
"""
import io
import json
import logging
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tests.ccwork_fakes import (KEY, ROBOT_ID, TOKEN, Clock, FakeBroker, FakePlatform, bridge, chat_message, make_certs,
                                robot, server_context, text_body, wait_for)

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
HAVE_PAHO = bridge.paho is not None
SECRETS = ("secret-1", "access-", "jwt-", KEY.decode())


class Captured(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
class NetCase(unittest.TestCase):
    """每个用例一套：临时 CA、假的开放平台、配置；日志全收下来，结束时核对里面没有任何密钥。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ca, cert, key = make_certs(self.tmp.name)
        self.server_tls = server_context(cert, key)
        self.platform = FakePlatform(server_context(cert, key))
        self.targets = Path(self.tmp.name, "targets.yaml")
        self.env = {"CCWORK_ENABLED": "true", "CCWORK_APP_KEY": "key-1", "CCWORK_APP_SECRET": "secret-1",
                    "CCWORK_BASE_URL": self.platform.url, "CCWORK_SAAS_HOST": self.platform.url,
                    "CCWORK_CA_FILE": str(self.ca), "CCWORK_SEND": "on", "CHAT_BRIDGE_TOKEN": TOKEN,
                    "CCWORK_TARGETS_FILE": str(self.targets)}
        self.log = Captured()
        bridge.log.addHandler(self.log)
        self.level = bridge.log.level
        bridge.log.setLevel(logging.DEBUG)

    def tearDown(self):
        bridge.log.removeHandler(self.log)
        bridge.log.setLevel(self.level)
        self.platform.close()
        self.tmp.cleanup()
        text = "\n".join(self.log.lines)
        for secret in SECRETS:
            self.assertNotIn(secret, text, f"日志里出现了 {secret!r}")
        self.assertNotIn("4242", text.replace("…4242", ""), "日志里出现了完整的会话 ID")

    def config(self, **extra):
        cfg, problems = bridge.load_config({**self.env, **extra})
        self.assertEqual(problems, [])
        return cfg


class PlatformTests(NetCase):
    def test_token_robot_info_and_router(self):
        platform = bridge.Platform(self.config())
        info = platform.robot_info()
        self.assertEqual((info.robot_id, info.org_id, info.org_code, info.password, info.key),
                         (ROBOT_ID, "org9", "ORG", "jwt-1", KEY))
        self.assertEqual((info.client_id, info.username), (f"org9_{ROBOT_ID}_sdk", f"org9_{ROBOT_ID}"))
        self.assertEqual(platform.org_router("ORG"), "127.0.0.1:1883")
        self.assertEqual(platform.expires_in, 7200)
        path, headers, body = self.platform.requests[0]
        self.assertEqual(path, bridge.TOKEN_PATH)
        self.assertIn(b"appSecret=secret-1", body)
        router = [h for p, h, _ in self.platform.requests if p == bridge.ROUTER_PATH][0]
        self.assertNotIn("access_token", router)

    def test_expired_token_is_refreshed_once(self):
        platform = bridge.Platform(self.config())
        platform.token()
        self.platform.expire_next = 1
        platform.robot_info()
        self.assertEqual(self.platform.tokens, 2)
        self.platform.expire_next = 2
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.robot_info()
        self.assertEqual(caught.exception.code, "0704")
        self.assertEqual(self.platform.tokens, 3)

    def test_failures_say_whether_the_platform_may_have_got_it(self):
        platform = bridge.Platform(self.config())
        self.platform.fail_next = [500, 400]
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_text(robot(), "hi", chat_id="4242")
        self.assertFalse(caught.exception.definite)
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_text(robot(), "hi", chat_id="4242")
        self.assertTrue(caught.exception.definite)
        with self.assertRaises(bridge.PlatformError):
            bridge.Platform(self.config(CCWORK_APP_SECRET="wrong")).token()
        unreachable = bridge.Platform(self.config(CCWORK_BASE_URL="https://127.0.0.1:9"))
        with self.assertRaises(bridge.PlatformError) as caught:
            unreachable.token()
        self.assertFalse(caught.exception.definite)

    def test_redirects_are_not_followed(self):
        self.platform.redirect = True
        with self.assertRaises(bridge.PlatformError):
            bridge.Platform(self.config()).token()
        self.assertNotIn("/stolen", [p for p, _, _ in self.platform.requests])

    def test_untrusted_certificate_is_refused(self):
        cfg, _ = bridge.load_config({**self.env, "CCWORK_CA_FILE": ""})
        with self.assertRaises(bridge.PlatformError):
            bridge.Platform(cfg).token()
        self.assertEqual(self.platform.requests, [])

    def test_message_shapes(self):
        platform = bridge.Platform(self.config())
        me = robot()
        platform.send_text(me, "群里的回答", chat_id="4242", at=["u_alice"])
        platform.send_text(me, "推给个人", user_id="u_bob")
        platform.send_stream(me, {"request_id": "r1", "seq": 1, "type": "delta", "message_type": "cover",
                                  "content": "正在查…"}, chat_id="4242")
        platform.send_stream(me, {"request_id": "r1", "seq": 2, "type": "done", "message_type": "", "content": ""},
                             user_id="u_bob")
        chat, user = self.platform.sent(bridge.SEND_CHAT_PATH, bridge.SEND_USER_PATH)
        self.assertEqual((chat["app_robot_code"], chat["chat_id"], chat["at"], chat["text"]),
                         (ROBOT_ID, 4242, ["u_alice"], {"message": "群里的回答", "at": ["u_alice"]}))
        self.assertEqual((user["user_id"], user["chat_id"], user["text"]), ("u_bob", 0, {"message": "推给个人"}))
        delta, done = self.platform.sent(bridge.STREAM_CHAT_PATH, bridge.STREAM_USER_PATH)
        self.assertEqual({k: delta[k] for k in ("chat_id", "request_id", "seq", "type", "message_type", "content")},
                         {"chat_id": 4242, "request_id": "r1", "seq": 1, "type": "delta", "message_type": "cover",
                          "content": "正在查…"})
        self.assertEqual((done["user_id"], done["type"]), ("u_bob", "done"))
        self.assertNotIn("content", done)


TLS_BROKER = bridge.Broker(True, "mqtt.example.com", 8883)


class ApiCase(NetCase):
    """本地接口：Bridge 不连 MQTT，直接把机器人和（加密的）broker 摆好，相当于已经连上。"""

    def setUp(self):
        super().setUp()
        self.targets.write_text("targets:\n  运维值班群: {chat_id: '4242'}\n  王某某: {user_id: u_boss}\n"
                                "deny_senders: [u_bot]\n", encoding="utf-8")

    def start(self, clock=None, broker=TLS_BROKER, **extra):
        cfg = self.config(**extra)
        self.bridge = bridge.Bridge(cfg, clock=clock or time.monotonic)
        self.bridge.outbox.bucket = bridge.TokenBucket(1000, 1000)
        self.bridge.robot, self.bridge.broker = robot(), broker
        self.server = bridge.make_server(self.bridge, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, path, body=None, token=TOKEN, protocol="1", method=None):
        headers = {}
        if token:
            headers[bridge.TOKEN_HEADER] = token
        if protocol:
            headers[bridge.PROTOCOL_HEADER] = protocol
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=headers,
                                         method=method or ("POST" if data is not None else "GET"))
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def deliver(self, payload):
        self.bridge.on_payload(payload)
        return self.call("/events?epoch=&after=0&wait=0")[1]


class ApiTests(ApiCase):
    def test_every_endpoint_needs_the_token(self):
        self.start()
        for path, body in (("/health", None), ("/status", None), ("/events", None), ("/reply", {}), ("/push", {})):
            with self.subTest(path=path):
                self.assertEqual(self.call(path, body, token=None)[0], 401)
                self.assertEqual(self.call(path, body, token="x" * 40)[0], 401)
        self.assertEqual(self.call("/health", protocol=None), (200, {"ok": True, "protocol": [1, 1]}))
        self.assertEqual(self.call("/status", protocol="2")[0], 409)
        self.assertEqual(self.call("/nope")[0], 404)
        with self.assertRaises(ValueError):
            bridge.make_server(self.bridge, "0.0.0.0", 0)

    def test_status_has_names_but_no_secrets_or_ids(self):
        self.start()
        status = self.call("/status")[1]
        self.assertEqual((status["state"], status["tls"], status["send"], status["robot"], status["targets"]),
                         ("starting", True, True, "…8765", ["王某某", "运维值班群"]))
        text = json.dumps(status, ensure_ascii=False)
        for secret in ("4242", "u_boss", "secret-1", "jwt-1", KEY.decode()):
            self.assertNotIn(secret, text)

    def test_messages_flow_out_and_get_acknowledged(self):
        self.start()
        first = self.deliver(chat_message(text_body("问一下", at=[ROBOT_ID])))
        event = first["events"][0]
        self.assertEqual((event["id"], event["kind"], event["text"], event["chat_id"]), (1, "text", "问一下", "4242"))
        self.assertTrue(event["handle"])
        self.assertEqual(self.call(f"/events?epoch={first['epoch']}&after=1&wait=0")[1]["events"], [])
        status, body = self.call("/events?epoch=stale&after=1&wait=0")
        self.assertEqual((status, body["epoch"]), (409, first["epoch"]))
        self.assertEqual(self.call("/events?after=x")[0], 400)

    def test_denied_senders_never_reach_kb_app(self):
        self.start()
        self.assertEqual(self.deliver(chat_message(text_body("刷屏", at=[ROBOT_ID]), sender="u_bot"))["events"], [])
        self.assertEqual(self.bridge.inbox.counters["denied_sender"], 1)

    def test_replies_go_back_through_the_handle(self):
        self.start()
        handle = self.deliver(chat_message(text_body("问", at=[ROBOT_ID])))["events"][0]["handle"]
        self.assertEqual(self.call("/reply", {"handle": handle, "text": "答", "mention": True})[0], 200)
        sent = self.platform.sent(bridge.SEND_CHAT_PATH)[-1]
        self.assertEqual((sent["chat_id"], sent["at"], sent["text"]["message"]), (4242, ["u_alice"], "答"))
        self.assertEqual(self.call("/reply", {"handle": "guessed", "text": "答"})[0], 410)
        for body in ({"handle": handle}, {"handle": handle, "text": "x" * 6001}, {"handle": handle, "text": "a\x00"},
                     {"handle": handle, "stream": {"request_id": "bad id", "seq": 1, "type": "delta"}},
                     {"handle": handle, "stream": {"request_id": "r", "seq": 0, "type": "delta"}},
                     {"handle": handle, "stream": {"request_id": "r", "seq": 1, "type": "push"}}):
            with self.subTest(body=str(body)[:60]):
                self.assertEqual(self.call("/reply", body)[0], 400)
        self.assertEqual(self.call("/reply", b"not json")[0], 400)
        self.assertEqual(self.call("/reply", b"x" * (bridge.BODY_MAX + 1))[0], 413)

    def test_direct_messages_are_answered_without_a_mention(self):
        self.start()
        handle = self.deliver(chat_message(text_body("私聊"), chat_type=1))["events"][0]["handle"]
        self.call("/reply", {"handle": handle, "text": "好", "mention": True})
        sent = self.platform.sent(bridge.SEND_CHAT_PATH)[-1]
        self.assertNotIn("at", sent)

    def test_a_repeated_stream_packet_is_not_sent_twice(self):
        self.start()
        handle = self.deliver(chat_message(text_body("问", at=[ROBOT_ID])))["events"][0]["handle"]
        packet = {"request_id": "req-1", "seq": 1, "type": "delta", "message_type": "cover", "content": "正在查"}
        self.assertEqual(self.call("/reply", {"handle": handle, "stream": packet}), (200, {"ok": True}))
        self.assertEqual(self.call("/reply", {"handle": handle, "stream": packet}), (200, {"ok": True, "cached": True}))
        self.assertEqual(len(self.platform.sent(bridge.STREAM_CHAT_PATH)), 1)
        self.platform.fail_next = [503]
        packet = {**packet, "seq": 2, "content": "正在查…"}
        status, body = self.call("/reply", {"handle": handle, "stream": packet})
        self.assertEqual((status, body["definite"]), (502, False))
        self.assertEqual(self.call("/reply", {"handle": handle, "stream": packet})[0], 200)   # 结果不明的可以重发

    def test_pushes_only_by_name(self):
        self.start()
        self.assertEqual(self.call("/push", {"target": "运维值班群", "text": "巡检有异常"})[0], 200)
        self.assertEqual(self.call("/push", {"target": "王某某", "text": "日报"})[0], 200)
        self.assertEqual(self.call("/push", {"target": "4242", "text": "按 ID 发"})[0], 404)
        self.assertEqual(self.call("/push", {"chat_id": "4242", "text": "按 ID 发"})[0], 404)
        chat, user = self.platform.sent(bridge.SEND_CHAT_PATH, bridge.SEND_USER_PATH)
        self.assertEqual((chat["chat_id"], user["user_id"]), (4242, "u_boss"))

    def test_a_storm_of_pushes_is_folded_into_one(self):
        clock = Clock()
        self.start(clock=clock)
        codes = [self.call("/push", {"target": "运维值班群", "text": f"告警 {n}"})[0] for n in range(25)]
        self.assertEqual(codes, [200] * 20 + [202] * 5)
        self.bridge.outbox.flush_held(self.bridge.robot)
        self.assertEqual(len(self.platform.sent(bridge.SEND_CHAT_PATH)), 20)
        clock.now += 3600
        self.bridge.outbox.flush_held(self.bridge.robot)
        summary = self.platform.sent(bridge.SEND_CHAT_PATH)[-1]["text"]["message"]
        self.assertIn("另有 5 条", summary)
        self.bridge.outbox.flush_held(self.bridge.robot)
        self.assertEqual(len(self.platform.sent(bridge.SEND_CHAT_PATH)), 21)

    def test_sending_off_and_plaintext_diagnosis_send_nothing(self):
        self.start(CCWORK_SEND="off")
        self.assertEqual(self.call("/push", {"target": "运维值班群", "text": "x"})[0], 403)
        self.server.shutdown()
        self.server.server_close()
        self.start(broker=bridge.Broker(False, "10.0.0.5", 1883), CCWORK_ALLOW_PLAINTEXT="diagnose")
        self.assertEqual(self.deliver(chat_message(text_body("问", at=[ROBOT_ID])))["events"], [])
        self.assertEqual(self.bridge.inbox.counters["diagnose_only"], 1)
        self.assertEqual(self.call("/push", {"target": "运维值班群", "text": "x"})[0], 403)
        status = self.call("/status")[1]
        self.assertEqual((status["tls"], status["diagnose"], status["send"]), (False, True, False))
        self.assertEqual(self.platform.sent(bridge.SEND_CHAT_PATH, bridge.SEND_USER_PATH), [])

    def test_disabled_bridge_only_answers_health(self):
        self.start(CCWORK_ENABLED="false")
        self.bridge.robot = None
        self.bridge.start()
        self.assertEqual(self.call("/status")[1]["state"], "disabled")
        self.assertEqual(self.call("/reply", {"handle": "h", "text": "x"})[0], 503)
        self.bridge.stop()
        self.assertEqual(self.platform.requests, [])


@unittest.skipUnless(HAVE_PAHO, "需要 paho-mqtt（apt 的 python3-paho-mqtt，测试环境 pip install paho-mqtt==1.6.1）")
class LinkTests(NetCase):
    def setUp(self):
        super().setUp()
        self.broker = FakeBroker(self.server_tls)
        self.addCleanup(self.broker.close)
        self.topic = f"org9_{ROBOT_ID}"

    def bridge_for(self, broker=None, **extra):
        cfg = self.config(CCWORK_BROKER=broker or f"ssl://127.0.0.1:{self.broker.port}", **extra)
        instance = bridge.Bridge(cfg, tick=0.1)
        instance.outbox.bucket = bridge.TokenBucket(1000, 1000)
        self.addCleanup(instance.stop)
        instance.start()
        return instance

    def test_connects_over_tls_and_forwards_only_mentions(self):
        link = self.bridge_for()
        self.assertTrue(wait_for(lambda: self.broker.subscriptions and link.status()["state"] == "connected"))
        self.assertEqual(self.broker.connects[0], {"client_id": f"org9_{ROBOT_ID}_sdk", "username": self.topic,
                                                   "password": "jwt-1", "keepalive": 60, "clean": True, "level": 4})
        self.assertEqual(self.broker.subscriptions[0], (self.topic, 1))
        question = chat_message(text_body("问一下", at=[ROBOT_ID]))
        self.broker.publish(self.topic, question, pid=5)
        self.broker.publish(self.topic, question, pid=6, dup=True)        # QoS 1 重发的同一条
        self.broker.publish(self.topic, chat_message(text_body("闲聊"), msg_id=8, uniq=2), pid=7)
        self.assertTrue(wait_for(lambda: sorted(self.broker.pubacks) == [5, 6, 7]))
        self.assertEqual([e["text"] for e in link.inbox.fetch("", 0, 0)["events"]], ["问一下"])
        self.assertEqual((link.inbox.counters["duplicate"], link.inbox.counters["not_at"]), (1, 1))
        self.assertTrue(any(line.startswith("message group:…4242") for line in self.log.lines))

    def test_an_untrusted_broker_certificate_is_refused(self):
        other = Path(self.tmp.name, "other")
        other.mkdir()
        _, cert, key = make_certs(other)
        stranger = FakeBroker(server_context(cert, key))
        self.addCleanup(stranger.close)
        link = self.bridge_for(broker=f"ssl://127.0.0.1:{stranger.port}")
        self.assertTrue(wait_for(lambda: "TLS" in " ".join(link.status()["problems"])))
        self.assertEqual(stranger.connects, [])

    def test_plaintext_is_refused_unless_diagnosing(self):
        plain = FakeBroker()
        self.addCleanup(plain.close)
        link = self.bridge_for(broker=f"tcp://127.0.0.1:{plain.port}")
        self.assertTrue(wait_for(lambda: "明文" in " ".join(link.status()["problems"])))
        link.stop()
        self.assertEqual(plain.connects, [])
        link = self.bridge_for(broker=f"tcp://127.0.0.1:{plain.port}", CCWORK_ALLOW_PLAINTEXT="diagnose")
        self.assertTrue(wait_for(lambda: plain.subscriptions))
        plain.publish(self.topic, chat_message(text_body("问", at=[ROBOT_ID])), pid=3)
        self.assertTrue(wait_for(lambda: link.inbox.counters.get("diagnose_only") == 1))
        self.assertEqual(link.inbox.fetch("", 0, 0)["events"], [])

    def test_a_refused_password_is_refreshed(self):
        self.broker.refuse = lambda password: 5 if password == "jwt-1" else 0
        link = self.bridge_for()
        self.assertTrue(wait_for(lambda: self.broker.subscriptions, timeout=15))
        self.assertEqual([c["password"] for c in self.broker.connects][:1], ["jwt-1"])
        self.assertEqual(self.broker.connects[-1]["password"], "jwt-2")
        self.assertEqual(link.status()["state"], "connected")

    def test_being_kicked_again_and_again_backs_off(self):
        self.broker.kick_after_connect = True
        link = self.bridge_for()
        self.assertTrue(wait_for(lambda: link.status()["conflict"], timeout=15))
        count = len(self.broker.connects)
        time.sleep(2)
        self.assertEqual(len(self.broker.connects), count)
        self.assertGreaterEqual(count, bridge.CONFLICT_COUNT)


@unittest.skipUnless(HAVE_PAHO, "需要 paho-mqtt")
class EndToEndTests(ApiCase):
    def test_a_question_comes_in_and_a_streamed_answer_goes_out(self):
        broker = FakeBroker(self.server_tls)
        self.addCleanup(broker.close)
        cfg = self.config(CCWORK_BROKER=f"ssl://127.0.0.1:{broker.port}")
        self.bridge = bridge.Bridge(cfg, tick=0.1)
        self.addCleanup(self.bridge.stop)
        self.server = bridge.make_server(self.bridge, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.bridge.start()
        self.assertTrue(wait_for(lambda: broker.subscriptions))
        broker.publish(f"org9_{ROBOT_ID}", chat_message(text_body("kb-app 内存高怎么办"), chat_type=1), pid=9)
        status, polled = self.call("/events?epoch=&after=0&wait=5")
        self.assertEqual((status, [e["text"] for e in polled["events"]]), (200, ["kb-app 内存高怎么办"]))
        handle = polled["events"][0]["handle"]
        for seq, kind, content in ((1, "delta", "🔎 正在查知识库…"), (2, "delta", "先看容器的内存上限 [1]"), (3, "done", "")):
            packet = {"request_id": "d2s-1", "seq": seq, "type": kind, "message_type": "cover" if content else "",
                      "content": content}
            self.assertEqual(self.call("/reply", {"handle": handle, "stream": packet})[0], 200)
        sent = self.platform.sent(bridge.STREAM_CHAT_PATH)
        self.assertEqual([(p["seq"], p["type"], p["chat_id"]) for p in sent], [(1, "delta", 4242), (2, "delta", 4242),
                                                                              (3, "done", 4242)])
        self.assertEqual(self.call(f"/events?epoch={polled['epoch']}&after={polled['events'][0]['id']}&wait=0")[1]["events"],
                         [])


class CommandTests(NetCase):
    def test_check_does_a_read_only_handshake(self):
        good = FakeBroker(self.server_tls)
        plain = FakeBroker()
        self.addCleanup(good.close)
        self.addCleanup(plain.close)
        out = io.StringIO()
        self.assertEqual(bridge.check(out, {**self.env, "CCWORK_BROKER": f"ssl://127.0.0.1:{good.port}"}), 0)
        text = out.getvalue()
        for expected in ("换令牌：成功（有效期 7200 秒）", "机器人：ID …8765", "DecryptKey 16 字节", "mqtt 字段：没有",
                         "组织路由给的 MQTT 地址：127.0.0.1:1883", f"127.0.0.1:{good.port}  可以"):
            self.assertIn(expected, text)
        self.platform.broker = f"127.0.0.1:{plain.port}"
        out = io.StringIO()
        self.assertEqual(bridge.check(out, self.env, ports=(good.port,)), 0)
        text = out.getvalue()
        self.assertIn(f"127.0.0.1:{plain.port}  不行", text)
        self.assertIn(f"建议：CCWORK_BROKER=ssl://127.0.0.1:{good.port}", text)
        self.assertEqual((good.connects, plain.connects), ([], []))     # 只握手，不发 MQTT 登录包
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        self.assertEqual(bridge.check(io.StringIO(), {"CCWORK_ENABLED": "true"}), 1)

    def test_set_credentials_writes_a_private_file(self):
        from datetime import datetime
        path = Path(self.tmp.name, "doc2sop-ccwork.env")
        path.write_text("CCWORK_ENABLED=true\nCCWORK_APP_KEY=old\n# 注释\n", encoding="utf-8")
        now = datetime(2026, 11, 2, 11, 0, 0)
        out = io.StringIO()
        self.assertEqual(bridge.set_credentials(path, io.StringIO("newkey\nnew-secret=\n"), out, False, now), 0)
        self.assertEqual(path.read_text(encoding="utf-8").splitlines(),
                         ["CCWORK_ENABLED=true", "# 注释", "CCWORK_APP_KEY=newkey", "CCWORK_APP_SECRET=new-secret="])
        backup = Path(f"{path}.bak-20261102110000")
        self.assertIn("CCWORK_APP_KEY=old", backup.read_text(encoding="utf-8"))
        self.assertIn("…wkey", out.getvalue())
        self.assertNotIn("new-secret", out.getvalue())
        self.assertEqual(bridge.set_credentials(path, io.StringIO("k2\ns2\n"), io.StringIO(), False, now), 0)
        self.assertTrue(Path(f"{path}.bak-20261102110000-1").exists())
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        before = path.read_text(encoding="utf-8")
        for bad in ("only-one-line\n", "has space\nsecret\n", 'key\n"quoted"\n'):
            with self.subTest(bad=bad):
                self.assertEqual(bridge.set_credentials(path, io.StringIO(bad), io.StringIO(), False, now), 1)
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertEqual([p.name for p in Path(self.tmp.name).glob(".*.tmp")], [])


if __name__ == "__main__":
    unittest.main()
