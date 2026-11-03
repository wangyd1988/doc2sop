"""钉钉转接程序的网络部分：假的钉钉（HTTPS 开放平台、sessionWebhook、Stream 的 WebSocket，证书写的是钉钉的主机名）、
本地接口、端到端、check / set-credentials 两个命令。每个用例结束时核对日志里没有任何密钥、消息原文和完整 ID。
"""
import io
import json
import logging
import os
import socket
import ssl
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from tests.dingtalk_fakes import (CLIENT_ID, CLIENT_SECRET, GROUP, HOSTS, STAFF, TOKEN, FakeDingTalk, bot_message,
                                  bridge, callback, make_certs, server_context, system, wait_for)

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
HAVE_WS = bridge.websocket is not None
CANARIES = (CLIENT_SECRET, "at-canary", "tk-canary", "sess-canary", "问题金丝雀", GROUP, STAFF)


class Captured(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
class NetCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ca, cert, key = make_certs(self.tmp.name, HOSTS)
        self.fake = FakeDingTalk(server_context(cert, key))
        self.targets = Path(self.tmp.name, "targets.yaml")
        self.env = {"DINGTALK_ENABLED": "true", "DINGTALK_SEND": "on", "DINGTALK_CLIENT_ID": CLIENT_ID,
                    "DINGTALK_CLIENT_SECRET": CLIENT_SECRET, "CHAT_BRIDGE_TOKEN": TOKEN,
                    "DINGTALK_CA_FILE": str(self.ca), "DINGTALK_TARGETS_FILE": str(self.targets)}
        self.log = Captured()
        bridge.log.addHandler(self.log)
        self.level = bridge.log.level
        bridge.log.setLevel(logging.DEBUG)
        self.bridges = []

    def tearDown(self):
        for b in self.bridges:
            b.stop()
        bridge.log.removeHandler(self.log)
        bridge.log.setLevel(self.level)
        self.fake.close()
        self.tmp.cleanup()
        text = "\n".join(self.log.lines)
        for canary in CANARIES:
            self.assertNotIn(canary, text, f"日志里出现了 {canary!r}")

    def config(self, **extra):
        cfg, problems = bridge.load_config({**self.env, **extra})
        self.assertEqual(problems, [])
        return cfg

    def net(self, cfg=None):
        return bridge.Net(bridge.tls_context((cfg or self.config()).ca_file), dial=self.fake.dial, timeout=5)

    def make_bridge(self, start=True, **extra):
        cfg = self.config(**extra)
        b = bridge.Bridge(cfg, net=self.net(cfg), tick=0.05, hint_delay=0.3)
        b._backoff = lambda: 0.05
        self.bridges.append(b)
        if start:
            b.start()
        return b


class PlatformTests(NetCase):
    def test_token_and_stream_ticket(self):
        platform = bridge.Platform(self.config(), self.net())
        self.assertEqual(platform.token(), "at-canary-1")
        self.assertEqual(platform.token(), "at-canary-1")
        host, port, path = platform.open_connection()
        self.assertEqual((host, port), ("wss-open-connection.dingtalk.com", 443))
        self.assertTrue(path.startswith("/connect?ticket=tk-canary-"))
        opened = [d for p, _, d in self.fake.sent(bridge.OPEN_PATH)][0]
        self.assertEqual(opened["subscriptions"], [{"type": "CALLBACK", "topic": bridge.BOT_TOPIC}])
        self.assertEqual({h for h, _ in self.fake.dialed}, {"api.dingtalk.com"})

    def test_wrong_credentials(self):
        cfg = self.config(DINGTALK_CLIENT_SECRET="wrong-secret")
        with self.assertRaises(bridge.PlatformError) as caught:
            bridge.Platform(cfg, self.net(cfg)).token()
        self.assertTrue(caught.exception.definite)
        self.assertNotIn("wrong-secret", str(caught.exception))

    def test_untrusted_or_misnamed_certificates_are_refused(self):
        cfg = self.config()
        system_roots = bridge.Net(bridge.tls_context(""), dial=self.fake.dial, timeout=5)
        with self.assertRaises(bridge.PlatformError) as caught:
            bridge.Platform(cfg, system_roots).token()
        self.assertFalse(caught.exception.sent)
        cert, key = make_certs(Path(self.tmp.name, "other").mkdir() or Path(self.tmp.name, "other"),
                               ("evil.example.com",))[1:]
        stranger = FakeDingTalk(server_context(cert, key))
        self.addCleanup(stranger.close)
        with self.assertRaises(bridge.PlatformError):
            bridge.Platform(cfg, bridge.Net(bridge.tls_context(cfg.ca_file), dial=stranger.dial, timeout=5)).token()
        self.assertEqual(stranger.requests, [])

    def test_redirects_and_foreign_endpoints_are_not_followed(self):
        platform = bridge.Platform(self.config(), self.net())
        self.fake.http_redirect = True
        with self.assertRaises(bridge.PlatformError):
            platform.open_connection()
        self.fake.http_redirect = False
        for endpoint in ("wss://wss-open-connection.dingtalk.com.evil.com/connect", "wss://evildingtalk.com/connect",
                         "wss://wss-open-connection.dingtalk.com:8443/connect", "ws://wss-open-connection.dingtalk.com/c"):
            self.fake.endpoint = endpoint
            with self.assertRaises(bridge.PlatformError):
                platform.open_connection()
        self.assertNotIn("/stolen", [p for p, _, _ in self.fake.sent("/")])
        self.assertTrue(all(h in HOSTS for h, _ in self.fake.dialed))

    def test_the_network_never_dials_anything_but_dingtalk(self):
        net = self.net()
        for url in ("https://evildingtalk.com/x", "https://127.0.0.1/x"):
            with self.assertRaises(bridge.PlatformError) as caught:
                net.post(url, {})
            self.assertFalse(caught.exception.sent)
        with self.assertRaises(bridge.PlatformError):
            net.connect("evil.example.com", 443)
        self.assertEqual(self.fake.dialed, [])

    def test_expired_token_is_refreshed_once(self):
        platform = bridge.Platform(self.config(), self.net())
        platform.token()
        self.fake.expire_next = 1
        platform.send_group(GROUP, "hi")
        self.assertEqual(self.fake.tokens, 2)
        self.fake.expire_next = 2
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_group(GROUP, "hi")
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(self.fake.tokens, 3)

    def test_message_shapes_and_partial_failures(self):
        platform = bridge.Platform(self.config(), self.net())
        platform.send_group(GROUP, "# 标题\n正文", "markdown")
        platform.send_user(STAFF, "你好")
        group, user = self.fake.sent(bridge.GROUP_SEND_PATH)[0][2], self.fake.sent(bridge.USER_SEND_PATH)[0][2]
        self.assertEqual((group["robotCode"], group["openConversationId"], group["msgKey"]),
                         (CLIENT_ID, GROUP, "sampleMarkdown"))
        self.assertEqual(json.loads(group["msgParam"]), {"title": "标题", "text": "# 标题\n正文"})
        self.assertEqual((user["userIds"], user["msgKey"], json.loads(user["msgParam"])),
                         ([STAFF], "sampleText", {"content": "你好"}))
        self.fake.user_reply = {"processQueryKey": "pq", "invalidStaffIdList": [STAFF]}
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_user(STAFF, "你好")
        self.assertTrue(caught.exception.definite and not caught.exception.throttled)
        self.fake.user_reply = {"processQueryKey": "pq", "flowControlledStaffIdList": [STAFF]}
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_user(STAFF, "你好")
        self.assertTrue(caught.exception.throttled)
        self.fake.user_reply = {"invalidStaffIdList": []}          # 200，却没有 processQueryKey：结果不明
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_user(STAFF, "你好")
        self.assertFalse(caught.exception.definite)
        self.fake.fail_next = [(500, {"code": "x"}), (400, {"code": "invalidParameter"})]
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_group(GROUP, "hi")
        self.assertFalse(caught.exception.definite)
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_group(GROUP, "hi")
        self.assertTrue(caught.exception.definite)

    def test_webhook_results(self):
        platform = bridge.Platform(self.config(), self.net())
        hook = "https://oapi.dingtalk.com/robot/sendBySession?session=sess-canary-9"
        platform.send_webhook(hook, "答", at=[STAFF])
        body = self.fake.sent("/robot/sendBySession")[0][2]
        self.assertEqual(body, {"msgtype": "text", "text": {"content": "答"}, "at": {"atUserIds": [STAFF],
                                                                                    "isAtAll": False}})
        self.fake.webhook_next = [(200, {"errcode": 130101, "errmsg": "send too fast"}),
                                  (200, {"errcode": 300001, "errmsg": "session 无效"}), (502, {})]
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_webhook(hook, "答")
        self.assertTrue(caught.exception.throttled)
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_webhook(hook, "答")
        self.assertTrue(caught.exception.definite)
        with self.assertRaises(bridge.PlatformError) as caught:
            platform.send_webhook(hook, "答")
        self.assertFalse(caught.exception.definite)


@unittest.skipUnless(HAVE_WS, "需要 websocket-client（apt: python3-websocket）")
class StreamTests(NetCase):
    def connected(self, b, count=1):
        self.assertTrue(wait_for(lambda: len(self.fake.live()) >= count and len(b.connections()) >= count, 10))
        return self.fake.live()[-1]

    def test_receive_ack_and_ping(self):
        b = self.make_bridge()
        conn = self.connected(b)
        conn.send(callback(bot_message(1), "mid-1"))
        conn.send(system("ping", {"opaque": "op-123"}, "sys-ping"))
        self.assertTrue(wait_for(lambda: len(conn.acks()) == 2))
        acks = {a["headers"]["messageId"]: a for a in conn.acks()}
        self.assertEqual(acks["mid-1"]["code"], 200)
        self.assertEqual(json.loads(acks["sys-ping"]["data"]), {"opaque": "op-123"})
        events = b.inbox.fetch("", 0, 0)["events"]
        self.assertEqual([(e["platform"], e["chat_id"], e["text"]) for e in events],
                         [("dingtalk", GROUP, "问题金丝雀 kb-app 内存高怎么办")])
        self.assertEqual(b.status()["state"], "connected")

    def test_disconnect_overlaps_two_connections_and_dedupes(self):
        b = self.make_bridge()
        old = self.connected(b)
        old.send(system("disconnect", {"reason": "connection is expired"}))
        self.assertTrue(wait_for(lambda: len(self.fake.live()) == 2, 10))
        new = self.fake.live()[-1]
        for n in range(1, 6):                       # 切换期间两边都推同一条
            old.send(callback(bot_message(n), f"a{n}"))
            new.send(callback(bot_message(n), f"b{n}"))
        old.send(callback(bot_message(9), "a9"))    # 旧连接上还能收
        self.assertTrue(wait_for(lambda: b.inbox.size()[0] == 6))
        old.close()
        self.assertTrue(wait_for(lambda: len(b.connections()) == 1))
        time.sleep(0.3)
        self.assertEqual(len(self.fake.live()), 1)
        self.assertEqual(b.inbox.counters["duplicate"], 5)
        self.assertEqual(b.status()["state"], "connected")
        self.assertEqual(len(set(self.fake.used_tickets)), len(self.fake.used_tickets))

    def test_reconnects_after_a_drop_with_a_fresh_ticket(self):
        b = self.make_bridge()
        first = self.connected(b)
        first.close(graceful=False)
        self.assertTrue(wait_for(lambda: len(self.fake.conns) == 2 and self.fake.conns[1].open, 10))
        self.assertNotEqual(self.fake.conns[0].ticket, self.fake.conns[1].ticket)
        self.fake.conns[1].send(callback(bot_message(2), "m2"))
        self.assertTrue(wait_for(lambda: b.inbox.size()[0] == 1))
        self.assertGreaterEqual(b.status()["reconnects"], 1)

    def test_websocket_redirect_and_bad_ticket_are_refused_without_leaking(self):
        self.fake.ws_redirect = True
        b = self.make_bridge()
        self.assertTrue(wait_for(lambda: len(self.fake.used_tickets) >= 2, 10))
        self.assertEqual(self.fake.conns, [])
        self.assertNotIn("/stolen", json.dumps(self.fake.requests, default=str))
        self.fake.ws_redirect = False
        self.fake.tickets.clear()
        original = self.fake.handle

        def stale(*args):                            # 给出去的 ticket 已经作废：握手回 401（正文里带着 ticket）
            result = original(*args)
            self.fake.tickets.clear()
            return result
        self.fake.handle = stale
        time.sleep(0.5)
        self.assertEqual(self.fake.conns, [])
        status = json.dumps(b.status(), ensure_ascii=False)
        for canary in CANARIES:
            self.assertNotIn(canary, status)
        self.fake.handle = original
        self.connected(b)

    def test_proxy_environment_is_ignored(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
                                     "ALL_PROXY": "socks5://127.0.0.1:9", "NO_PROXY": ""}):
            b = self.make_bridge()
            conn = self.connected(b)
            conn.send(callback(bot_message(1)))
            self.assertTrue(wait_for(lambda: b.inbox.size()[0] == 1))

    def test_disabled_never_connects(self):
        b = self.make_bridge(DINGTALK_ENABLED="false")
        time.sleep(0.3)
        self.assertEqual((self.fake.requests, self.fake.dialed), ([], []))
        self.assertEqual(b.status()["state"], "disabled")


@unittest.skipUnless(HAVE_WS, "需要 websocket-client（apt: python3-websocket）")
class LocalApiTests(NetCase):
    def setUp(self):
        super().setUp()
        self.targets.write_text(f'targets:\n  值班群: {{chat_id: "{GROUP}"}}\n  王某某: {{user_id: "{STAFF}"}}\n',
                                encoding="utf-8")
        self.b = self.make_bridge()
        self.server = bridge.make_server(self.b, "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.conn = self.fake.live()[0] if wait_for(lambda: self.fake.live()) else None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def call(self, method, path, body=None, token=TOKEN, protocol="1"):
        request = urllib.request.Request(self.url + path, method=method,
                                         data=None if body is None else json.dumps(body).encode())
        if token:
            request.add_header(bridge.TOKEN_HEADER, token)
        if protocol:
            request.add_header(bridge.PROTOCOL_HEADER, protocol)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def event(self, n=1, **kwargs):
        self.conn.send(callback(bot_message(n, **kwargs), f"m{n}"))
        self.assertTrue(wait_for(lambda: self.b.inbox.size()[0] >= 1))
        return self.call("GET", "/events?wait=0")[1]["events"][-1]

    def test_token_and_protocol_everywhere(self):
        self.assertEqual(self.call("GET", "/health", token="")[0], 401)
        self.assertEqual(self.call("GET", "/health", token="x" * 40)[0], 401)
        self.assertEqual(self.call("GET", "/health", protocol="")[0], 200)
        self.assertEqual(self.call("GET", "/status", protocol="2")[0], 409)
        self.assertEqual(self.call("POST", "/push", {"target": "值班群", "text": "x"}, token="")[0], 401)
        status, body = self.call("GET", "/status")
        self.assertEqual((status, body["platform"], body["formats"], body["targets"]),
                         (200, "dingtalk", ["text", "markdown"], ["值班群", "王某某"]))
        self.assertEqual(body["target_kinds"], {"值班群": "chat", "王某某": "user"})
        text = json.dumps(body, ensure_ascii=False)
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        with self.assertRaises(ValueError):
            bridge.make_server(self.b, "0.0.0.0", 0)

    def test_events_never_carry_the_session_webhook(self):
        got = self.event()
        self.assertNotIn("sess-canary", json.dumps(got))
        self.assertEqual((got["platform"], got["chat_type"], got["sender_id"]), ("dingtalk", "group", STAFF))

    def test_reply_text_and_markdown_through_the_session_webhook(self):
        got = self.event()
        self.assertEqual(self.call("POST", "/reply", {"handle": got["handle"], "text": "答", "mention": True})[0], 200)
        self.assertEqual(self.call("POST", "/reply", {"handle": got["handle"], "text": "**答**",
                                                      "format": "markdown"})[0], 200)
        sent = self.fake.sent("/robot/sendBySession")
        self.assertEqual(sent[0][1]["session"], ["sess-canary-1"])
        self.assertEqual(sent[0][2]["at"]["atUserIds"], [STAFF])
        self.assertEqual(sent[1][2]["msgtype"], "markdown")
        self.assertNotIn("at", sent[1][2])

    def test_stream_quick_and_slow(self):
        got = self.event()
        handle = got["handle"]
        for seq, kind, content in ((1, "delta", "↪ 回复 张三\n🔎 正在查知识库…"), (2, "delta", "正文"),
                                   (3, "delta", "正文\n出处"), (4, "done", "正文\n出处")):
            stream = {"request_id": "q1", "seq": seq, "type": kind, "message_type": "cover", "content": content}
            self.assertEqual(self.call("POST", "/reply", {"handle": handle, "stream": stream})[0], 200)
        time.sleep(0.5)
        self.assertEqual([d["text"]["content"] for _, _, d in self.fake.sent("/robot/sendBySession")], ["正文\n出处"])
        first = {"request_id": "q2", "seq": 1, "type": "delta", "message_type": "cover", "content": "🔎 正在查…"}
        self.call("POST", "/reply", {"handle": handle, "stream": first})
        time.sleep(0.6)
        done = {**first, "seq": 2, "type": "done", "content": "慢答"}
        self.call("POST", "/reply", {"handle": handle, "stream": done})
        self.assertEqual([d["text"]["content"] for _, _, d in self.fake.sent("/robot/sendBySession")][1:],
                         ["🔎 正在查…", "慢答"])

    def test_dead_webhook_falls_back_inside_one_reply(self):
        got = self.event()
        self.fake.webhook_next = [(200, {"errcode": 300001, "errmsg": "session 无效"})]
        status, body = self.call("POST", "/reply", {"handle": got["handle"], "text": "答", "mention": True})
        self.assertEqual((status, body["ok"]), (200, True))
        self.assertEqual(self.fake.sent(bridge.GROUP_SEND_PATH)[0][2]["openConversationId"], GROUP)

    def test_push_by_name(self):
        self.assertEqual(self.call("POST", "/push", {"target": "值班群", "text": "巡检"})[0], 200)
        self.assertEqual(self.call("POST", "/push", {"target": "王某某", "text": "巡检", "format": "markdown"})[0], 200)
        self.assertEqual(self.call("POST", "/push", {"target": GROUP, "text": "巡检"})[0], 404)
        self.assertEqual(self.fake.sent(bridge.GROUP_SEND_PATH)[0][2]["openConversationId"], GROUP)
        self.assertEqual(self.fake.sent(bridge.USER_SEND_PATH)[0][2]["msgKey"], "sampleMarkdown")


class CommandTests(NetCase):
    def test_check_prints_no_secrets(self):
        out = io.StringIO()
        code = bridge.check(out=out, env=self.env, net=self.net())
        text = out.getvalue()
        self.assertEqual(code, 0, text)
        self.assertIn("wss://wss-open-connection.dingtalk.com:443", text)
        self.assertIn("主机名校验通过", text)
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        self.assertEqual(self.fake.conns, [])

    def test_set_credentials(self):
        path = Path(self.tmp.name, "dingtalk.env")
        path.write_text("DINGTALK_ENABLED=false\nDINGTALK_CLIENT_SECRET=old-secret\n", encoding="utf-8")
        out = io.StringIO()
        code = bridge.set_credentials(path, stdin=io.StringIO(f"{CLIENT_ID}\n{CLIENT_SECRET}\n"), out=out,
                                      interactive=False)
        self.assertEqual(code, 0)
        self.assertNotIn(CLIENT_SECRET, out.getvalue())
        values = bridge.read_env_file(path)
        self.assertEqual((values["DINGTALK_CLIENT_ID"], values["DINGTALK_CLIENT_SECRET"], values["DINGTALK_ENABLED"]),
                         (CLIENT_ID, CLIENT_SECRET, "false"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(len(list(path.parent.glob("dingtalk.env.bak-*"))), 1)
        self.assertEqual(bridge.set_credentials(path, stdin=io.StringIO("id\nhas space\n"), out=io.StringIO(),
                                                interactive=False), 1)


if __name__ == "__main__":
    unittest.main()
