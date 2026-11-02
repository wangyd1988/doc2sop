"""云上协同转接程序（deploy/ccwork/ccwork_bridge.py）的离线部分：加解密、厂商程序对照数据、protobuf 解码、
收到推送后的过滤、待取队列、handle、配置。网络部分（平台接口、MQTT、本地接口、命令）在 test_ccwork_bridge_net.py。
"""
import base64
import json
import random
import threading
import time
import unittest
from pathlib import Path

from tests.ccwork_fakes import (KEY, ROBOT_ID, Clock, bridge, chat_message, f_bytes, f_int, robot, text_body,
                                varint)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ccwork_crypto_vectors.json"
HAVE_CRYPTO = bridge.Cipher is not None


@unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
class CryptoTests(unittest.TestCase):
    def test_standard_vectors(self):
        # FIPS-197 附录 C.1（AES-128）：ECB 的第一块就是标准密文
        aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(bridge.encrypt("aes", bytes.fromhex("00112233445566778899aabbccddeeff"), aes_key)[:16].hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")
        # GB/T 32907 的 SM4 示例：这把密钥不是合法 UTF-8，IV 全 0，CBC 的第一块就是标准密文
        sm4_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        self.assertEqual(bridge.sm4_iv(sm4_key), bytes(16))
        self.assertEqual(bridge.encrypt("sm4", sm4_key, sm4_key)[:16].hex(), "681edf34d206965e86b3e94f536e4246")

    def test_sm4_iv_comes_from_the_key(self):
        self.assertEqual(bridge.sm4_iv(b"Wc6AQHJFQiBasKJQ"), b"W6QJQBsJcAHFiaKQ")
        self.assertEqual(bridge.sm4_iv(bytes(range(240, 256))), bytes(16))

    def test_round_trips_keep_every_byte(self):
        rng = random.Random(7)
        keys = {"aes": [KEY, KEY * 2, bytes(rng.randrange(256) for _ in range(16))],
                "sm4": [KEY, bytes(rng.randrange(256) for _ in range(16))]}
        for alg, ring in keys.items():
            for key in ring:
                for size in (0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 1000):
                    plain = bytes(rng.randrange(256) for _ in range(size))
                    with self.subTest(alg=alg, key=len(key), size=size):
                        cipher = bridge.encrypt(alg, plain, key)
                        self.assertEqual(len(cipher) % 16, 0)
                        self.assertEqual(bridge.decrypt(alg, cipher, key), plain)

    def test_rejects_bad_input(self):
        cipher = bridge.encrypt("aes", b"hello", KEY)
        for alg, data, key in (("aes", cipher[:-1], KEY), ("aes", b"", KEY), ("aes", cipher, b"short"),
                               ("sm4", cipher, KEY * 2), ("aes", cipher, b"X" * 16), ("rot13", cipher, KEY)):
            with self.subTest(alg=alg, size=len(data), key=len(key)):
                with self.assertRaises(bridge.CryptoError):
                    bridge.decrypt(alg, data, key)

    def test_external_type_picks_the_cipher(self):
        for flags, expected in ((0, "aes"), (0x02, "aes"), (0x40, "sm4"), (0x42, None), (0x41, "sm4"), (0x83, "aes")):
            with self.subTest(flags=hex(flags)):
                self.assertEqual(bridge.cipher_for(flags), expected)


@unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
class VendorVectorTests(unittest.TestCase):
    """厂商程序在 A 上用 gVisor 断网跑一次的结果（deploy/ccwork/crypto_vectors.py）：我们的实现要逐字节对上。"""

    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    @staticmethod
    def parts(case):
        req = case["request"]
        plain = base64.b64decode(case["plain"]) if case["plain"] is not None else None
        return req, base64.b64decode(req["key"]), plain

    def test_it_is_the_audited_binary(self):
        self.assertEqual(self.data["vendor"]["sha256"],
                         "11c375dae38e41f44addfbd3f6607d691a959ba6a8d6df2868b8c1fa94854800")
        self.assertIn("--network none", self.data["vendor"]["command"])
        self.assertEqual(len(self.data["cases"]), 220)

    def test_our_encryption_matches_the_vendor_byte_for_byte(self):
        checked = {"aes": 0, "sm4": 0}
        for case in self.data["cases"]:
            req, key, plain = self.parts(case)
            if req["op"] != "encrypt" or case["response"].get("code") != 0:
                continue
            with self.subTest(case=case["id"], name=case["name"], key=case["key_name"]):
                vendor = base64.b64decode(case["response"]["data"])
                self.assertEqual(bridge.encrypt(case["alg"], plain, key), vendor)
                self.assertEqual(bridge.decrypt(case["alg"], vendor, key), plain)
                checked[case["alg"]] += 1
        self.assertEqual(checked, {"aes": 49, "sm4": 33})

    def test_vendor_decryption_agrees_and_mangles_binary(self):
        """解密的请求里，密文是生成请求时我们的实现加密的（那时 SM4 还按 IV 全 0）。厂商程序按 utf8 输出：
        明文是合法 UTF-8 时和我们按同一规则解出来的一致；不是时（二进制、超过 127 字节的 protobuf）被它改坏。"""
        agreed = mangled = 0
        for case in self.data["cases"]:
            req, key, plain = self.parts(case)
            if req["op"] != "decrypt" or case["response"].get("code") != 0:
                continue
            raw = base64.b64decode(req["data"])
            alg = case["alg"]
            worker = bridge._cipher(alg, key).decryptor()
            padded = worker.update(raw) + worker.finalize()
            pad = padded[-1]
            expected = padded[:-pad] if 1 <= pad <= 16 and padded[-pad:] == bytes([pad]) * pad else b""
            out = case["response"]["data"]
            with self.subTest(case=case["id"], name=case["name"], key=case["key_name"]):
                try:
                    text = expected.decode("utf-8")
                except UnicodeDecodeError:
                    self.assertNotEqual(out.encode("utf-8"), expected)
                    self.assertIn("\ufffd", out)
                    mangled += 1
                else:
                    self.assertEqual(out, text)
                    agreed += 1
        self.assertEqual((agreed, mangled), (58, 22))
        pb = [c for c in self.data["cases"] if c["name"] == "decrypt raw->utf8 pb" and c["alg"] == "aes"]
        self.assertTrue(pb and all("\ufffd" in c["response"]["data"] for c in pb))

    def test_vendor_refusals(self):
        refusals = {case["name"].split()[1] for case in self.data["cases"] if case["response"].get("code") != 0}
        self.assertEqual(refusals, {"raw->raw", "bad"})
        bad_key = [c for c in self.data["cases"] if c["name"] == "encrypt bad key"]
        self.assertTrue(all("invalid key size" in c["response"]["message"] for c in bad_key))
        with self.assertRaises(bridge.CryptoError):
            bridge.encrypt("aes", b"abc", b"0123456789")


class ProtoTests(unittest.TestCase):
    def test_decodes_what_we_need(self):
        msg = bridge.decode(chat_message(text_body("你好", at=[ROBOT_ID]), user_type=3, encrypt=False,
                                         external_type=0), bridge.MESSAGE)
        self.assertEqual((msg["message_type"], msg["chat_id"], msg["chat_type"], msg["chat_name"]),
                         (1, 4242, 2, "运维值班群"))
        self.assertEqual(msg["sender"], {"user_id": "u_alice", "name": "张三", "user_type": 3})
        self.assertEqual(bridge.decode(msg["content"], bridge.TEXT), {"text": "你好", "at": [ROBOT_ID]})

    def test_skips_unknown_fields_and_reads_negative_int32(self):
        data = f_bytes(9, b"\x0a\x03abc") + varint(13 << 3 | 1) + b"12345678" + f_int(1, -2) + varint(14 << 3 | 5) + b"abcd"
        self.assertEqual(bridge.decode(data, bridge.MESSAGE), {"message_type": -2})

    def test_limits(self):
        nested = {}
        nested[1] = ("x", nested)
        deep = b""
        for _ in range(8):
            deep = f_bytes(1, deep)
        cases = {"truncated varint": (b"\x08\x80", bridge.MESSAGE), "varint too long": (b"\x08" + b"\xff" * 11, bridge.MESSAGE),
                 "length past the end": (b"\x62\x10abc", bridge.MESSAGE), "group wire type": (b"\x0b\x0c", bridge.MESSAGE),
                 "field zero": (b"\x00\x01", bridge.MESSAGE), "wrong wire type": (f_bytes(1, b"x"), bridge.MESSAGE),
                 "too deep": (deep, nested), "too many at": (b"".join(f_bytes(2, "a") for _ in range(600)), bridge.TEXT),
                 "too many fields": (f_int(30, 1) * 5000, bridge.MESSAGE), "short fixed64": (b"\x09abc", bridge.MESSAGE)}
        for name, (data, schema) in cases.items():
            with self.subTest(name):
                with self.assertRaises(bridge.ProtoError):
                    bridge.decode(data, schema)

    @unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
    def test_fuzzed_payloads_never_escape(self):
        rng = random.Random(1102)
        seeds = [chat_message(text_body("问题" * n, at=[ROBOT_ID] * (n % 3)), chat_type=1 + n % 2) for n in range(1, 6)]
        outcomes = set()
        for _ in range(3000):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randrange(1, 6)):
                action, pos = rng.randrange(3), rng.randrange(len(data))
                if action == 0:
                    data[pos] = rng.randrange(256)
                elif action == 1:
                    del data[pos:pos + rng.randrange(1, 8)]
                else:
                    data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
            outcome, event = bridge.interpret(bytes(data), robot())
            outcomes.add(outcome.split("_")[0])
            self.assertTrue(event is None or isinstance(event["text"], str))
        self.assertIn("malformed", outcomes)


@unittest.skipUnless(HAVE_CRYPTO, "需要 cryptography")
class InterpretTests(unittest.TestCase):
    def check(self, payload, outcome, kind=None):
        got, event = bridge.interpret(payload, robot())
        self.assertEqual(got, outcome)
        self.assertEqual(event["kind"] if event else None, kind)
        return event

    def test_direct_and_mentioned_text_is_forwarded(self):
        event = self.check(chat_message(text_body("kb-app 内存高怎么办"), chat_type=1, chat_name=""), "forwarded", "text")
        self.assertEqual(event, {"kind": "text", "platform": "ccwork", "chat_type": "single", "chat_id": "4242",
                                 "chat_name": "", "sender_id": "u_alice", "sender_name": "张三", "sender_type": 0,
                                 "msg_key": "123456789", "text": "kb-app 内存高怎么办"})
        event = self.check(chat_message(text_body("@doc2sop 查一下", at=["u_bob", ROBOT_ID]), uniq=0), "forwarded", "text")
        self.assertEqual((event["chat_type"], event["msg_key"], event["text"]), ("group", "4242:7", "@doc2sop 查一下"))

    def test_group_messages_without_a_mention_are_dropped(self):
        self.check(chat_message(text_body("大家好")), "not_at")
        self.check(chat_message(text_body("@所有人 开会", at_all=True)), "not_at")
        self.check(chat_message(text_body("@张三", at=["u_zhang"]), chat_type=3), "not_at")

    def test_dropped_before_anything_else(self):
        self.check(b"\x08" * (bridge.PAYLOAD_MAX + 1), "too_large")
        self.check(chat_message(text_body("hi"), sender=ROBOT_ID, chat_type=1), "self")
        self.check(chat_message(b"", message_type=6666, chat_type=1), "order")
        for chat_type in (6, 7, 8, 0):
            self.check(chat_message(text_body("hi"), chat_type=chat_type), "chat_type")
        self.check(b"\xff\xff\xff", "malformed")

    def test_other_content(self):
        self.check(chat_message(b"\x0a\x01x", message_type=2, chat_type=1), "unsupported", "unsupported")
        self.check(chat_message(b"\x0a\x01x", message_type=2), "not_text")
        self.check(chat_message(b"\x0a\x01x", message_type=9999, chat_type=1), "not_text")
        mixed = f_bytes(1, f_bytes(2, text_body("看图"))) + f_bytes(2, ROBOT_ID)
        self.check(chat_message(mixed, message_type=14), "unsupported", "unsupported")
        self.check(chat_message(f_bytes(2, "u_bob"), message_type=14), "not_at")
        quote = f_bytes(1, text_body("执行", at=[ROBOT_ID])) + f_bytes(2, b"\x08\x01")
        self.check(chat_message(quote, message_type=999), "unsupported", "unsupported")

    def test_encryption_variants(self):
        self.check(chat_message(text_body("国密", at=[ROBOT_ID]), external_type=0x40), "forwarded", "text")
        self.check(chat_message(text_body("默认", at=[ROBOT_ID]), external_type=0), "forwarded", "text")
        self.check(chat_message(text_body("不加密", at=[ROBOT_ID]), external_type=0x42), "forwarded", "text")
        wrong = chat_message(text_body("错的密钥"), chat_type=1, key=b"X" * 16)
        self.check(wrong, "decrypt_failed_aes", "undecryptable")
        self.check(chat_message(text_body("错的密钥", at=[ROBOT_ID]), key=b"X" * 16), "decrypt_failed_aes")

    def test_long_text_is_cut_on_a_character_boundary(self):
        event = self.check(chat_message(text_body("长" * 5000), chat_type=1), "forwarded", "text")
        self.assertTrue(event["truncated"])
        self.assertLessEqual(len(event["text"].encode()), bridge.TEXT_MAX)
        self.assertEqual(set(event["text"]), {"长"})


def event(n=1, chat="4242", sender="u_alice", kind="text"):
    return {"kind": kind, "platform": "ccwork", "chat_type": "group", "chat_id": chat, "chat_name": "群",
            "sender_id": sender, "sender_name": "张三", "sender_type": 0, "msg_key": f"k{chat}-{sender}-{n}", "text": "问"}


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.inbox = bridge.Inbox(self.clock, wall=lambda: 1_700_000_000)

    def test_fetch_acknowledges_what_kb_app_has_stored(self):
        for n in range(3):
            self.assertEqual(self.inbox.offer(event(n, sender=f"u{n}")), "queued")
        first = self.inbox.fetch("", 0, 0)
        self.assertEqual([e["id"] for e in first["events"]], [1, 2, 3])
        again = self.inbox.fetch(first["epoch"], 2, 0)
        self.assertEqual([e["id"] for e in again["events"]], [3])
        self.assertEqual(self.inbox.size()[0], 1)

    def test_epoch_guards_the_cursor(self):
        self.inbox.offer(event())
        with self.assertRaises(bridge.EpochMismatch) as caught:
            self.inbox.fetch("old-epoch", 5, 0)
        self.assertEqual(str(caught.exception), self.inbox.epoch)
        # 不带 epoch 时编号不作数（可能是转接程序重启前的），也就不会误确认
        self.assertEqual(len(self.inbox.fetch("", 99, 0)["events"]), 1)

    def test_duplicates_and_rates(self):
        self.assertEqual(self.inbox.offer(event()), "queued")
        self.assertEqual(self.inbox.offer(event()), "duplicate")
        results = [self.inbox.offer(event(n)) for n in range(2, 20)]
        self.assertEqual(results.count("queued"), bridge.SENDER_PER_MINUTE - 1)
        self.assertEqual(set(results[bridge.SENDER_PER_MINUTE - 1:]), {"sender_rate"})
        results = [self.inbox.offer(event(n, sender=f"s{n}", chat="77")) for n in range(40)]
        self.assertEqual(results.count("queued"), bridge.CHAT_PER_MINUTE)
        self.clock.now += 61
        self.assertEqual(self.inbox.offer(event(99)), "queued")

    def test_one_noisy_chat_cannot_crowd_out_the_others(self):
        for n in range(10):
            self.inbox.offer(event(n, chat="quiet", sender=f"q{n}"))
        for minute in range(3):                 # 每分钟 25 条，三分钟 75 条：超过一个会话最多占的 50 条
            self.clock.now += 61
            for n in range(25):
                self.inbox.offer(event(minute * 100 + n, chat="noisy", sender=f"n{minute}-{n}"))
        self.assertEqual(self.inbox.size()[0], 10 + bridge.PER_CHAT_MAX)
        self.assertEqual(self.inbox.counters["dropped_chat_full"], 75 - bridge.PER_CHAT_MAX)
        # 队列满了：从占得最多的会话里丢，安静的那个群一条不少
        for minute in range(3):
            self.clock.now += 61
            for chat in range(6):
                for n in range(20):
                    self.inbox.offer(event(minute * 1000 + n, chat=f"c{chat}", sender=f"c{chat}-{minute}-{n}"))
        chats = [e["chat_id"] for e in self.inbox.fetch("", 0, 0, limit=50)["events"]]
        self.assertEqual(self.inbox.size()[0], bridge.QUEUE_MAX)
        self.assertEqual(chats[:10], ["quiet"] * 10)
        self.assertGreater(self.inbox.counters["dropped_queue_full"], 0)

    def test_old_messages_expire(self):
        self.inbox.offer(event())
        self.clock.now += bridge.EVENT_TTL
        self.assertEqual(self.inbox.fetch("", 0, 0)["events"], [])
        self.assertEqual(self.inbox.counters["expired"], 1)

    def test_long_poll_wakes_up_on_new_messages(self):
        inbox = bridge.Inbox()
        got = {}
        worker = threading.Thread(target=lambda: got.update(inbox.fetch("", 0, 5)))
        started = time.monotonic()
        worker.start()
        time.sleep(0.2)
        inbox.offer(event())
        worker.join(5)
        self.assertEqual(len(got["events"]), 1)
        self.assertLess(time.monotonic() - started, 3)


class HandleTests(unittest.TestCase):
    def test_handles_expire_and_carry_only_the_destination(self):
        clock = Clock()
        handles = bridge.Handles(clock)
        handle = handles.issue(event())
        self.assertEqual(handles.get(handle), {"chat_type": "group", "chat_id": "4242", "sender_id": "u_alice"})
        self.assertIsNone(handles.get("guess"))
        clock.now += bridge.HANDLE_TTL
        self.assertIsNone(handles.get(handle))


class ConfigTests(unittest.TestCase):
    BASE = {"CCWORK_ENABLED": "true", "CCWORK_APP_KEY": "key-1", "CCWORK_APP_SECRET": "secret-1",
            "CCWORK_BASE_URL": "https://open.example.com/", "CCWORK_BROKER": "ssl://mqtt.example.com:8883",
            "CHAT_BRIDGE_TOKEN": "t" * 40}

    def test_defaults_are_off(self):
        cfg, problems = bridge.load_config({})
        self.assertEqual(problems, [])
        self.assertFalse(cfg.enabled or cfg.send or cfg.plaintext)
        self.assertEqual((cfg.listen, cfg.saas_host, cfg.broker), (("127.0.0.1", 8796), bridge.SAAS_DEFAULT, None))

    def test_a_good_configuration(self):
        cfg, problems = bridge.load_config(self.BASE)
        self.assertEqual(problems, [])
        self.assertEqual(cfg.base_url, "https://open.example.com")
        self.assertEqual(cfg.broker, bridge.Broker(True, "mqtt.example.com", 8883))
        self.assertNotIn("secret-1", repr(cfg))
        self.assertNotIn("t" * 40, repr(cfg))

    def test_refusals(self):
        cases = {"CCWORK_BASE_URL": "http://open.example.com", "CCWORK_SAAS_HOST": "http://r.ccwork.com",
                 "CCWORK_BROKER": "ws://mqtt.example.com", "CCWORK_ALLOW_PLAINTEXT": "yes", "CCWORK_SEND": "maybe",
                 "CCWORK_CRYPTO": "vendor", "CHAT_BRIDGE_TOKEN": "short", "CCWORK_LISTEN": "0.0.0.0:8796"}
        for name, value in cases.items():
            with self.subTest(name):
                cfg, problems = bridge.load_config({**self.BASE, name: value})
                self.assertEqual(len(problems), 1, problems)
        cfg, _ = bridge.load_config({**self.BASE, "CCWORK_LISTEN": "[::1]:9000", "CCWORK_ALLOW_PLAINTEXT": "diagnose",
                                     "CCWORK_BROKER": "tcp://10.0.0.5", "CCWORK_SEND": "on"})
        self.assertEqual((cfg.listen, cfg.plaintext, cfg.broker.tls, cfg.broker.port, cfg.send),
                         (("::1", 9000), True, False, 1883, True))

    def test_robot_never_shows_its_secrets(self):
        self.assertEqual(repr(robot(password="jwt-secret")), "Robot(…8765, org=ORG)")
        self.assertEqual(bridge.tail("123456789"), "…6789")
        self.assertEqual(bridge.tail(""), "-")


class DeployFileTests(unittest.TestCase):
    """systemd 单元和环境文件的样例：默认关、只收不发；进程读不到 kb-app 的数据、别的服务的凭据和自己的环境文件。"""

    def test_unit_keeps_the_bridge_boxed_in(self):
        unit = (FIXTURE.parent.parent.parent / "deploy" / "ccwork" / "doc2sop-ccwork.service.example").read_text(
            encoding="utf-8")
        settings = [line.strip() for line in unit.splitlines() if line.strip() and not line.startswith("#")]
        for expected in ("User=doc2sop-ccwork", "EnvironmentFile=/etc/doc2sop-ccwork.env", "NoNewPrivileges=yes",
                         "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "CapabilityBoundingSet=",
                         "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "MemoryMax=100M",
                         "ExecStart=/usr/bin/python3 -I /opt/doc2sop-ccwork/ccwork_bridge.py serve"):
            self.assertIn(expected, settings)
        hidden = " ".join(line for line in settings if line.startswith("InaccessiblePaths="))
        for path in ("/opt/kb-app", "/etc/ops-readonly.env", "/etc/doc2sop-sandbox.env", "/etc/doc2sop-ccwork.env",
                     "/run/docker.sock"):
            self.assertIn(f"-{path}", hidden)
        self.assertFalse(any(line.startswith(("ReadWritePaths=", "StateDirectory=", "SupplementaryGroups="))
                             for line in settings))

    def test_env_example_starts_off(self):
        env = (FIXTURE.parent.parent.parent / "deploy" / "ccwork" / "ccwork.env.example").read_text(encoding="utf-8")
        values = dict(line.split("=", 1) for line in env.splitlines() if line and not line.startswith("#"))
        self.assertEqual((values["CCWORK_ENABLED"], values["CCWORK_SEND"], values["CCWORK_ALLOW_PLAINTEXT"]),
                         ("false", "off", ""))
        self.assertNotIn("CCWORK_APP_SECRET", values)
        cfg, problems = bridge.load_config(values)
        self.assertEqual(problems, [])
        self.assertFalse(cfg.enabled or cfg.send or cfg.plaintext)


if __name__ == "__main__":
    unittest.main()
