"""邮件（app/mailer.py、app/notify.py、app/automation_config.py）：用本地的假 SMTP 服务器测 465（ssl）和 587（starttls）、
失败重试、只发给配置好的收件组、HTML 转义、发不发的判断、服务器配置文件的解析、页面上的「发一封测试邮件」。"""
import base64
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph

from app import automation_config, mailer, notify, runs
from app.config import AUTOMATION_FILE, WEB_PASSWORD, WEB_USER
from app.main import app

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:      # 没有 cryptography 就测不了 TLS
    x509 = None

PASSWORD = "auth-code-123456"
_TMP = tempfile.TemporaryDirectory()
CERT, KEY = Path(_TMP.name, "cert.pem"), Path(_TMP.name, "key.pem")


def make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), True)
            .sign(key, hashes.SHA256()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


if x509 is not None:
    make_cert()


class FakeSMTP:
    """够 smtplib 用的最小 SMTP 服务器：ssl（一连上就是 TLS）或 starttls，AUTH PLAIN，收信存下来。
    fail_first：前几个连接直接回 421（临时失败）。"""

    def __init__(self, mode, fail_first=0):
        self.mode, self.fail_first = mode, fail_first
        self.messages, self.logins, self.connections = [], [], 0
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(CERT, KEY)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def close(self):
        self.sock.close()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        self.connections += 1
        state = {"conn": conn, "tls": False}
        try:
            if self.connections <= self.fail_first:
                conn.sendall(b"421 too busy, try later\r\n")
                return
            if self.mode == "ssl":
                state.update(conn=self.context.wrap_socket(conn, server_side=True), tls=True)
            reader = state["conn"].makefile("rb")

            def send(line):
                state["conn"].sendall(line.encode() + b"\r\n")

            send("220 fake ESMTP")
            sender, rcpts = None, []
            while True:
                raw = reader.readline()
                if not raw:
                    return
                cmd = raw.decode("utf-8", "replace").strip()
                upper = cmd.upper()
                if upper.startswith(("EHLO", "HELO")):
                    lines = ["250-fake"] + (["250-STARTTLS"] if self.mode == "starttls" and not state["tls"] else [])
                    send("\r\n".join(lines + ["250-AUTH PLAIN", "250 8BITMIME"]))
                elif upper == "STARTTLS":
                    send("220 go ahead")
                    state.update(conn=self.context.wrap_socket(state["conn"], server_side=True), tls=True)
                    reader = state["conn"].makefile("rb")
                elif upper.startswith("AUTH PLAIN"):
                    parts = cmd.split(" ", 2)
                    _, user, password = base64.b64decode(parts[2]).split(b"\0")
                    self.logins.append((user.decode(), password.decode(), state["tls"]))
                    send("235 ok" if password.decode() == PASSWORD else "535 5.7.8 bad credentials")
                elif upper.startswith("MAIL FROM"):
                    sender = cmd[10:].strip()
                    send("250 ok")
                elif upper.startswith("RCPT TO"):
                    rcpts.append(cmd[8:].strip().split()[0])
                    send("250 ok")
                elif upper == "DATA":
                    send("354 end with .")
                    data = b""
                    while True:
                        line = reader.readline()
                        if not line or line in (b".\r\n", b".\n"):
                            break
                        data += line
                    self.messages.append((sender, list(rcpts), data, state["tls"]))
                    send("250 queued")
                elif upper == "QUIT":
                    send("221 bye")
                    return
                else:
                    send("250 ok")
        except (OSError, ssl.SSLError):
            return
        finally:
            state["conn"].close()


def write_config(text):
    AUTOMATION_FILE.write_text(text, encoding="utf-8")
    automation_config.reset()


def remove_config():
    AUTOMATION_FILE.unlink(missing_ok=True)
    automation_config.reset()


def config_for(server, security, ca=True, user="bot@example.com", password=PASSWORD):
    return (f"site_url: http://10.0.0.5:8765\nmail:\n  host: 127.0.0.1\n  port: {server.port}\n  security: {security}\n"
            f"  user: {user}\n  password: {password}\n  from: doc2sop 巡检 <bot@example.com>\n"
            + (f"  ca_file: {CERT.as_posix()}\n" if ca else "") + "  timeout: 5\n"
            "groups:\n  运维值班: [ops1@example.com, ops2@example.com]\n  负责人: boss@example.com\n")


@unittest.skipIf(x509 is None, "没有 cryptography，测不了 TLS")
class SmtpTests(unittest.TestCase):
    def setUp(self):
        remove_config()
        self.addCleanup(remove_config)

    def serve(self, mode, **kwargs):
        server = FakeSMTP(mode, **kwargs)
        self.addCleanup(server.close)
        return server

    def test_starttls_on_587(self):
        server = self.serve("starttls")
        write_config(config_for(server, "starttls"))
        result = mailer.send("运维值班", "主题：巡检", "正文", "<p>正文</p>")
        self.assertEqual((result["status"], result["attempts"], result["recipients"]), ("sent", 1, 2))
        sender, rcpts, data, tls = server.messages[0]
        self.assertTrue(tls)
        self.assertEqual(server.logins, [("bot@example.com", PASSWORD, True)])     # 先升级 TLS 再登录
        self.assertEqual(rcpts, ["<ops1@example.com>", "<ops2@example.com>"])
        message = message_from_bytes(data, policy=policy.default)
        self.assertEqual(message["Subject"], "主题：巡检")
        self.assertIn("bot@example.com", message["From"])
        self.assertEqual([part.get_content_type() for part in message.iter_parts()], ["text/plain", "text/html"])

    def test_implicit_tls_on_465(self):
        server = self.serve("ssl")
        write_config(config_for(server, "ssl"))
        self.assertEqual(mailer.send("负责人", "s", "t")["recipients"], 1)
        self.assertEqual(server.messages[0][1], ["<boss@example.com>"])
        self.assertTrue(server.messages[0][3])

    def test_temporary_failures_are_retried(self):
        server = self.serve("starttls", fail_first=2)
        write_config(config_for(server, "starttls"))
        waits = []
        result = mailer.send("运维值班", "s", "t", sleep=waits.append, delays=(1, 2))
        self.assertEqual((result["attempts"], waits), (3, [1, 2]))
        server2 = self.serve("starttls", fail_first=5)
        write_config(config_for(server2, "starttls"))
        with self.assertRaises(mailer.MailError) as caught:
            mailer.send("运维值班", "s", "t", sleep=lambda s: None, delays=(0, 0))
        self.assertEqual(caught.exception.attempts, 3)

    def test_permanent_failures_are_not_retried_and_hide_secrets(self):
        server = self.serve("starttls")
        write_config(config_for(server, "starttls", password="wrong-code-999999"))
        with self.assertLogs("kb", level="WARNING") as logs, self.assertRaises(mailer.MailError) as caught:
            mailer.send("运维值班", "s", "t", sleep=lambda s: None, delays=(0, 0))
        self.assertEqual(caught.exception.attempts, 1)
        self.assertIn("登录被拒绝", str(caught.exception))
        self.assertNotIn("wrong-code-999999", "\n".join(logs.output) + str(caught.exception))
        self.assertNotIn("127.0.0.1", str(caught.exception))       # 页面上看不到 SMTP 地址

    def test_untrusted_certificates_fail(self):
        server = self.serve("ssl")
        write_config(config_for(server, "ssl", ca=False))
        with self.assertRaises(mailer.MailError) as caught:
            mailer.send("运维值班", "s", "t", sleep=lambda s: None, delays=(0, 0))
        self.assertIn("证书", str(caught.exception))
        self.assertEqual(server.messages, [])

    def test_only_configured_groups(self):
        server = self.serve("starttls")
        write_config(config_for(server, "starttls"))
        with self.assertRaises(mailer.MailError) as caught:
            mailer.send("someone@evil.example", "s", "t")
        self.assertIn("没有收件组", str(caught.exception))
        self.assertEqual(server.messages, [])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        remove_config()
        self.addCleanup(remove_config)

    def test_nothing_configured(self):
        settings = automation_config.load()
        self.assertEqual((settings.exists, settings.mail, settings.groups, settings.alert_token), (False, None, {}, ""))
        self.assertEqual(automation_config.public()["mail"], {"configured": False, "security": ""})

    def test_public_view_has_no_addresses_or_secrets(self):
        write_config("site_url: http://10.0.0.5:8765/\nmail:\n  host: smtp.qq.com\n  user: bot@qq.com\n"
                     "  password: secret-auth-code\ngroups:\n  运维值班: [a@x.com, b@x.com]\n"
                     f"alerts:\n  token: {'t' * 32}\n  clients: [10.0.0.0/8]\n")
        public = automation_config.public()
        text = repr(public)
        for secret in ("smtp.qq.com", "bot@qq.com", "secret-auth-code", "a@x.com", "t" * 32):
            self.assertNotIn(secret, text)
        self.assertEqual(public["groups"], [{"name": "运维值班", "count": 2}])
        self.assertEqual((public["mail"]["security"], public["site_url"]), ("ssl", "http://10.0.0.5:8765"))
        self.assertEqual(public["alerts"], {"enabled": True, "clients": ["10.0.0.0/8"]})
        self.assertEqual(automation_config.load().mail.port, 465)

    def test_mistakes_are_described_without_the_secret(self):
        write_config("mail:\n  host: smtp.qq.com\n  password: abc: secret-in-a-broken-line\n")
        problems = automation_config.load().problems
        self.assertIn("第 3 行", problems[0])
        self.assertNotIn("secret-in-a-broken-line", problems[0])
        write_config("mail:\n  host: relay.local\n  security: none\n  user: u@x.com\n  password: p\n"
                     "groups:\n  组: [ok@x.com, not-an-address]\nwhat: 1\n")
        settings = automation_config.load()
        self.assertIsNone(settings.mail)
        joined = "；".join(settings.problems)
        self.assertIn("明文连接", joined)
        self.assertIn("1 个地址写得不对", joined)
        self.assertNotIn("not-an-address", joined)
        self.assertIn("不认识的配置项：what", joined)
        self.assertEqual(settings.groups, {"组": ("ok@x.com",)})

    @unittest.skipIf(os.name == "nt", "只在 Linux 上看文件权限")
    def test_loose_permissions_are_flagged(self):
        write_config("groups:\n  组: [a@x.com]\n")
        os.chmod(AUTOMATION_FILE, 0o644)
        automation_config.reset()
        self.assertIn("chmod 600", automation_config.load().loose)
        os.chmod(AUTOMATION_FILE, 0o600)
        automation_config.reset()
        self.assertEqual(automation_config.load().loose, "")

    def test_changes_are_picked_up_without_restart(self):
        write_config("groups:\n  组: [a@x.com]\n")
        self.assertEqual(list(automation_config.load().groups), ["组"])
        AUTOMATION_FILE.write_text("groups:\n  新的组: [a@x.com]\n", encoding="utf-8")
        stamp = AUTOMATION_FILE.stat().st_mtime + 5
        os.utime(AUTOMATION_FILE, (stamp, stamp))
        self.assertEqual(list(automation_config.load().groups), ["新的组"])


def a_run(level="anomaly", findings=None, followups=None, note="每天 09:00"):
    rows = findings if findings is not None else [
        {"step": "1", "n": 1, "check": "宿主机磁盘", "value": "/ 91% <script>alert(1)</script>", "mark": "bad",
         "note": "超过 90%", "verdict": "❌ 严重"}]
    return {"id": "r1", "execution_id": None, "playbook_id": "p", "playbook_name": "每日<b>巡检</b>", "trigger": "schedule",
            "note": note, "params": {"target": "gateway-b"}, "status": "done", "level": level,
            "level_name": runs.LEVEL_NAMES[level], "summary": "1 项异常", "started_at": "2026-11-01T01:00:05+00:00",
            "finished_at": "2026-11-01T01:01:00+00:00", "answer": "工具原始返回：SECRET-RAW-OUTPUT",
            "report": {"rows": rows, "findings": runs.findings(rows),
                       "followups": followups if followups is not None else ["看 http://evil.example/x 的说明"]}}


class ComposeTests(unittest.TestCase):
    def test_subject_body_and_escaping(self):
        subject, text, body = notify.compose(a_run(), "problem", None, "http://10.0.0.5:8765")
        self.assertEqual(subject, "[doc2sop] 【有异常】SOP《每日<b>巡检</b>》 11-01 09:00")
        self.assertIn("北京时间", text)
        self.assertIn("❌ 第 1 步 宿主机磁盘：/ 91%", text)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<script>", body)
        self.assertIn("每日&lt;b&gt;巡检&lt;/b&gt;", body)
        # 只有我们自己的报告链接是可点的；模型输出里的链接原样当文字
        self.assertEqual(body.count("<a "), 1)
        self.assertIn('<a href="http://10.0.0.5:8765/sop?tab=runs&amp;item=r1">', body)
        self.assertIn("http://evil.example/x", body)
        self.assertNotIn('href="http://evil.example', body)
        # 不附工具的原始返回
        self.assertNotIn("SECRET-RAW-OUTPUT", text + body)

    def test_tags_and_missing_site_url(self):
        self.assertIn("【仍未恢复·有异常】", notify.compose(a_run(), "still", None)[0])
        self.assertIn("【已恢复】", notify.compose(a_run(level="ok", findings=[]), "recovered", None)[0])
        self.assertIn("【没跑成】", notify.compose(a_run(level="failed", findings=[]), "problem", None)[0])
        _, text, body = notify.compose(a_run(), "problem", None, "")
        self.assertIn("没有配置 site_url", text)
        self.assertNotIn("<a ", body)

    def test_compare_goes_into_the_mail(self):
        diff = {"previous": {"started_at": "2026-10-31T01:00:00+00:00", "level": "ok"}, "note": "",
                "new": [{"step": "第 1 步 宿主机磁盘", "value": "/ 91%"}], "still": [], "recovered": [],
                "changed": [{"step": "第 1 步 宿主机磁盘", "deltas": ["70% → 91%（+21）"]}], "gone": []}
        _, text, _ = notify.compose(a_run(), "problem", diff, "")
        self.assertIn("和上次比（2026-10-31 09:00）", text)
        self.assertIn("新出现：第 1 步 宿主机磁盘：/ 91%", text)
        self.assertIn("70% → 91%（+21）", text)


class DecideTests(unittest.TestCase):
    NOTIFY = {"group": "运维值班", "when": "problems", "repeat": "daily"}

    def decide(self, run, state, now=None, **notify_):
        return notify.decide({**self.NOTIFY, **notify_}, state, run, now or datetime(2026, 11, 1, 2, tzinfo=timezone.utc))[0]

    def test_rules(self):
        bad, ok = a_run(), a_run(level="ok", findings=[])
        sig = runs.signature(bad)
        self.assertEqual(self.decide(bad, {}), "problem")
        sent = {"notified": sig, "sent_at": "2026-11-01T01:30:00+00:00"}
        self.assertIsNone(self.decide(bad, sent))                                    # 一天内不重复
        self.assertEqual(self.decide(bad, sent, now=datetime(2026, 11, 2, 2, tzinfo=timezone.utc)), "still")
        self.assertEqual(self.decide(bad, sent, repeat="always"), "still")
        self.assertIsNone(self.decide(bad, sent, repeat="never",
                                      now=datetime(2026, 11, 9, tzinfo=timezone.utc)))  # 恢复之前不重复发
        self.assertEqual(self.decide(ok, sent), "recovered")
        self.assertIsNone(self.decide(ok, {}))
        self.assertEqual(self.decide(ok, {}, when="always"), "normal")
        self.assertEqual(self.decide(a_run(level="failed", findings=[]), sent), "problem")   # 换了问题
        self.assertIsNone(self.decide(bad, {}, group=""))

    def test_clean_only_allows_server_groups(self):
        self.assertEqual(notify.clean({"group": "运维值班"}, {"运维值班": ("a@x.com",)})["repeat"], "daily")
        with self.assertRaises(notify.InvalidNotify):
            notify.clean({"group": "a@evil.example"}, {"运维值班": ("a@x.com",)})
        with self.assertRaises(notify.InvalidNotify):
            notify.clean({"group": "", "when": "sometimes"}, {})


class TestMailApiTests(unittest.TestCase):
    def setUp(self):
        clear_graph()
        remove_config()
        self.addCleanup(remove_config)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def post(self, group):
        return self.client.post("/api/automation/test-mail", json={"group": group}, auth=self.auth)

    def test_test_mail(self):
        self.assertEqual(self.post("运维值班").status_code, 409)                 # 没配邮件
        write_config("mail:\n  host: smtp.example.com\n  user: bot@example.com\n  password: secret-code-xyz\n"
                     "groups:\n  运维值班: [ops@example.com]\n")
        self.assertEqual(self.post("a@evil.example").status_code, 400)
        sent = []
        with patch.object(mailer, "send", side_effect=lambda *a, **k: sent.append(a) or {"recipients": 1, "attempts": 1}), \
             patch.dict("app.automation_api._test_mail", {"times": __import__("collections").deque(), "by_group": {}}), \
             self.assertLogs("kb", level="INFO") as logs:
            first = self.post("运维值班")
            second = self.post("运维值班")
        self.assertEqual((first.status_code, first.json()["recipients"]), (200, 1))
        self.assertEqual(second.status_code, 429)
        self.assertEqual(sent[0][0], "运维值班")
        self.assertIn("test mail to group 运维值班 requested", "\n".join(logs.output))
        self.assertNotIn("secret-code-xyz", "\n".join(logs.output))
        status = self.client.get("/api/automation", auth=self.auth).json()
        self.assertTrue(status["mail"]["configured"])
        self.assertNotIn("secret-code-xyz", repr(status))
        # 收件地址、发件账号现在在 settings 里看得到（要改就得看得见）；摘要里照旧只有组名和人数，授权码哪里都没有
        self.assertEqual(status["settings"]["groups"], [{"name": "运维值班", "addresses": ["ops@example.com"], "source": "server"}])
        self.assertEqual(status["settings"]["mail"]["password"], {"state": "server", "set_at": ""})
        self.assertNotIn("ops@example.com", repr({k: v for k, v in status.items() if k != "settings"}))


if __name__ == "__main__":
    unittest.main()
