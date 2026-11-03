"""用账号密码添加机器（工具服务这一层）：添加流程的授权（票据）、安装第 0 步核对来源地址、改出口地址。

票据：host-onboard 核对一次口令后发出，只存 sha256（compare_digest 比较），绑定主机、条目、来源 IP、口令文件，15 分钟；
只能代替口令登记 host key（一次）、用密码安装、只改出口地址；页面审批锁定中不认；不对、过期不计口令的输错次数；
主机改了、删了、口令改了就作废。来源地址：目标主机看到的来源（SSH_CONNECTION）不在出口地址里，第 0 步就停下、什么都不改。
"""
import io
import json
import os
import re
import shutil
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

from tests.test_host_install import SECRET, SUPPORTED, FakeRemote
from tests.test_page_config import HOST_BLOB, HOSTS_CONFIG, PASS, POSIX, WEB01, WRONG, _Config, ops, quiet

REAL_WHICH = shutil.which
OTHER_IP = "web user=admin ip=10.9.9.9"


class _Onboard(_Config):
    CONFIG = HOSTS_CONFIG

    def setUp(self):
        super().setUp()
        self.set_passphrase()
        for patcher in (patch.dict(ops._install_times, clear=True), patch.dict(ops._install_denied, clear=True),
                        patch.dict(ops._onboard, clear=True),
                        patch.object(ops, "host_install_support", lambda: dict(SUPPORTED))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def onboard(self, **fields):
        result = self.ok(ops.page_host_onboard, {"host": {**WEB01, **fields}, "passphrase": PASS})
        self.assertRegex(result["ticket"], r"^[A-Za-z0-9_-]{40,}$")
        return result

    def trust(self, ticket, caller=None, **extra):
        payload = {"name": "web01", "fingerprint": ops.key_fingerprint(HOST_BLOB), "confirm_impact": ["gw_disk"],
                   "ticket": ticket, **extra}
        if caller is None:
            return self.do(ops.page_host_trust, payload)[0]
        result, printed = quiet(ops.page_host_trust, payload, caller)
        self.printed.write(printed)
        return result

    def passphrase_checks(self):
        return self.printed.getvalue().count("：口令正确")


class TicketTests(_Onboard):
    def test_one_passphrase_for_the_whole_flow(self):
        result = self.onboard()
        self.assertEqual(result["saved"], "web01")
        self.assertEqual(result["ticket_minutes"], 15)
        self.assertTrue(result["scan"]["checks"][0]["keys"])
        self.assertEqual(self.passphrase_checks(), 1)
        trusted = self.trust(result["ticket"])
        self.assertNotIsInstance(trusted, Exception, trusted)
        self.assertEqual(self.passphrase_checks(), 1)                       # 登记 host key 没再核对口令
        self.assertIn("[approval] 核对 host key web01：用添加流程的授权（口令在", self.printed.getvalue())
        self.assertTrue(ops._page_host_view("web01")["active"])
        # 票据不进日志、旁路文件、变更记录、任何对外的视图
        self.assertNotIn(result["ticket"], self.everything_said())
        self.assertNotIn(result["ticket"], json.dumps(ops._onboard, default=str))
        self.assertEqual(ops._approval["failures"], 0)

    def test_trust_with_a_ticket_is_used_once(self):
        ticket = self.onboard()["ticket"]
        self.assertNotIsInstance(self.trust(ticket), Exception)
        error = self.trust(ticket, replace=True)
        self.assertIsInstance(error, ops.TicketRefused)
        self.assertEqual((error.status, error.extra), (409, {"ticket_refused": True}))
        self.assertIn("已经用来登记过", str(error))
        # 用掉的只是「登记」这一项：改出口地址照样认
        self.ok(ops.page_host_from, {"name": "web01", "address": "117.72.91.20", "ticket": ticket})

    def test_wrong_tickets_do_not_count_and_do_not_burn_the_real_one(self):
        ticket = self.onboard()["ticket"]
        compared = []
        real = ops.secrets.compare_digest
        with patch.object(ops.secrets, "compare_digest", lambda a, b: compared.append(1) or real(a, b)):
            for bad in ("x" * 43, ticket[:-1] + ("A" if ticket[-1] != "A" else "B"), "", None):
                payload_ticket = bad if bad else "nope"
                error = self.trust(payload_ticket)
                self.assertIsInstance(error, ops.TicketRefused)
                self.assertIn("对不上", str(error))
        self.assertTrue(compared)
        self.assertEqual(ops._approval["failures"], 0)                      # 票据不对不计口令的输错次数
        self.assertNotIsInstance(self.trust(ticket), Exception)

    def test_missing_ticket_falls_back_to_the_passphrase(self):
        self.onboard()
        error = self.do(ops.page_host_trust, {"name": "web01", "fingerprint": ops.key_fingerprint(HOST_BLOB),
                                              "confirm_impact": ["gw_disk"], "passphrase": WRONG})[0]
        self.assertEqual(getattr(error, "status", None), 403)
        self.assertEqual(ops._approval["failures"], 1)

    def test_expired(self):
        ticket = self.onboard()["ticket"]
        ops._onboard["web01"]["expires"] = time.time() - 1
        error = self.trust(ticket)
        self.assertIn("过期", str(error))
        self.assertNotIn("web01", ops._onboard)                             # 过期的作废、删掉
        self.assertIn("已经没有了", str(self.trust(ticket)))

    def test_other_source_address(self):
        ticket = self.onboard()["ticket"]
        error = self.trust(ticket, caller=OTHER_IP)
        self.assertIsInstance(error, ops.TicketRefused)
        self.assertIn("不是从发它的那个地址来的", str(error))

    def test_changed_passphrase_voids_it(self):
        ticket = self.onboard()["ticket"]
        time.sleep(0.01)
        self.set_passphrase("another passphrase entirely")
        self.assertIn("口令改过", str(self.trust(ticket)))

    def test_locked_approval_ignores_tickets(self):
        ticket = self.onboard()["ticket"]
        ops._approval["locked_until"] = time.time() + 600
        error = self.trust(ticket)
        self.assertEqual((type(error), error.status), (ops.ApprovalRefused, 423))
        self.assertEqual(ops._approval["failures"], 0)
        ops._approval["locked_until"] = 0.0
        self.assertNotIsInstance(self.trust(ticket), Exception)             # 解锁后照样能用

    def test_changing_the_host_voids_it(self):
        ticket = self.onboard()["ticket"]
        self.ok(ops.page_host_save, {"host": {**WEB01, "port": 2222}, "original": "web01", "passphrase": PASS})
        self.assertIn("主机的设置变了", str(self.trust(ticket)))

    def test_deleting_the_host_drops_it(self):
        ticket = self.onboard()["ticket"]
        self.ok(ops.page_host_delete, {"name": "web01", "confirm_impact": [], "passphrase": PASS})
        self.assertNotIn("web01", ops._onboard)
        self.ok(ops.page_host_save, {"host": WEB01, "passphrase": PASS})
        self.assertIn("已经没有了", str(self.trust(ticket)))

    def test_only_for_its_own_host(self):
        ticket = self.onboard()["ticket"]
        self.ok(ops.page_host_save, {"host": {**WEB01, "name": "web02"}, "passphrase": PASS})
        error = self.do(ops.page_host_trust, {"name": "web02", "fingerprint": ops.key_fingerprint(HOST_BLOB),
                                              "confirm_impact": ["gw_disk"], "ticket": ticket})[0]
        self.assertIsInstance(error, ops.TicketRefused)
        # 不能拿来删主机：删除只认口令
        self.refused(ops.page_host_delete, {"name": "web01", "confirm_impact": [], "ticket": ticket}, 400)

    def test_page_config_off(self):
        ticket = self.onboard()["ticket"]
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            self.refused(ops.page_host_onboard, {"host": {**WEB01, "name": "web02"}, "passphrase": PASS}, 403)
            self.assertIsInstance(self.trust(ticket), ops.Forbidden)
            self.refused(ops.page_host_from, {"name": "web01", "address": "1.2.3.4", "ticket": ticket}, 403)

    def test_at_most_five_live_tickets(self):
        for index in range(7):
            self.ok(ops.page_host_onboard, {"host": {**WEB01, "name": f"h{index}"}, "passphrase": PASS})
        self.assertEqual(sorted(ops._onboard), ["h2", "h3", "h4", "h5", "h6"])


class OnboardRefusalTests(_Onboard):
    def test_checked_before_the_passphrase(self):
        for payload, status in (({"host": {**WEB01, "os": "darwin"}}, 400), ({"host": WEB01, "original": "web01"}, 400),
                                ({"host": "web01"}, 400), ({"host": {**WEB01, "name": "Bad Name"}}, 400)):
            with self.subTest(payload=payload):
                self.refused(ops.page_host_onboard, {**payload, "passphrase": PASS}, status)
        with patch.object(ops, "host_install_support", lambda: {"supported": False, "why": "OpenSSH 太旧"}):
            self.assertIn("分步", str(self.refused(ops.page_host_onboard, {"host": WEB01, "passphrase": PASS}, 400)))
        self.assertEqual(self.passphrase_checks(), 0)
        self.assertFalse(ops._page_file().exists())

    def test_wrong_passphrase_gives_no_ticket_and_saves_nothing(self):
        self.refused(ops.page_host_onboard, {"host": WEB01, "passphrase": WRONG}, 403)
        self.assertEqual(ops._onboard, {})
        self.assertEqual(ops._approval["failures"], 1)
        self.assertIsNone(ops._page_host_view("web01"))


class FromTests(_Onboard):
    def test_only_a_single_address_replaces_the_list(self):
        ticket = self.onboard(**{"from": ["117.72.91.19", "10.0.0.0/24"]})["ticket"]
        for bad in ("10.0.0.0/24", "gw.example.com", "", "1.2.3.4, 5.6.7.8"):
            with self.subTest(bad=bad):
                self.refused(ops.page_host_from, {"name": "web01", "address": bad, "ticket": ticket}, 400)
        result = self.ok(ops.page_host_from, {"name": "web01", "address": "203.0.113.7", "ticket": ticket})
        self.assertEqual(result["from"], ["203.0.113.7"])
        self.assertEqual(self.page_doc()["hosts"][0]["from"], ["203.0.113.7"])
        self.assertIn('from="203.0.113.7"', ops._page_host_view("web01")["install"]["authorized_keys"])
        change = ops._page_changes()[0]
        self.assertEqual(change["action"], "修改出口地址")
        self.assertIn("→ 203.0.113.7", change["detail"])
        # 改出口地址之后票据跟着条目走，照样能登记
        self.assertNotIsInstance(self.trust(ticket), Exception)
        self.assertEqual(self.passphrase_checks(), 1)

    def test_ipv6_is_a_single_address(self):
        ticket = self.onboard()["ticket"]
        self.ok(ops.page_host_from, {"name": "web01", "address": "2001:db8::7", "ticket": ticket})
        self.assertEqual(self.page_doc()["hosts"][0]["from"], ["2001:db8::7"])

    def test_with_the_passphrase(self):
        self.ok(ops.page_host_save, {"host": WEB01, "passphrase": PASS})
        self.refused(ops.page_host_from, {"name": "web01", "address": "203.0.113.7"}, 400)
        self.ok(ops.page_host_from, {"name": "web01", "address": "203.0.113.7", "passphrase": PASS})
        self.refused(ops.page_host_from, {"name": "nope", "address": "203.0.113.7", "passphrase": PASS}, 404)


@unittest.skipUnless(REAL_WHICH("sh"), "要 /bin/sh 跑出来看")
class SourceScriptTests(unittest.TestCase):
    """第 0 步核对来源地址的那段 shell：真的用 sh 跑一遍。"""

    def run_check(self, sources, src):
        mark = "@@doc2sop-0123456789abcdef"
        script = "\n".join(ops._source_check({"from": sources}, mark) + ["echo ALLOWED"]) + "\n"
        proc = subprocess.Popen([REAL_WHICH("sh"), "-c", script, "doc2sop", src], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out = proc.communicate(timeout=10)[0].decode()
        self.assertIn(f"{mark} source", out)
        return "ALLOWED" in out, out

    def test_cases(self):
        cases = [(["117.72.91.19"], "117.72.91.19", True), (["117.72.91.19"], "117.72.91.20", False),
                 (["10.0.0.0/8"], "10.200.3.4", True), (["10.0.0.0/8"], "11.0.0.1", False),
                 (["192.168.1.0/24", "117.72.91.19"], "117.72.91.19", True),
                 (["10.0.0.0/8"], "::ffff:10.2.3.4", True), (["117.72.91.19"], "", True),
                 (["2001:db8::1"], "2001:db8::1", True), (["2001:db8::1"], "2001:db8::2", False),
                 (["2001:db8::/64"], "2001:db8::99", True), (["117.72.91.19"], "2001:db8::1", False),
                 (["117.72.91.19"], "1.2.3.4;id", True), (["0.0.0.0/16"], "0.0.200.1", True)]
        for sources, src, allowed in cases:
            with self.subTest(sources=sources, src=src):
                got, out = self.run_check(sources, src)
                self.assertEqual(got, allowed, out)
                self.assertEqual("source-mismatch" in out, not allowed, out)

    def test_remote_commands_pass_the_source(self):
        self.assertIn('"${SSH_CONNECTION%% *}"', ops.INSTALL_ROOT_COMMAND)
        self.assertIn("c=${SSH_CONNECTION%% *}", ops.INSTALL_SUDO_COMMAND)
        self.assertIn('doc2sop "$c"; r=$?', ops.INSTALL_SUDO_COMMAND)


class MismatchRemote(FakeRemote):
    def __init__(self, case, source):
        super().__init__(case)
        self.source = source

    def __call__(self, argv, data, timeout, limit, env=None, started=None):
        self.argv, self.env, self.data = argv, env, data
        import types
        started(types.SimpleNamespace(pid=os.getpid()))
        from tests.test_host_install import spawn
        self.answers.append(spawn([env["SSH_ASKPASS"], "root@h's password: "], env)[1].decode())
        mark = re.search(r"@@doc2sop-[0-9a-f]{16}", data.decode()).group(0)
        return 0, f"{mark} source {self.source}\n{mark} source-mismatch\n".encode(), b""


@unittest.skipUnless(POSIX and hasattr(ops.socket, "SO_PEERCRED"), "askpass 用 Unix socket 和 SO_PEERCRED（Linux）")
class InstallWithTicketTests(_Onboard):
    def setUp(self):
        super().setUp()
        self.ticket = self.onboard()["ticket"]
        self.assertNotIsInstance(self.trust(self.ticket), Exception)
        patcher = patch.object(ops, "_page_check_checks", lambda host, done: [ops._check("host", "ok", "连主机", "连通")])
        patcher.start()
        self.addCleanup(patcher.stop)

    def install(self, remote, **extra):
        with patch.object(ops, "_communicate", remote):
            return self.do(ops.page_host_install, {"name": "web01", "login": "root", "password": SECRET,
                                                   "ticket": self.ticket, **extra})[0]

    def test_install_with_the_ticket(self):
        result = self.install(FakeRemote(self))
        self.assertTrue(result["install"]["ok"], result)
        self.assertEqual(self.passphrase_checks(), 1)
        self.assertIn("[approval] 用密码安装 web01：用添加流程的授权", self.printed.getvalue())

    def test_source_mismatch_stops_before_any_change_then_fix_and_retry(self):
        result = self.install(MismatchRemote(self, "203.0.113.7"))
        install = result["install"]
        self.assertFalse(install["ok"])
        self.assertEqual((install["category"], install["source"], install["source_mismatch"]), ("source", "203.0.113.7", True))
        self.assertIn("什么都没改", install["error"])
        self.assertIn("先别改", install["error"])
        self.assertTrue(all(step["status"] == "pending" for step in install["steps"] if step["key"].isdigit()))
        self.assertIsNone(result["check"])
        self.assertEqual(ops._install_denied, {})                            # 不算登录被拒
        self.ok(ops.page_host_from, {"name": "web01", "address": "203.0.113.7", "ticket": self.ticket})
        result = self.install(FakeRemote(self))
        self.assertTrue(result["install"]["ok"], result)
        self.assertEqual(self.passphrase_checks(), 1)
        self.assertNotIn(SECRET, self.everything_said())

    def test_wrong_ticket_never_starts_ssh(self):
        calls = []
        with patch.object(ops, "_communicate", lambda *a, **k: calls.append(a)):
            error = self.do(ops.page_host_install, {"name": "web01", "login": "root", "password": SECRET,
                                                    "ticket": "forged-ticket"})[0]
        self.assertIsInstance(error, ops.TicketRefused)
        self.assertEqual(calls, [])
        self.assertEqual(ops._install_times.get("web01", []), [])         # 没核对过的不计安装次数


class HttpOnboardTests(_Onboard):
    def setUp(self):
        super().setUp()
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        token = patch.object(ops.Handler, "token", "t0k")
        token.start()
        self.addCleanup(token.stop)

    def http(self, path, payload):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(self.url + path, json.dumps(payload).encode(),
                                         {"X-Ops-Token": "t0k", "Content-Type": "application/json",
                                          "X-Ops-Caller": "web user=admin ip=127.0.0.1"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_endpoints(self):
        status, body = self.http("/tools/config/host-onboard", {"host": WEB01, "passphrase": PASS})
        self.assertEqual(status, 200, body)
        ticket = body["ticket"]
        status, body = self.http("/tools/config/host-trust", {"name": "web01", "fingerprint": "SHA256:" + "A" * 43,
                                                              "confirm_impact": ["gw_disk"], "ticket": "forged"})
        self.assertEqual((status, body.get("ticket_refused")), (409, True))
        status, body = self.http("/tools/config/host-from", {"name": "web01", "address": "203.0.113.9", "ticket": ticket})
        self.assertEqual(status, 200, body)
        self.assertNotIn(ticket, self.printed.getvalue())


if __name__ == "__main__":
    unittest.main()
