"""用主机密码自动安装（工具服务这一层）。

密码只用一次：不在 ssh 的命令行和环境变量里、不进日志和回复；先核对登记的 host key（没登记不启动 ssh）；askpass 只回答
这一次起的 ssh、只回答要密码的提示、只回答一次；远端执行的就是页面上给人手工执行的那几行和安装包里 install.sh 的原文；
输出里盖住密码的各种写法；限频、登录被拒锁定、全局同时一个；要口令，OPS_PAGE_CONFIG=off 时 403；主配置的主机不能用。
真实的 sshd（root、sudo、NOPASSWD、密码错、host key 不对、半途失败）在 WSL 里另外实测，见 docs/工具.md。
"""
import json
import os
import re
import subprocess
import threading
import time
import types
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from tests.test_page_config import HOST_BLOB, HOSTS_CONFIG, OTHER_BLOB, PASS, POSIX, WEB01, WRONG, _Config, ops

SECRET = "Tgt-root pw'$(id)\"&x"     # 目标主机的登录密码：带空格、引号、$()，看各种转义写法都盖住
SUPPORTED = {"supported": True, "why": ""}


class _Install(_Config):
    CONFIG = HOSTS_CONFIG

    def setUp(self):
        super().setUp()
        self.set_passphrase()
        for patcher in (patch.dict(ops._install_times, clear=True), patch.dict(ops._install_denied, clear=True),
                        patch.object(ops, "host_install_support", lambda: dict(SUPPORTED))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ok(ops.page_host_save, {"host": WEB01, "passphrase": PASS})
        self.calls = []

    def trust(self):
        self.ok(ops.page_host_trust, {"name": "web01", "fingerprint": ops.key_fingerprint(HOST_BLOB),
                                      "confirm_impact": ["gw_disk"], "passphrase": PASS})

    def payload(self, **extra):
        return {"name": "web01", "login": "root", "password": SECRET, "passphrase": PASS, **extra}

    def no_ssh(self, argv, *args, **kwargs):
        self.calls.append(argv)
        raise AssertionError("不该启动 ssh")


class RefusalTests(_Install):
    """这些情况下 ssh 根本不启动、口令次数不消耗（口令错的那一条除外）。"""

    def test_refused_before_any_connection(self):
        with patch.object(ops, "_communicate", self.no_ssh):
            error = self.refused(ops.page_host_install, self.payload(), 409)        # host key 还没核对
            self.assertIn("host key", str(error))
            self.trust()
            self.refused(ops.page_host_install, self.payload(name="gateway-b"), 404)   # 主配置的主机
            self.refused(ops.page_host_install, self.payload(name="nope"), 404)
            self.refused(ops.page_host_install, self.payload(login="Root;rm"), 400)
            self.refused(ops.page_host_install, self.payload(password=""), 400)
            for bad in ("line1\nline2", "x" * 1025, "tab\there"):
                error = self.refused(ops.page_host_install, self.payload(password=bad), 400)
                self.assertNotIn(bad[:8], str(error))
            self.refused(ops.page_host_install, self.payload(passphrase=""), 400)
            self.assertEqual(ops._approval["failures"], 0)
            self.refused(ops.page_host_install, self.payload(passphrase=WRONG), 403)
            with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
                self.refused(ops.page_host_install, self.payload(), 403)
            with patch.object(ops, "host_install_support", lambda: {"supported": False, "why": "OpenSSH 太旧"}):
                self.assertIn("OpenSSH", str(self.refused(ops.page_host_install, self.payload(), 400)))
        self.assertEqual(self.calls, [])
        self.assertNotIn(SECRET, self.printed.getvalue())

    def test_only_linux_hosts(self):
        self.ok(ops.page_host_save, {"host": {**WEB01, "name": "mac01", "os": "darwin"}, "passphrase": PASS})
        dry = self.ok(ops.page_host_trust, {"name": "mac01", "dry_run": True})
        self.ok(ops.page_host_trust, {"name": "mac01", "fingerprint": ops.key_fingerprint(HOST_BLOB),
                                      "confirm_impact": [i["tool"] for i in dry["impact"]], "passphrase": PASS})
        with patch.object(ops, "_communicate", self.no_ssh):
            self.assertIn("Linux", str(self.refused(ops.page_host_install, self.payload(name="mac01"), 400)))

    def test_support_needs_posix_and_openssh_8_4(self):
        real = _real_support()
        if not POSIX:
            self.assertFalse(real()["supported"])
            return
        for text, ok in (("OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13", True), ("OpenSSH_8.4p1", True),
                         ("OpenSSH_8.2p1 Ubuntu", False), ("garbage", False)):
            with self.subTest(text=text), patch.dict(ops._install_openssh, clear=True), \
                    patch.object(ops.subprocess, "run",
                                 lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", (text + "\n").encode())):
                self.assertEqual(real()["supported"], ok)
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            self.assertIn("OPS_PAGE_CONFIG", real()["why"])


_ORIGINAL_SUPPORT = ops.host_install_support


def _real_support():
    return _ORIGINAL_SUPPORT


def spawn(argv, env=None):
    """起子进程（subprocess.run 在这些用例里被假的 ssh-keygen 顶替了，这里直接用 Popen）：(退出码, stdout)。"""
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate(timeout=20)
    return proc.returncode, out


class FakeRemote:
    """假的 ssh：记下命令行、环境、stdin；像 ssh 一样启动 askpass（父进程就是「ssh」= 测试进程自己），再按脚本里的标记回输出。"""

    def __init__(self, case, prompts=("root@10.0.1.11's password: ",), code=0, account="absent", fail_at=None,
                 err=b"", echo=""):
        self.case, self.prompts, self.code, self.account, self.fail_at = case, prompts, code, account, fail_at
        self.err, self.echo = err, echo
        self.argv = self.env = self.data = None
        self.answers = []
        self.askpass_dir = None

    def __call__(self, argv, data, timeout, limit, env=None, started=None):
        self.argv, self.env, self.data = argv, env, data
        started(types.SimpleNamespace(pid=os.getpid()))
        self.askpass_dir = os.path.dirname(env["SSH_ASKPASS"])
        for prompt in self.prompts:
            code, out = spawn([env["SSH_ASKPASS"], prompt], env)
            self.answers.append(out.decode() if code == 0 else None)
        if self.code:
            return self.code, b"", self.err
        text = data.decode("utf-8")
        mark = re.search(r"@@doc2sop-[0-9a-f]{16}", text).group(0)
        out = [f"{mark} account {self.account}"]
        if self.account == "foreign":
            return 0, ("\n".join(out) + "\n").encode(), b""
        steps = sorted({int(n) for n in re.findall(re.escape(mark) + r" begin (\d+)", text)})
        for index in steps:
            if self.account == "ours" and index < steps[-1]:
                continue
            out += [f"{mark} begin {index}", f"output of step {index} {self.echo}"]
            if index == self.fail_at:
                out.append(f"{mark} end {index} 1")
                return 0, ("\n".join(out) + "\n").encode(), b""
            out.append(f"{mark} end {index} 0")
        out.append(f"{mark} done")
        return 0, ("\n".join(out) + "\n").encode(), b""


@unittest.skipUnless(POSIX and hasattr(ops.socket, "SO_PEERCRED"), "askpass 用 Unix socket 和 SO_PEERCRED（Linux）")
class InstallTests(_Install):
    def setUp(self):
        super().setUp()
        self.trust()
        self.checked = []
        patcher = patch.object(ops, "_page_check_checks",
                               lambda host, done: self.checked.append(host["name"]) or [ops._check("host", "ok", "连主机", "连通")])
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_install(self, remote, **extra):
        with patch.object(ops, "_communicate", remote):
            return self.ok(ops.page_host_install, self.payload(**extra))

    def assertNoPassword(self, *texts):
        said = self.everything_said() + "\n".join(str(text) for text in texts)
        for form in ops._password_forms(SECRET):
            self.assertNotIn(form, said)

    def test_root_install_runs_exactly_the_page_commands(self):
        remote = FakeRemote(self, echo=SECRET)
        result = self.run_install(remote)
        install = result["install"]
        self.assertTrue(install["ok"], install)
        self.assertTrue(install["password_sent"])
        self.assertEqual(remote.answers, [SECRET + "\n"])
        # 密码不在 ssh 的命令行、环境里；askpass 的目录用完删掉
        self.assertNotIn(SECRET, json.dumps(remote.argv))
        self.assertNotIn(SECRET, json.dumps(remote.env))
        self.assertEqual(remote.env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertFalse(os.path.exists(remote.askpass_dir))
        options = [part for part in remote.argv if "=" in part]
        for option in ("StrictHostKeyChecking=yes", f"UserKnownHostsFile={ops._page_known_hosts()}",
                       "GlobalKnownHostsFile=" + os.devnull, "HostKeyAlias=web01", "PubkeyAuthentication=no",
                       "NumberOfPasswordPrompts=1", "ProxyCommand=none", "UpdateHostKeys=no", "BatchMode=no"):
            self.assertIn(option, options)
        self.assertEqual(remote.argv[-5:], ["-l", "root", "--", "10.0.1.11", ops.INSTALL_ROOT_COMMAND])
        # 执行的就是页面上那几行（逐行原文）和安装包里 install.sh 的原文；root 时 stdin 里没有密码
        script = remote.data.decode("utf-8")
        self.assertNotIn(SECRET, script)
        item = ops._page_host_view("web01")
        for line in item["install"]["account"]:
            self.assertIn("\n" + line + "\n", script)
        import tarfile
        with tarfile.open(ops._page_bundle_path("web01"), "r:gz") as archive:
            installer = archive.extractfile("web01/install.sh").read().decode()
        self.assertIn("i='" + installer.replace("'", "'\\''") + "'", script)
        self.assertEqual(result["install"]["steps"][-1]["command"].split("（")[0], "sh web01/install.sh")
        # 输出里的密码盖住了
        outputs = [step.get("output", "") for step in install["steps"]]
        self.assertTrue(any("output of step" in text for text in outputs))
        self.assertTrue(all(SECRET not in text for text in outputs))
        self.assertEqual(self.checked, ["web01"])
        self.assertEqual(result["check"]["verdict"], "ok")
        change = ops._page_changes()[0]
        self.assertEqual((change["action"], change["target"]), ("用密码安装", "web01"))
        self.assertIn("root@10.0.1.11:22（root）", change["detail"])
        self.assertIn("成功", change["detail"])
        self.assertIn("密码已丢弃", change["detail"])
        self.assertIn("ip=10.1.2.3", change["caller"])
        self.assertIn("[page-config] 用密码安装 web01", self.printed.getvalue())
        self.assertNoPassword(json.dumps(result, ensure_ascii=False))

    def test_sudo_sends_the_password_as_the_first_stdin_line_only(self):
        remote = FakeRemote(self, prompts=("(ops1@10.0.1.11) Password: ",))
        result = self.run_install(remote, login="ops1")
        self.assertTrue(result["install"]["ok"])
        self.assertTrue(result["install"]["sudo"])
        self.assertEqual(remote.argv[-1], ops.INSTALL_SUDO_COMMAND)
        first, rest = remote.data.split(b"\n", 1)
        self.assertEqual(first.decode(), SECRET)
        self.assertNotIn(SECRET.encode(), rest)
        self.assertNotIn(SECRET, ops.INSTALL_SUDO_COMMAND)
        self.assertIn("sudo -k", ops.INSTALL_SUDO_COMMAND)
        self.assertNoPassword(json.dumps(result, ensure_ascii=False))

    def test_askpass_answers_once_and_only_password_prompts(self):
        remote = FakeRemote(self, prompts=("Verification code: ", "root@h's password: ", "root@h's password: "))
        self.run_install(remote)
        self.assertEqual(remote.answers, [None, SECRET + "\n", None])

    def test_askpass_refuses_other_processes(self):
        asked = ops._Askpass(SECRET)
        try:
            asked.started(types.SimpleNamespace(pid=999999999))   # 「ssh」不是测试进程：askpass 的父进程对不上
            code, out = spawn([asked.script, "root@h's password: "])
            self.assertNotEqual(code, 0)
            self.assertEqual(out, b"")
            self.assertEqual(asked.refused, "peer")
            self.assertFalse(asked.answered)
            mode = os.stat(asked.folder).st_mode & 0o777
            self.assertEqual(mode, 0o700)
            self.assertNotIn(SECRET, Path(asked.script).read_text(encoding="utf-8"))
        finally:
            asked.close()
        self.assertFalse(os.path.exists(asked.folder))

    def test_host_key_mismatch_never_sends_the_password(self):
        remote = FakeRemote(self, prompts=(), code=255,
                            err=b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n")
        result = self.run_install(remote)
        install = result["install"]
        self.assertFalse(install["ok"])
        self.assertEqual(install["category"], "hostkey")
        self.assertFalse(install["password_sent"])
        self.assertEqual(install["steps"][0]["status"], "fail")
        self.assertIn("密码没有发出去", install["error"])
        self.assertIsNone(result["check"])
        self.assertIn("失败于", ops._page_changes()[0]["detail"])

    def test_wrong_passwords_lock_the_host_after_two_denials(self):
        denied = lambda: FakeRemote(self, code=255, err=b"root@10.0.1.11: Permission denied (publickey,password).\n")  # noqa: E731
        for _ in range(2):
            install = self.run_install(denied())["install"]
            self.assertEqual(install["category"], "denied")
            self.assertTrue(install["password_sent"])
            self.assertEqual([s["status"] for s in install["steps"][:2]], ["ok", "fail"])
        failures = ops._approval["failures"]
        with patch.object(ops, "_communicate", self.no_ssh):
            error = self.refused(ops.page_host_install, self.payload(), 429)
        self.assertIn("连续被拒 2 次", str(error))
        self.assertEqual(ops._approval["failures"], failures)        # 锁定时不核对口令、不消耗次数
        self.assertEqual(self.calls, [])

    def test_password_only_servers_and_otp_are_unsupported(self):
        remote = FakeRemote(self, prompts=(), code=255, err=b"root@h: Permission denied (publickey).\n")
        install = self.run_install(remote)["install"]
        self.assertEqual((install["category"], install["password_sent"]), ("unsupported", False))
        remote = FakeRemote(self, prompts=("Verification code: ",), code=255, err=b"Permission denied (keyboard-interactive).\n")
        install = self.run_install(remote)["install"]
        self.assertEqual((install["category"], install["password_sent"]), ("unsupported", False))

    def test_sudo_failures_are_explained(self):
        for code, category in ((95, "sudo-denied"), (94, "sudo-nocache")):
            with self.subTest(code=code):
                ops._install_times.clear()
                remote = FakeRemote(self, prompts=("ops1@h's password: ",), code=code,
                                    err=f"Sorry, try again.\n{SECRET}\nsudo: 1 incorrect password attempt\n".encode())
                install = self.run_install(remote, login="ops1")["install"]
                self.assertEqual(install["category"], category)
                self.assertEqual(next(s for s in install["steps"] if s["key"] == "sudo")["status"], "fail")
                self.assertNotIn(SECRET, json.dumps(install, ensure_ascii=False))

    def test_half_way_failure_and_retry_recognises_its_own_account(self):
        steps = len(ops._page_host_view("web01")["install"]["account"]) + 1
        install = self.run_install(FakeRemote(self, fail_at=steps))["install"]
        self.assertEqual(install["category"], "step")
        self.assertEqual(install["steps"][-1]["status"], "fail")
        self.assertIn("重试", install["error"])
        self.assertEqual(self.checked, [])
        install = self.run_install(FakeRemote(self, account="ours"))["install"]
        self.assertTrue(install["ok"])
        self.assertEqual([s["status"] for s in install["steps"] if s["key"].isdigit()],
                         ["skip"] * (steps - 1) + ["ok"])

    def test_a_foreign_account_is_left_alone(self):
        install = self.run_install(FakeRemote(self, account="foreign"))["install"]
        self.assertEqual(install["category"], "account-exists")
        self.assertTrue(all(s["status"] == "pending" for s in install["steps"] if s["key"].isdigit()))

    def test_the_remote_check_compares_the_whole_authorized_keys_line(self):
        remote = FakeRemote(self)
        self.run_install(remote)
        script = remote.data.decode()
        line = ops._page_host_view("web01")["install"]["authorized_keys"]
        self.assertIn(f"[ \"$(cat \"$f\")\" = '{line}' ]", script)
        self.assertIn("exec 2>&1", script)

    def test_limits(self):
        for _ in range(3):
            self.run_install(FakeRemote(self))
        with patch.object(ops, "_communicate", self.no_ssh):
            self.assertIn("10 分钟内", str(self.refused(ops.page_host_install, self.payload(), 429)))
        ops._install_times.clear()
        self.assertTrue(ops._install_running.acquire(blocking=False))
        try:
            with patch.object(ops, "_communicate", self.no_ssh):
                self.assertIn("另一台主机", str(self.refused(ops.page_host_install, self.payload(), 429)))
        finally:
            ops._install_running.release()

    def test_timeouts_are_reported(self):
        def slow(argv, data, timeout, limit, env=None, started=None):
            self.assertEqual(timeout, ops.INSTALL_TIMEOUT)
            raise ops.HostError("执行超时")

        with patch.object(ops, "_communicate", slow):
            install = self.ok(ops.page_host_install, self.payload())["install"]
        self.assertEqual(install["category"], "timeout")


class ShownTests(unittest.TestCase):
    def test_password_forms_are_masked(self):
        forms = [SECRET, urllib.parse.quote(SECRET, safe=""), urllib.parse.quote_plus(SECRET),
                 SECRET.replace("'", "'\\''"), json.dumps(SECRET)[1:-1], re.sub(r"([^A-Za-z0-9_])", r"\\\1", SECRET)]
        for form in forms:
            with self.subTest(form=form):
                shown, hidden = ops._install_shown(f"before {form} after", SECRET)
                self.assertFalse(hidden)
                self.assertNotIn(SECRET, shown)
                self.assertNotIn(form, shown)
                self.assertIn("before", shown)

    def test_unmaskable_output_is_hidden(self):
        self.assertEqual(ops._install_shown("pw is abc12", "abc12"), ("", True))      # 太短：替换不可靠
        self.assertEqual(ops._install_shown(f"x {SECRET.upper()} y", SECRET), ("", True))  # 换了大小写还认得出
        shown, hidden = ops._install_shown("y" * 5000, SECRET)
        self.assertFalse(hidden)
        self.assertLess(len(shown), 2100)
        self.assertEqual(ops._install_shown("", SECRET), ("", False))


class HttpInstallTests(_Install):
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

    def http(self, path, payload=None, token="t0k"):
        import urllib.error
        import urllib.request
        request = urllib.request.Request(self.url + path, json.dumps(payload).encode() if payload is not None else None,
                                         {"X-Ops-Token": token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_endpoints(self):
        self.assertEqual(self.http("/tools/config/host-install", token="bad")[0], 401)
        status, body = self.http("/tools/config/host-install")
        self.assertEqual((status, json.loads(body)), (200, SUPPORTED))
        status, body = self.http("/tools/config/host-install", self.payload(), token="bad")
        self.assertEqual(status, 401)
        with patch.object(ops, "_communicate", self.no_ssh):
            status, body = self.http("/tools/config/host-install", self.payload())
        self.assertEqual(status, 409)                      # 还没核对 host key
        self.assertNotIn(SECRET, body)
        self.assertNotIn(SECRET, self.printed.getvalue())


if __name__ == "__main__":
    unittest.main()
