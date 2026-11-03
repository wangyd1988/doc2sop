"""HTTPS 与来源地址：app/peer.py（可信代理、经没登记的代理转来的请求）、app/serve.py（内置 TLS、本机明文口、预检）、
deploy/make-tls-certs.sh（私有 CA + 名字约束）、release.sh 的探活与预检。

真起 HTTPS 的用例要 bash 和 openssl（Linux、macOS、Git for Windows 都有），没有就跳过。
"""
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tests.support  # noqa: F401
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app import approval, automation_config, mcp_server, peer, serve
from app import main as app_main

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "make-tls-certs.sh"
RELEASE = (REPO / "deploy" / "release.sh").read_text(encoding="utf-8")
TRUST_LOCAL = peer.parse_trusted("127.0.0.1,::1")


def scope(client=("203.0.113.9", 50000), host="kb.example.com", headers=(), kind="http"):
    raw = ([(b"host", host.encode())] if host is not None else []) + \
          [(k.lower().encode(), v.encode()) for k, v in headers]
    return {"type": kind, "client": client, "headers": raw, "scheme": "http"}


def resolved(networks=(), **kwargs):
    s = scope(**kwargs)
    peer.resolve(s, networks)
    return s


class HostNameTests(unittest.TestCase):
    def test_host_names_ignore_ports_brackets_and_case(self):
        for value, name in (("127.0.0.1:8765", "127.0.0.1"), ("LOCALHOST:8765", "localhost"), ("[::1]:8765", "::1"),
                            ("[::1]", "::1"), ("::1", "::1"), ("Kb.Example.com", "kb.example.com"), ("", "")):
            with self.subTest(value=value):
                self.assertEqual(peer.host_name(value), name)

    def test_local_hosts(self):
        for value in ("127.0.0.1:8765", "localhost:8765", "LocalHost", "[::1]:8765", "127.0.0.2", "app.localhost:1",
                      "[::ffff:127.0.0.1]:8765"):
            with self.subTest(value=value):
                self.assertTrue(peer.local_host(value))
        for value in ("kb.example.com", "117.72.91.19:8765", "", "[::2]:8765", "localhost.evil.com", "10.0.0.1"):
            with self.subTest(value=value):
                self.assertFalse(peer.local_host(value))


class TrustedProxiesTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(peer.parse_trusted(""), ())
        self.assertEqual([str(n) for n in peer.parse_trusted(" 127.0.0.1, ::1 ,10.0.0.0/8")],
                         ["127.0.0.1/32", "::1/128", "10.0.0.0/8"])
        for bad in ("*", "0.0.0.0/0", "::/0", "localhost", "10.0.0.0/33", "127.0.0.1,*"):
            with self.subTest(bad=bad), self.assertRaises(peer.ConfigError):
                peer.parse_trusted(bad)


class ResolveTests(unittest.TestCase):
    """默认不信任任何代理：直连的照旧；回环对端带转发头、或 Host 不是本机的，记成 UNTRUSTED。"""

    def setUp(self):
        peer.reset_events()

    def client(self, s):
        return s["client"][0]

    def test_tunnel_probe_and_local_curl_stay_local(self):
        """经 SSH 隧道（localhost / 127.0.0.1 / [::1] 加端口）、release.sh 探活、基线里的本机 curl：都还是本机。"""
        for client, host in ((("127.0.0.1", 1), "127.0.0.1:8765"), (("127.0.0.1", 1), "localhost:8765"),
                             (("127.0.0.1", 1), "LOCALHOST:8765"), (("::1", 1), "[::1]:8765"),
                             (("127.0.0.1", 1), "127.0.0.1"), (("::ffff:127.0.0.1", 1), "127.0.0.1:8765")):
            with self.subTest(client=client, host=host):
                s = resolved(client=client, host=host)
                self.assertEqual(s["client"], client)
                self.assertTrue(peer.is_loopback(self.client(s)))
                for networks in ((), TRUST_LOCAL):          # 登记了本机的代理以后，隧道照样能用
                    self.assertEqual(resolved(networks, client=client, host=host)["client"], client)
        self.assertEqual(peer.events(), {})

    def test_loopback_with_forwarding_headers_or_a_foreign_host_is_untrusted(self):
        cases = ((("X-Forwarded-For", "203.0.113.9"),), (("X-Forwarded-Proto", "https"),), (("X-Real-IP", "1.2.3.4"),),
                 (("Forwarded", "for=1.2.3.4"),), (("X-Forwarded-Host", "kb.example.com"),))
        for headers in cases:
            with self.subTest(headers=headers):
                s = resolved(client=("127.0.0.1", 5), host="127.0.0.1:8765", headers=headers)
                self.assertEqual(s["client"], (peer.UNTRUSTED, 5))
                self.assertEqual(s[peer.PEER_KEY], "127.0.0.1")
                self.assertEqual(s["scheme"], "http")                    # 没登记的代理说的协议不算数
        for host in ("kb.example.com", "117.72.91.19:8765", "[2001:db8::1]:443", None):
            with self.subTest(host=host):
                self.assertEqual(self.client(resolved(client=("::1", 5), host=host)), peer.UNTRUSTED)
        event = peer.events()["untrusted"]
        self.assertEqual((event["peer"], event["count"]), ("::1", len(cases) + 4))
        self.assertIn("Host 不是本机地址", event["why"])

    def test_public_peers_cannot_pretend_to_be_local(self):
        for networks in ((), TRUST_LOCAL):
            s = resolved(networks, client=("203.0.113.9", 1), host="127.0.0.1:8765",
                         headers=(("X-Forwarded-For", "127.0.0.1"), ("X-Forwarded-Proto", "https")))
            self.assertEqual(s["client"], ("203.0.113.9", 1))
            self.assertEqual(s["scheme"], "http")
        self.assertNotIn("untrusted", peer.events())

    def test_private_peers_with_forwarding_headers_only_get_a_hint(self):
        s = resolved(client=("10.0.0.9", 1), headers=(("X-Forwarded-For", "203.0.113.9"),))
        self.assertEqual(s["client"], ("10.0.0.9", 1))
        self.assertEqual(peer.events()["private"]["peer"], "10.0.0.9")
        resolved(client=("1.1.1.1", 1), headers=(("X-Forwarded-For", "10.1.1.1"),))   # 公司正向代理：不提示
        self.assertEqual(peer.events()["private"]["count"], 1)

    def test_trusted_proxies(self):
        trusted = peer.parse_trusted("127.0.0.1,::1,10.0.0.0/8")
        for chain, client in (("203.0.113.9", "203.0.113.9"),
                              ("127.0.0.1, 203.0.113.9", "203.0.113.9"),       # 客户端伪造的左边一段不算数
                              ("203.0.113.9, 10.0.0.2", "203.0.113.9"),        # 两层代理
                              ("203.0.113.9:5555", "203.0.113.9"), ("[2001:db8::1]:443", "2001:db8::1"),
                              ('"[2001:db8::1]"', "2001:db8::1"), ("::ffff:198.51.100.1", "198.51.100.1"),
                              ("10.0.0.3", "10.0.0.3")):                       # 全是代理：最左边那个发起
            with self.subTest(chain=chain):
                s = resolved(trusted, client=("127.0.0.1", 9), headers=(("X-Forwarded-For", chain),))
                self.assertEqual(s["client"], (client, 0))
                self.assertEqual(s[peer.VIA_KEY], "127.0.0.1")
        both = resolved(trusted, client=("127.0.0.1", 9),
                        headers=(("X-Forwarded-For", "198.51.100.1"), ("X-Forwarded-For", "203.0.113.9")))
        self.assertEqual(both["client"][0], "203.0.113.9")                        # 两行 X-Forwarded-For 连起来看
        for chain in ("unknown", "203.0.113.9, garbage", ""):
            with self.subTest(chain=chain):
                s = resolved(trusted, client=("127.0.0.1", 9), host="127.0.0.1:8765",
                             headers=(("X-Forwarded-For", chain),))
                self.assertEqual(s["client"][0], peer.UNTRUSTED)

    def test_trusted_proxy_protocol(self):
        for protos, scheme in ((("https",), "https"), (("http",), "http"), (("https, http",), "http"),
                               (("http, https",), "https"), (("ftp",), "http"), ((), "http")):
            with self.subTest(protos=protos):
                headers = [("X-Forwarded-For", "203.0.113.9")] + [("X-Forwarded-Proto", p) for p in protos]
                self.assertEqual(resolved(TRUST_LOCAL, client=("127.0.0.1", 9), headers=headers)["scheme"], scheme)
        ws = resolved(TRUST_LOCAL, client=("127.0.0.1", 9), kind="websocket",
                      headers=(("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Proto", "https")))
        self.assertEqual(ws["scheme"], "wss")

    def test_a_trusted_proxy_must_send_x_forwarded_for(self):
        for headers in ((("X-Real-IP", "203.0.113.9"),), (("Forwarded", "for=203.0.113.9"),),
                        (("X-Forwarded-Proto", "https"),)):
            with self.subTest(headers=headers):
                s = resolved(TRUST_LOCAL, client=("127.0.0.1", 9), host="kb.example.com", headers=headers)
                self.assertEqual(s["client"][0], peer.UNTRUSTED)
        self.assertIn("没带 X-Forwarded-For", peer.events()["untrusted"]["why"])
        # 代理忘了传 X-Forwarded-For、也没有别的转发头：Host 不是本机，一样认出来
        self.assertEqual(resolved(TRUST_LOCAL, client=("127.0.0.1", 9), host="kb.example.com")["client"][0],
                         peer.UNTRUSTED)

    def test_odd_peers(self):
        for client in (("testclient", 50000), None, ("", 0)):
            with self.subTest(client=client):
                s = resolved(client=client, headers=(("X-Forwarded-For", "127.0.0.1"),))
                self.assertEqual(s["client"], client)

    def test_logs_are_rate_limited(self):
        with self.assertLogs("kb", "WARNING") as logged:
            for _ in range(5):
                resolved(client=("127.0.0.1", 1), host="kb.example.com")
        self.assertEqual(len(logged.output), 1)
        self.assertEqual(peer.events()["untrusted"]["count"], 5)


def probe_app():
    async def where(request):
        return JSONResponse({"address": peer.address(request), "local": peer.is_local(request),
                             "caller": approval.caller(request), "transport": peer.transport(request)})
    return Starlette(routes=[Route("/where", where)])


class EverywhereTests(unittest.TestCase):
    """记成 UNTRUSTED 以后，每个按来源做判断、记录的地方都不报错，也都不放行。"""

    def get(self, client, base="http://127.0.0.1:8765", headers=None, networks=()):
        app = peer.ClientAddress(probe_app(), networks=networks)
        with TestClient(app, client=client, base_url=base) as http:
            return http.get("/where", headers=headers or {}).json()

    def test_through_the_middleware(self):
        with self.assertLogs("kb", "WARNING"):
            got = self.get(("127.0.0.1", 1), headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual((got["address"], got["local"]), (peer.UNTRUSTED, False))
        self.assertEqual(got["caller"], f"web user={app_main.WEB_USER} ip={peer.UNTRUSTED}")
        self.assertTrue(got["transport"]["untrusted"])
        tunnel = self.get(("127.0.0.1", 1))
        self.assertEqual((tunnel["address"], tunnel["local"], tunnel["transport"]["https"]), ("127.0.0.1", True, False))
        proxied = self.get(("127.0.0.1", 1), "http://kb.example.com", networks=TRUST_LOCAL,
                           headers={"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
        self.assertEqual((proxied["address"], proxied["local"]), ("203.0.113.9", False))
        self.assertEqual((proxied["transport"]["https"], proxied["transport"]["via"], proxied["transport"]["peer"]),
                         (True, "127.0.0.1", "127.0.0.1"))

    def test_lists_and_records(self):
        with patch.object(mcp_server, "MCP_CLIENTS", ["127.0.0.1", "::1", "0.0.0.0/1", "128.0.0.0/1"]):
            mcp_server._client_networks.cache_clear()
            self.assertFalse(mcp_server.client_allowed(peer.UNTRUSTED))
            self.assertTrue(mcp_server.exposed())
            self.assertIn("只接受来自", mcp_server.reachability(peer.UNTRUSTED, "127.0.0.1:8765")["reasons"][0])
        with patch.object(mcp_server, "MCP_CLIENTS", ["127.0.0.1", "::1"]):
            self.assertFalse(mcp_server.exposed())
        with patch.object(mcp_server, "MCP_CLIENTS", []):
            self.assertTrue(mcp_server.exposed())
        mcp_server._client_networks.cache_clear()
        settings = SimpleNamespace(alert_clients=["127.0.0.1", "10.0.0.0/8"],
                                   alert_networks=peer.parse_trusted("127.0.0.1,10.0.0.0/8"))
        self.assertFalse(automation_config.client_allowed(settings, peer.UNTRUSTED))
        self.assertTrue(automation_config.client_allowed(settings, "10.1.1.1"))
        # 工具服务从 caller 里取来源地址（页面上「来自 …」）：这个标记照样取得出来
        sys.path.insert(0, str(REPO / "deploy"))
        try:
            import ops_readonly
        finally:
            sys.path.remove(str(REPO / "deploy"))
        self.assertEqual(ops_readonly._caller_source(f"web user=admin ip={peer.UNTRUSTED}"), peer.UNTRUSTED)
        # 限频的键就是这个字符串：所有经没登记的代理转来的请求共用一份名额
        self.assertEqual(app_main._draft_wait(peer.UNTRUSTED), 0)

    def test_main_app_runs_the_middleware_outermost(self):
        self.assertIs(app_main.app.user_middleware[0].cls, peer.ClientAddress)
        self.assertIs(app_main.app.user_middleware[1].cls, app_main.SameOriginOnly)


# --- serve ---------------------------------------------------------------------------------------

class ServeSettingsTests(unittest.TestCase):
    def test_defaults_are_the_old_command(self):
        config = serve.settings({})
        self.assertEqual(config, {"port": 8765, "host": "0.0.0.0", "cert": "", "key": "", "local_port": None,
                                  "problems": []})
        self.assertEqual(serve.settings({"PORT": "9000"})["port"], 9000)
        built = serve._uvicorn_config(config)
        self.assertEqual((built.host, built.port, built.workers, built.proxy_headers, built.ssl),
                         ("0.0.0.0", 8765, 1, False, None))
        self.assertEqual(serve.describe(config), ["http://0.0.0.0:8765"])
        self.assertEqual(serve.tls_status({}), {"builtin": False, "local_port": None})

    def test_refusals(self):
        for env, needle in (({"LISTEN_HOST": "10.0.0.5"}, "LISTEN_HOST"), ({"PORT": "x"}, "PORT"),
                            ({"PORT": "70000"}, "PORT"), ({"TLS_CERT_FILE": "/tls/a"}, "一起填"),
                            ({"TLS_KEY_FILE": "/tls/a"}, "一起填"), ({"LOCAL_HTTP_PORT": "8766"}, "只在开了 TLS 时用"),
                            ({"TLS_CERT_FILE": "a", "TLS_KEY_FILE": "b", "LOCAL_HTTP_PORT": "8765"}, "不能和 PORT 相同"),
                            ({"TLS_CERT_FILE": "a", "TLS_KEY_FILE": "b", "LOCAL_HTTP_PORT": "0"}, "LOCAL_HTTP_PORT"),
                            ({"FORWARDED_ALLOW_IPS": "*"}, "TRUSTED_PROXIES"),
                            ({"FORWARDED_ALLOW_IPS": "127.0.0.1"}, "FORWARDED_ALLOW_IPS")):
            with self.subTest(env=env):
                problems = serve.settings(env)["problems"]
                self.assertTrue(any(needle in p for p in problems), problems)
        self.assertEqual(serve.settings({"LISTEN_HOST": "127.0.0.1"})["problems"], [])

    def test_expiry_warnings(self):
        now = 2_000_000_000
        day = 86400
        self.assertEqual(serve.expiry_warning({"not_before": now - day, "not_after": now + 90 * day}, now), "")
        self.assertIn("29 天后过期", serve.expiry_warning({"not_before": now - day, "not_after": now + 29.5 * day}, now))
        self.assertIn("已经过期", serve.expiry_warning({"not_before": now - 9 * day, "not_after": now - day}, now))
        self.assertIn("还没生效", serve.expiry_warning({"not_before": now + day, "not_after": now + 9 * day}, now))


def find_bash():
    found = shutil.which("bash")
    if found and "System32" not in found:
        return found
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\bin\bash.exe")):
        if Path(candidate).is_file():
            return candidate
    return None


BASH = find_bash()


def bash_path(path):
    return str(path).replace("\\", "/")


def script_env():
    """脚本要 python3 核对 IP 写法：Git for Windows 的 bash 里不一定有，把跑测试的这个解释器放到 PATH 前面。"""
    return {**os.environ, "PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")}


def make_certs(base, *args):
    done = subprocess.run([BASH, bash_path(SCRIPT), "--ca-dir", bash_path(base / "ca"), "--out", bash_path(base / "tls"),
                           *args], capture_output=True, text=True, encoding="utf-8", env=script_env())
    return done


def has_openssl():
    if not BASH:
        return False
    return subprocess.run([BASH, "-c", "command -v openssl"], capture_output=True).returncode == 0


OPENSSL = has_openssl()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(OPENSSL, "没有 bash + openssl")
class CertScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.done = make_certs(cls.base, "--ip", "192.0.2.10", "--dns", "kb.internal")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_ca_and_server_certificate(self):
        self.assertEqual(self.done.returncode, 0, self.done.stderr)
        for name in ("ca/ca.key", "ca/ca.crt", "tls/server.key", "tls/server.crt"):
            self.assertTrue((self.base / name).is_file(), name)
        self.assertFalse((self.base / "tls" / "ca.key").exists())
        if os.name == "posix":
            self.assertEqual(os.stat(self.base / "ca" / "ca.key").st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(self.base / "tls" / "server.key").st_mode & 0o777, 0o600)
        info = serve.decode_cert(self.base / "tls" / "server.crt")
        self.assertEqual(sorted(info["names"]), sorted(["192.0.2.10", "127.0.0.1", "0:0:0:0:0:0:0:1", "localhost",
                                                         "kb.internal"]))
        self.assertLess(info["not_after"] - time.time(), 826 * 86400)
        self.assertIn("不要放进 TLS_DIR", self.done.stdout)
        self.assertIn("TLS_CERT_FILE=/tls/server.crt", self.done.stdout)
        self.assertEqual(serve.check_tls(str(self.base / "tls" / "server.crt"), str(self.base / "tls" / "server.key"))[0], [])

    def test_python_trusts_only_the_names_on_the_certificate(self):
        """Python（OpenSSL）认这个 CA：证书上的名字能连；CA 签出名字约束以外的证书，客户端拒绝。"""
        ca = str(self.base / "ca" / "ca.crt")
        good = (str(self.base / "tls" / "server.crt"), str(self.base / "tls" / "server.key"))
        self.assertTrue(handshake(good, ca, "127.0.0.1"))
        self.assertTrue(handshake(good, ca, "kb.internal"))
        self.assertTrue(handshake(good, ca, "localhost"))
        self.assertFalse(handshake(good, ca, "example.com"))                # 证书上没有这个名字
        self.assertFalse(handshake(good, None, "127.0.0.1"))                # 没导入 CA
        rogue = rogue_cert(self.base, "DNS:example.com")                   # 用同一个 CA 硬签一张约束以外的
        self.assertFalse(handshake(rogue, ca, "example.com"))
        rogue_ip = rogue_cert(self.base, "IP:203.0.113.5")
        self.assertFalse(handshake(rogue_ip, ca, "203.0.113.5"))

    def test_renewing_keeps_the_ca_and_new_names_need_a_new_ca(self):
        before = (self.base / "ca" / "ca.crt").read_bytes()
        again = make_certs(self.base, "--ip", "192.0.2.10")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("用已有的 CA", again.stdout)
        self.assertEqual((self.base / "ca" / "ca.crt").read_bytes(), before)
        wider = make_certs(self.base, "--ip", "198.51.100.1")
        self.assertEqual(wider.returncode, 2, wider.stdout + wider.stderr)
        self.assertIn("换一个 CA", wider.stderr)
        self.assertEqual(serve.check_tls(str(self.base / "tls" / "server.crt"), str(self.base / "tls" / "server.key"))[0],
                         [], "过不了校验时不能把旧的服务器证书换掉")

    def test_bad_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            for args, needle in ((("--ip", "not-an-ip"), "不是可用的 IP"), (("--ip", "0.0.0.0"), "不是可用的 IP"),
                                 (("--dns", "bad name"), "主机名"), (("--ip", "192.0.2.1", "--days", "3650"), "825"),
                                 ((), "至少给一个")):
                with self.subTest(args=args):
                    done = make_certs(Path(tmp), *args)
                    self.assertEqual(done.returncode, 2)
                    self.assertIn(needle, done.stderr)
            same = subprocess.run([BASH, bash_path(SCRIPT), "--ca-dir", bash_path(Path(tmp) / "tls" / "ca"), "--out",
                                   bash_path(Path(tmp) / "tls"), "--ip", "192.0.2.1"], capture_output=True, text=True,
                                  encoding="utf-8", env=script_env())
            self.assertEqual(same.returncode, 2)
            self.assertIn("CA 私钥不能跟着进去", same.stderr)


def rogue_cert(base, san):
    """绕过脚本，直接拿 CA 私钥签一张名字约束以外的证书（模拟 CA 私钥泄露）。"""
    out = base / ("rogue-" + re.sub(r"\W", "_", san))
    out.mkdir(exist_ok=True)
    script = f"""set -e
export MSYS2_ARG_CONV_EXCL='/CN='
cd '{bash_path(out)}'
printf '[e]\\nsubjectAltName={san}\\nextendedKeyUsage=serverAuth\\n' > ext.cnf
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out r.key 2>/dev/null
openssl req -new -key r.key -subj '/CN=rogue' -out r.csr
openssl x509 -req -in r.csr -CA '{bash_path(base / "ca" / "ca.crt")}' -CAkey '{bash_path(base / "ca" / "ca.key")}' \\
  -set_serial 7 -days 30 -extfile ext.cnf -extensions e -out r.crt 2>/dev/null
"""
    done = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return str(out / "r.crt"), str(out / "r.key")


def handshake(pair, cafile, name) -> bool:
    """起一个只握手的 TLS 服务器，用 Python 的默认校验去连。"""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(*pair)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def accept():
        try:
            conn, _ = listener.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    client_ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                client_ctx.wrap_socket(raw, server_hostname=name) as tls:
            tls.sendall(b"x")
        return True
    except ssl.SSLError:
        return False
    finally:
        listener.close()
        thread.join(5)


# --- 真起应用 ---------------------------------------------------------------------------------

def child_env(**extra):
    env = {k: v for k, v in os.environ.items()}
    env.update(extra)
    return env


@unittest.skipUnless(OPENSSL, "没有 bash + openssl")
class ServeProcessTests(unittest.TestCase):
    """python -m app.serve 真起来：内置 TLS + 本机明文口；--check、--probe；SIGTERM 两个口一起停。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        done = make_certs(cls.base, "--ip", "192.0.2.10")
        assert done.returncode == 0, done.stderr
        cls.cert, cls.key = str(cls.base / "tls" / "server.crt"), str(cls.base / "tls" / "server.key")
        cls.ca = str(cls.base / "ca" / "ca.crt")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_module(self, *args, **env):
        return subprocess.run([sys.executable, "-m", "app.serve", *args], capture_output=True, text=True,
                              encoding="utf-8", cwd=str(REPO), env=child_env(**env), timeout=60)

    def test_check(self):
        ok = self.run_module("--check", TLS_CERT_FILE=self.cert, TLS_KEY_FILE=self.key, LOCAL_HTTP_PORT="18766")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("https://0.0.0.0:8765", ok.stdout)
        self.assertIn("http://127.0.0.1:18766（只给本机）", ok.stdout)
        self.assertIn("192.0.2.10", ok.stdout)
        self.assertEqual(self.run_module("--check").returncode, 0)
        other = make_certs(self.base / "other", "--ip", "192.0.2.11")
        self.assertEqual(other.returncode, 0, other.stderr)
        for env, needle in (({"FORWARDED_ALLOW_IPS": "*"}, "TRUSTED_PROXIES"),
                            ({"TRUSTED_PROXIES": "*"}, "不能写 *"), ({"TRUSTED_PROXIES": "proxy.local"}, "不是 IP"),
                            ({"TLS_CERT_FILE": self.cert, "TLS_KEY_FILE": str(self.base / "other" / "tls" / "server.key")},
                             "不配对"),
                            ({"TLS_CERT_FILE": "/nope/server.crt", "TLS_KEY_FILE": self.key}, "不存在"),
                            ({"LOCAL_HTTP_PORT": "18766"}, "只在开了 TLS 时用")):
            with self.subTest(env=env):
                bad = self.run_module("--check", **env)
                self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)
                self.assertIn(needle, bad.stdout)
        if os.name == "posix":
            loose = self.base / "loose.key"
            shutil.copy(self.key, loose)
            os.chmod(loose, 0o644)
            bad = self.run_module("--check", TLS_CERT_FILE=self.cert, TLS_KEY_FILE=str(loose))
            self.assertEqual(bad.returncode, 2)
            self.assertIn("chmod 600", bad.stdout)

    def test_refuses_to_start(self):
        bad = self.run_module(FORWARDED_ALLOW_IPS="127.0.0.1")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("FORWARDED_ALLOW_IPS", bad.stderr)

    def test_https_and_the_local_plain_port(self):
        port, local = free_port(), free_port()
        (self.base / "data").mkdir(exist_ok=True)
        env = child_env(PORT=str(port), LOCAL_HTTP_PORT=str(local), TLS_CERT_FILE=self.cert, TLS_KEY_FILE=self.key,
                        LISTEN_HOST="127.0.0.1", DATA_DIR=str(self.base / "data"))
        process = subprocess.Popen([sys.executable, "-m", "app.serve"], cwd=str(REPO), env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        output = []
        reader = threading.Thread(target=lambda: output.extend(process.stdout), daemon=True)
        reader.start()
        try:
            self.assertTrue(wait_for(local, process), "".join(output))
            verified = ssl.create_default_context(cafile=self.ca)
            self.assertEqual(status(f"https://127.0.0.1:{port}/api/documents", verified), 401)
            self.assertEqual(status(f"https://localhost:{port}/", verified), 401)
            with self.assertRaises(urllib.error.URLError) as refused:     # 没导入 CA：连不上，绝不跳过校验
                status(f"https://127.0.0.1:{port}/", ssl.create_default_context())
            self.assertIsInstance(refused.exception.reason, ssl.SSLCertVerificationError)
            old = ssl.create_default_context(cafile=self.ca)
            old.maximum_version = ssl.TLSVersion.TLSv1_1
            with self.assertRaises((urllib.error.URLError, ssl.SSLError, ConnectionError)):
                status(f"https://127.0.0.1:{port}/", old)
            self.assertEqual(status(f"http://127.0.0.1:{local}/api/documents"), 401)
            with self.assertRaises((urllib.error.URLError, ConnectionError, http_exceptions())):
                status(f"http://127.0.0.1:{port}/")                       # HTTPS 口上说明文：不应答
            probe = subprocess.run([sys.executable, "-m", "app.serve", "--probe"], cwd=str(REPO), env=env,
                                   capture_output=True, timeout=30)
            self.assertEqual(probe.returncode, 0, probe.stderr)
            no_local = {**env, "LOCAL_HTTP_PORT": ""}
            probe = subprocess.run([sys.executable, "-m", "app.serve", "--probe"], cwd=str(REPO), env=no_local,
                                   capture_output=True, timeout=30)
            self.assertEqual(probe.returncode, 0, probe.stderr)
            if os.name == "posix":
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                process.wait(20)
                self.assertLess(time.monotonic() - started, 15)
                for p in (port, local):
                    with self.assertRaises(OSError):
                        socket.create_connection(("127.0.0.1", p), timeout=2).close()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(20)
            reader.join(5)
        text = "".join(output)
        self.assertIn(f"Uvicorn running on https://127.0.0.1:{port}", text)
        self.assertIn(f"Uvicorn running on http://127.0.0.1:{local}", text)
        self.assertEqual(text.count("Application startup complete"), 1, text)    # lifespan 只跑一次
        if os.name == "posix":
            self.assertIn("Application shutdown complete", text)


def http_exceptions():
    import http.client
    return http.client.HTTPException


def status(url, context=None):
    try:
        with urllib.request.urlopen(url, timeout=10, context=context) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def wait_for(port, process, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


# --- release.sh ----------------------------------------------------------------------------------

class ReleaseTests(unittest.TestCase):
    def test_preflight_runs_before_the_old_container_stops(self):
        preflight = RELEASE.rindex("python -m app.serve --check")
        self.assertLess(preflight, RELEASE.index("docker stop -t 60"))
        self.assertIn('elif [ "$PREFLIGHT_CODE" = 2 ]; then', RELEASE)
        self.assertIn("--network none", RELEASE[preflight - 200:preflight])
        self.assertIn("No module named app.serve", RELEASE)
        for name in ("TLS_CERT_FILE", "TLS_KEY_FILE", "LOCAL_HTTP_PORT", "LISTEN_HOST", "TRUSTED_PROXIES"):
            self.assertIn(name, RELEASE[RELEASE.index("NEW_ONLY=\"\""):])

    def test_probe_url_and_mount(self):
        self.assertIn('PROBE_URL="http://127.0.0.1:$LOCAL_HTTP_PORT"', RELEASE)
        self.assertIn('PROBE_URL="https://127.0.0.1:$APP_PORT"', RELEASE)
        self.assertIn('PROBE_URL="http://127.0.0.1:$APP_PORT"', RELEASE)
        self.assertEqual(RELEASE.count('CURL_TLS="-k"'), 1)
        self.assertIn('TLS_MOUNT=(-v "$TLS_DIR:/tls:ro")', RELEASE)
        self.assertEqual(RELEASE.count('${TLS_MOUNT[@]+"${TLS_MOUNT[@]}"}'), 2)    # 预检和正式启动挂同一个目录

    @unittest.skipUnless(BASH, "没有 bash")
    def test_print_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "prod.env"
            for text, url in (("PORT=9000\n", "http://127.0.0.1:9000"),
                              ("PORT=9000\nTLS_CERT_FILE=/tls/server.crt\nTLS_KEY_FILE=/tls/server.key\n",
                               "https://127.0.0.1:9000"),
                              ("PORT=9000\nTLS_CERT_FILE=/tls/server.crt\nLOCAL_HTTP_PORT=8765\n",
                               "http://127.0.0.1:8765")):
                with self.subTest(text=text):
                    env_file.write_text("WEB_USER=a\nWEB_PASSWORD=b\n" + text, encoding="utf-8")
                    env = {k: v for k, v in os.environ.items() if not k.startswith(("APP_", "TLS_", "ENV_FILE"))}
                    env.update(ENV_FILE=bash_path(env_file), TLS_DIR="/opt/kb-app/tls")
                    done = subprocess.run([BASH, bash_path(REPO / "deploy" / "release.sh"), "--print-config"],
                                          capture_output=True, text=True, encoding="utf-8", env=env)
                    got = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
                    self.assertEqual(got["PROBE_URL"], url, done.stderr)
                    self.assertEqual(got["TLS_DIR"], "/opt/kb-app/tls")


if __name__ == "__main__":
    unittest.main()
