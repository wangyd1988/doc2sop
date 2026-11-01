"""页面上配置主机与数据源（应用这一层）：接一个真起的工具服务，应用只转交。

口令和凭据原样转给工具服务（请求体手动解析，FastAPI 的 422 会回显输入），不出现在任何回复和日志里；状态码原样转回页面；
跨站的写请求 403；按来源地址限频；要确认的工具旁边补上用到它们的 SOP；安装包原样下载；老工具服务时页面照旧只读。
"""
import contextlib
import hashlib
import io
import json
import logging
import os
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import tests.support  # noqa: F401
from tests.test_page_config import (DB_SECRET, HOST_BLOB, HOSTS_CONFIG, PASS, TOKEN, WRONG, FakeDriver, FakeSsh,
                                    ops)

from app import main as app_main, playbooks
from app.agent import ops_client
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app

POSIX = os.name == "posix"
CONFIG = textwrap.dedent("""\
    tools:
      - {name: one, desc: 看内存, binary: free, argv: [free, -m], params: {}}
      - {name: cmdb_count, desc: 资产数, impl: {type: sql, conn: cmdb, query: "SELECT count(*) AS n FROM assets"},
         params: {}}
    """)
CONNECTION = {"name": "cmdb", "type": "postgres", "host": "db.example.internal", "database": "cmdb",
              "user": "doc2sop_ro", "tls": "require"}


class _App(unittest.TestCase):
    CONFIG = CONFIG

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        self.main.write_text(self.CONFIG, encoding="utf-8")
        (self.dir / "scripts").mkdir()
        self.passfile = self.dir / "private" / "approval.hash"
        self.printed = io.StringIO()
        redirect = contextlib.redirect_stdout(self.printed)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.ssh = FakeSsh()
        self.driver = FakeDriver()
        patchers = [
            patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
                                    "mmtime": None, "pmtime": None, "includes": [], "tools": {}, "problems": [],
                                    "mcp_servers": {}, "connections": {}, "hosts": None, "held": [], "page": {}}),
            patch.dict(ops._approval, {"failures": 0, "locked_until": 0.0, "logged": None}),
            patch.dict(ops.SCRYPT_PARAMS, {"p": 1}),
            patch.dict(os.environ, {"OPS_APPROVAL_FILE": str(self.passfile), "OPS_CLI": ""}),
            patch.dict(ops._page_tests, clear=True),
            patch.dict(ops._page_bundle_times, clear=True),
            patch.dict(app_main._config_hits, clear=True),
            patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"),
            patch.object(ops._monitor, "wake", lambda: None),
            patch.object(ops.subprocess, "run", self.ssh.run),
            patch.object(ops, "_driver", lambda kind: (self.driver, "")),
            patch.object(ops, "_page_probe", lambda label, caller, probe, wait=None: ops._precheck_run(label, caller, probe)),
            patch.object(ops.Handler, "token", "t0k"),
        ]
        os.environ.pop("OPS_PAGE_CONFIG", None)
        os.environ.pop("OPS_PRIVATE_DIR", None)
        if POSIX:
            patchers.append(patch.object(ops, "APPROVAL_OWNER", os.geteuid()))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        ops.refresh(force=True)
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        for patcher in (patch.object(ops_client, "OPS_URL", f"http://127.0.0.1:{server.server_address[1]}"),
                        patch.object(ops_client, "OPS_TOKEN", "t0k")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)
        ops._write_private(str(self.passfile), json.dumps(ops.new_approval_record(PASS)))

    def post(self, action, body, **kwargs):
        return self.client.post(f"/api/tools/config/{action}", auth=self.auth, json=body, **kwargs)

    def assertNoSecrets(self, *texts):
        for text in texts + (self.printed.getvalue(),):
            for value in (PASS, WRONG, DB_SECRET, TOKEN, "FAKEPRIVATEKEYMATERIAL"):
                self.assertNotIn(value, text)


class RelayTests(_App):
    def test_save_relays_and_never_echoes_the_secret_or_passphrase(self):
        with self.assertLogs("kb", level="DEBUG") as logs:
            wrong = self.post("connection-save", {"connection": CONNECTION, "secret": DB_SECRET, "passphrase": WRONG})
            right = self.post("connection-save", {"connection": CONNECTION, "secret": DB_SECRET, "passphrase": PASS})
        self.assertEqual(wrong.status_code, 403)
        self.assertIn("审批口令不对", wrong.json()["detail"])
        self.assertEqual(right.status_code, 200, right.text)
        self.assertEqual(right.json()["note"], "凭据已设置")
        view = self.client.get("/api/tools/config", auth=self.auth)
        self.assertEqual(view.status_code, 200)
        item = next(conn for conn in view.json()["connections"] if conn["name"] == "cmdb")
        self.assertEqual((item["origin"], item["secret"]["state"]), ("page", "set"))
        tools = self.client.get("/api/tools", auth=self.auth).json()
        self.assertEqual(tools["connections"]["cmdb"]["secret"]["state"], "set")
        self.assertNoSecrets(wrong.text, right.text, view.text, json.dumps(tools, ensure_ascii=False),
                             "\n".join(logs.output))

    def test_bad_bodies_are_not_echoed(self):
        response = self.client.post("/api/tools/config/connection-save", auth=self.auth,
                                    content=b'{"secret": "' + DB_SECRET.encode() + b'", oops',
                                    headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(DB_SECRET, response.text)
        self.assertEqual(self.post("nope", {"secret": DB_SECRET}).status_code, 404)
        big = self.post("connection-save", {"secret": "x" * 70000})
        self.assertEqual(big.status_code, 413)
        refused = self.post("connection-save", {"connection": {**CONNECTION, "password": DB_SECRET},
                                                "passphrase": PASS})
        self.assertEqual(refused.status_code, 400)
        self.assertNoSecrets(response.text, refused.text)

    def test_wrong_passphrases_lock_the_page_and_423_passes_through(self):
        for _ in range(4):
            self.assertEqual(self.post("connection-save", {"connection": CONNECTION, "passphrase": WRONG}).status_code, 403)
        self.assertEqual(self.post("export", {"tool": "one", "on": True, "passphrase": WRONG}).status_code, 423)
        locked = self.post("connection-save", {"connection": CONNECTION, "passphrase": PASS})
        self.assertEqual(locked.status_code, 423)
        self.assertIn("锁定", locked.json()["detail"])

    def test_cross_site_writes_are_refused(self):
        for action in ("connection-save", "export", "host-trust", "host-check"):
            with self.subTest(action=action):
                response = self.client.post(f"/api/tools/config/{action}", auth=self.auth,
                                            json={"connection": CONNECTION, "secret": DB_SECRET, "passphrase": PASS},
                                            headers={"Origin": "https://evil.example"})
                self.assertEqual(response.status_code, 403)
                self.assertIn("跨站请求被拒绝", response.json()["detail"])
        self.assertFalse(ops._page_file().exists())
        self.assertEqual(ops._approval["failures"], 0)

    def test_requests_are_rate_limited_per_address(self):
        for _ in range(10):
            self.assertEqual(self.post("connection-save", {"connection": {"name": "Bad"}}).status_code, 400)
        limited = self.post("connection-save", {"connection": CONNECTION, "passphrase": PASS})
        self.assertEqual(limited.status_code, 429)
        self.assertIn("太频繁", limited.json()["detail"])
        # 关闭对外开放另算一类
        self.assertEqual(self.post("export", {"tool": "one", "on": False}).status_code, 200)

    def test_confirm_lists_come_with_the_sops_that_use_those_tools(self):
        self.assertEqual(self.post("connection-save", {"connection": CONNECTION, "secret": DB_SECRET,
                                                       "passphrase": PASS}).status_code, 200)
        sop = playbooks.save(None, "资产核对", "资产数对不上时", [{"tool": "cmdb_count", "args": {}, "checkpoint": "看总数"}],
                             {"cmdb_count"})
        self.addCleanup(playbooks.delete, sop)
        refused = self.post("connection-delete", {"name": "cmdb", "passphrase": PASS})
        self.assertEqual(refused.status_code, 409)
        body = refused.json()
        self.assertEqual(body["confirm"], ["cmdb_count"])
        self.assertEqual([item["name"] for item in body["confirm_sops"]], ["资产核对"])
        view = self.client.get("/api/tools/config", auth=self.auth).json()
        item = next(conn for conn in view["connections"] if conn["name"] == "cmdb")
        self.assertEqual([sop["name"] for sop in item["sops"]], ["资产核对"])
        done = self.post("connection-delete", {"name": "cmdb", "confirm": ["cmdb_count"], "passphrase": PASS})
        self.assertEqual(done.status_code, 200, done.text)

    def test_the_switch_off_passes_403_through(self):
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            response = self.post("connection-save", {"connection": CONNECTION, "passphrase": PASS})
            self.assertEqual(response.status_code, 403)
            self.assertIn("OPS_PAGE_CONFIG=off", response.json()["detail"])
            self.assertFalse(self.client.get("/api/tools/config", auth=self.auth).json()["enabled"])

    def test_an_old_tool_service_leaves_the_page_read_only(self):
        real = ops_client._request

        def old(path, payload=None, timeout=30, headers=None):
            if path.startswith("/tools/config"):
                raise ops_client.OpsUnavailable("Not found", status=404, data={"error": "Not found"})
            return real(path, payload, timeout, headers)

        with patch.object(ops_client, "_request", old):
            view = self.client.get("/api/tools/config", auth=self.auth).json()
            self.assertFalse(view["supported"])
            self.assertIn("工具服务版本较旧", view["error"])
            response = self.post("connection-save", {"connection": CONNECTION, "passphrase": PASS})
            self.assertEqual(response.status_code, 501)
            self.assertIn("工具服务版本较旧", response.json()["detail"])


class HostRelayTests(_App):
    CONFIG = HOSTS_CONFIG

    def test_impact_lists_and_the_bundle_download(self):
        web01 = {"name": "web01", "address": "10.0.1.11", "user": "opsread", "groups": ["gateway"],
                 "from": ["117.72.91.19"]}
        added = self.post("host-save", {"host": web01, "passphrase": PASS})
        self.assertEqual(added.status_code, 200, added.text)
        sop = playbooks.save(None, "网关磁盘巡检", "", [{"tool": "gw_disk", "args": {}, "checkpoint": "看用量"}],
                             {"gw_disk"})
        self.addCleanup(playbooks.delete, sop)
        fingerprint = ops.key_fingerprint(HOST_BLOB)
        dry = self.post("host-trust", {"name": "web01", "dry_run": True})
        self.assertEqual(dry.status_code, 200)
        impact = dry.json()["impact"]
        self.assertEqual([item["tool"] for item in impact], ["gw_disk"])
        self.assertEqual([sop["name"] for sop in impact[0]["sops"]], ["网关磁盘巡检"])
        refused = self.post("host-trust", {"name": "web01", "fingerprint": fingerprint, "passphrase": PASS})
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(refused.json()["confirm_impact"][0]["sops"][0]["name"], "网关磁盘巡检")
        trusted = self.post("host-trust", {"name": "web01", "fingerprint": fingerprint, "confirm_impact": ["gw_disk"],
                                           "passphrase": PASS})
        self.assertEqual(trusted.status_code, 200, trusted.text)
        self.assertEqual(self.post("host-bundle", {"name": "web01"}).status_code, 200)
        download = self.client.get("/api/tools/config/hosts/web01/bundle", auth=self.auth)
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.headers["content-type"], "application/gzip")
        self.assertIn('filename="doc2sop-ops-web01.tgz"', download.headers["content-disposition"])
        on_disk = Path(ops._page_bundle_path("web01")).read_bytes()
        self.assertEqual(download.content, on_disk)
        self.assertEqual(download.headers["x-content-sha256"], hashlib.sha256(on_disk).hexdigest())
        self.assertEqual(self.client.get("/api/tools/config/hosts/..%2Fx/bundle", auth=self.auth).status_code, 404)
        self.assertEqual(self.client.get("/api/tools/config/hosts/nope/bundle", auth=self.auth).status_code, 404)
        self.assertNoSecrets(added.text, trusted.text, json.dumps(self.client.get("/api/tools/config",
                                                                                  auth=self.auth).json()))


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
