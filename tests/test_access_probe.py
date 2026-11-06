"""对外接入页的「测一下」「试调」（app/mcp_probe.py）和审计里的「页面试调」标记（access.py 的 via 列）。

测一下、试调在进程内转给 /mcp 的 TokenGate：令牌、来源（MCP_CLIENTS）、总开关、Host 白名单、范围、限流照真实检查走；
每次结束都关掉开的会话。令牌明文不进日志、不进回复。
"""
import sqlite3
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import tests.support  # noqa: F401

from app import access, mcp_probe, mcp_server, serve
from app import main as app_main
from tests.test_mcp_export import BASIC, ExportCase, make_app, make_client, reset_access

OLD_CALLS = """CREATE TABLE mcp_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, token_id TEXT NOT NULL, client TEXT NOT NULL,
  kind TEXT NOT NULL, name TEXT NOT NULL, args TEXT NOT NULL DEFAULT '{}', result_chars INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 1, error TEXT NOT NULL DEFAULT '',
  execution_id TEXT, session TEXT NOT NULL DEFAULT '')"""
OLD_INSERT = ("INSERT INTO mcp_calls (at, token_id, client, kind, name, args, result_chars, duration_ms, ok,"
              " error, execution_id, session) VALUES ('2026-11-01T00:00:00+00:00', 't', 'c', 'tool', 'kb_search',"
              " '{}', 1, 1, 1, '', NULL, '')")


class AuditViaTests(unittest.TestCase):
    def setUp(self):
        reset_access()
        self.addCleanup(reset_access)

    def test_old_database_gets_the_column_and_old_rows_read_as_external(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(OLD_CALLS)
        conn.execute(OLD_INSERT)
        access._migrate(conn)
        access._migrate(conn)     # 再跑一遍不报错
        self.assertEqual(dict(conn.execute("SELECT via FROM mcp_calls").fetchone()), {"via": ""})

    def test_rollback_old_code_still_writes_and_reads_the_migrated_table(self):
        """回滚到老镜像：老代码的 INSERT 写明了列名（不含 via），SELECT * 多一列。"""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(OLD_CALLS)
        access._migrate(conn)
        conn.execute(OLD_INSERT)
        row = dict(conn.execute("SELECT * FROM mcp_calls").fetchone())
        self.assertEqual((row["name"], row["via"]), ("kb_search", ""))

    def test_record_call_keeps_page_and_drops_unknown_marks(self):
        client = make_client()
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True, via="page")
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True, via="evil")
        access.record_call(client, "tool", "kb_catalog", {}, 1, 1, True)
        self.assertEqual([c["via"] for c in access.recent_calls()], ["", "", "page"])

    def test_describe_tells_revoked_and_expired_apart_without_touching(self):
        token, secret = access.issue("测试", ["knowledge"])
        self.assertEqual(access.describe(secret)["status"], "active")
        self.assertIsNone(access.get(token["id"])["last_used_at"])
        access.revoke(token["id"])
        self.assertEqual(access.describe(secret)["status"], "revoked")
        self.assertIsNone(access.describe("d2s_nope"))
        self.assertIsNone(access.describe("not-a-token"))
        _, old = access.issue("过期的", ["knowledge"], expires_days=1)
        with access.lock:
            access.db.execute("UPDATE mcp_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE name = '过期的'")
            access.db.commit()
        self.assertEqual(access.describe(old)["status"], "expired")


ALL = ["initialize", "initialized", "tools/list", "tools/call", "close"]


class ProbeCase(ExportCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(reset_access)
        self.app, self.gate, _ = make_app()
        self.http = TestClient(self.app)
        self.http.__enter__()
        self.addCleanup(self.http.__exit__, None, None, None)
        self.token, self.secret = access.issue("张三的 Claude Code", ["knowledge", "sop"])

    def probe(self, body, http=None):
        return (http or self.http).post("/api/mcp/probe", auth=BASIC, json=body)

    def steps(self, result):
        return {row["step"]: row for row in result["steps"]}


class ProbeTests(ProbeCase):
    def test_probe_walks_the_real_path_and_closes_its_session(self):
        response = self.probe({"token": self.secret})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        result = response.json()
        self.assertTrue(result["ok"], result)
        self.assertEqual([row["step"] for row in result["steps"]], ALL)
        self.assertTrue(all(row["ok"] for row in result["steps"]))
        names = [t["name"] for t in result["tools"]]
        self.assertIn("kb_search", names)
        self.assertNotIn("host_disk", names)                    # 这枚令牌没有数据工具范围
        search = next(t for t in result["tools"] if t["name"] == "kb_search")
        self.assertEqual(search["inputSchema"]["required"], ["query"])
        self.assertEqual(result["call"]["tool"], "kb_catalog")
        self.assertIn("休假制度.md", result["call"]["text"])
        self.assertEqual(result["server"]["protocol"], "2025-11-25")
        self.assertEqual((result["token"]["id"], result["token"]["status"]), (self.token["id"], "active"))
        self.assertEqual(self.gate.tracker.live(self.token["id"]), 0)       # 会话关掉了
        calls = access.recent_calls()
        self.assertEqual([(c["name"], c["via"]) for c in calls], [("kb_catalog", "page")])

    def test_repeated_probes_do_not_use_up_the_session_slots(self):
        with patch.object(mcp_server, "SESSIONS_PER_TOKEN", 2):
            for _ in range(4):
                self.assertTrue(self.probe({"token": self.secret}).json()["ok"])

    def test_a_bearer_prefix_is_tolerated_and_odd_characters_are_refused_without_echo(self):
        self.assertTrue(self.probe({"token": f"  Bearer {self.secret}\n"}).json()["ok"])
        bad = self.probe({"token": self.secret[:10] + " 中文" + self.secret[10:]})
        self.assertEqual(bad.status_code, 400)
        self.assertNotIn(self.secret[10:], bad.text)
        self.assertEqual(self.probe({}).status_code, 400)
        raw = self.http.post("/api/mcp/probe", auth=BASIC, content=b'{"token": "' + self.secret.encode() + b'"',
                             headers={"Content-Type": "application/json"})
        self.assertEqual(raw.status_code, 400)
        self.assertNotIn(self.secret, raw.text)

    def test_wrong_revoked_and_expired_tokens_are_told_apart(self):
        unknown = self.probe({"token": "d2s_000000000000_nothing"}).json()
        first = self.steps(unknown)["initialize"]
        self.assertEqual((unknown["ok"], first["status"], first["code"], unknown["token"]),
                         (False, 401, "invalid_token", None))
        self.assertEqual([r["code"] for r in unknown["steps"][1:]], ["not_run"] * 3)   # 没开会话：没有「关会话」
        access.revoke(self.token["id"])
        revoked = self.probe({"token": self.secret}).json()
        self.assertEqual((self.steps(revoked)["initialize"]["code"], revoked["token"]["status"]),
                         ("invalid_token", "revoked"))

    def test_the_token_never_reaches_the_log_or_the_reply(self):
        with self.assertLogs("kb", "INFO") as logged:
            text = self.probe({"token": self.secret}).text
            self.probe({"token": "d2s_000000000000_nothing"})
        output = "\n".join(logged.output)
        self.assertIn(f"mcp page probe token={self.token['id']}", output)
        self.assertNotIn(self.secret, output)
        self.assertNotIn("d2s_000000000000_nothing", output)
        self.assertNotIn(self.secret, text)

    def test_switch_off_and_client_list_are_reported(self):
        access.set_switch(False, "tester", "127.0.0.1")
        self.assertEqual(self.steps(self.probe({"token": self.secret}).json())["initialize"]["code"], "disabled")
        access.set_switch(True, "tester", "127.0.0.1")
        with patch.object(mcp_server, "MCP_CLIENTS", ["127.0.0.1"]):
            row = self.steps(self.probe({"token": self.secret}).json())["initialize"]
        self.assertEqual((row["status"], row["code"]), (403, "client_not_allowed"))
        self.assertIn("127.0.0.1", row["detail"])

    def test_host_is_checked_and_must_be_one_of_the_offered_addresses(self):
        with patch.object(mcp_server, "MCP_ALLOWED_HOSTS", ["127.0.0.1"]):
            app, _, _ = make_app()       # 会话管理器按启动时的 Host 白名单建：另起一个应用
            with TestClient(app) as http:
                row = self.steps(self.probe({"token": self.secret}, http).json())["initialize"]
        self.assertEqual((row["status"], row["code"]), (421, "invalid_host"))
        for host in ("evil.example", "testserver\r\nX-Evil: 1", "a,b", " testserver", 3):
            with self.subTest(host=host):
                self.assertEqual(self.probe({"token": self.secret, "host": host}).status_code, 400)
        self.assertTrue(self.probe({"token": self.secret, "host": "testserver"}).json()["ok"])

    def test_a_data_only_token_is_not_used_to_call_the_host(self):
        _, data = access.issue("只有数据工具", ["data"])
        result = self.probe({"token": data}).json()
        self.assertTrue(result["ok"], result)
        row = self.steps(result)["tools/call"]
        self.assertEqual((row["ok"], row["code"]), (True, "skipped"))
        self.assertEqual(access.recent_calls(), [])

    def test_only_two_at_a_time(self):
        mcp_probe._running["count"] = mcp_probe.MAX_RUNNING
        self.addCleanup(mcp_probe._running.update, count=0)
        self.assertEqual(self.probe({"token": self.secret}).status_code, 429)
        self.assertEqual(self.http.post("/api/mcp/try", auth=BASIC, json={"token": self.secret, "tool": "kb_catalog"})
                         .status_code, 429)

    def test_the_endpoints_need_the_page_password_and_the_same_site(self):
        self.assertEqual(self.http.post("/api/mcp/probe", json={"token": self.secret}).status_code, 401)
        self.assertEqual(self.http.post("/api/mcp/try", json={"token": self.secret, "tool": "x"}).status_code, 401)
        for path in ("/api/mcp/probe", "/api/mcp/try"):
            self.assertTrue(app_main.cross_site("POST", path, {"host": "a:1", "origin": "http://b:1"}))

    def test_status_offers_addresses_and_sop_titles(self):
        status = self.http.get("/api/mcp", auth=BASIC).json()
        self.assertEqual(status["addresses"], [{"url": "http://testserver/mcp", "host": "testserver", "label": "本页地址"}])
        self.assertEqual(sorted(status["sop_titles"]), ["磁盘巡检", "请假核对"])
        tls = {"builtin": True, "port": 9443, "local_port": 8765, "names": ["117.72.91.19", "doc2sop.autos", "*.x", "::1"]}
        with patch.object(serve, "tls_status", return_value=tls):
            app, _, _ = make_app()
            with TestClient(app, base_url="https://117.72.91.19:9443") as http:
                found = [(a["url"], a["label"]) for a in http.get("/api/mcp", auth=BASIC).json()["addresses"]]
                self.assertTrue(self.probe({"token": self.secret, "host": "doc2sop.autos:9443"}, http).json()["ok"])
        self.assertEqual(found, [("https://117.72.91.19:9443/mcp", "本页地址"), ("https://doc2sop.autos:9443/mcp", "证书里的名字"),
                                 ("https://[::1]:9443/mcp", "证书里的名字"), ("http://127.0.0.1:8765/mcp", "经 SSH 隧道")])


class TryTests(ProbeCase):
    def post(self, body):
        return self.http.post("/api/mcp/try", auth=BASIC, json=body)

    def test_try_follows_the_token_s_categories_and_shows_the_raw_reply(self):
        _, hr = access.issue("人事", ["knowledge"], categories=["人事"])
        result = self.post({"token": hr, "tool": "kb_search", "arguments": {"query": "磁盘告警"}}).json()
        self.assertTrue(result["ok"], result)
        self.assertEqual([r["step"] for r in result["steps"]], ["initialize", "initialized", "tools/call", "close"])
        self.assertNotIn("巡检规范", result["result"]["text"])
        self.assertEqual(result["result"]["raw"]["result"]["content"][0]["text"], result["result"]["text"])
        self.assertEqual([(c["name"], c["via"]) for c in access.recent_calls()], [("kb_search", "page")])

    def test_errors_rate_limits_and_bad_arguments(self):
        result = self.post({"token": self.secret, "tool": "host_disk"}).json()
        self.assertFalse(result["ok"])
        self.assertTrue(result["result"]["is_error"])
        self.assertEqual(result["steps"][2]["code"], "tool_error")
        _, slow = access.issue("每分钟一次", ["knowledge"], rate_per_minute=1)
        self.assertTrue(self.post({"token": slow, "tool": "kb_catalog"}).json()["ok"])
        limited = self.post({"token": slow, "tool": "kb_catalog"}).json()
        self.assertIn("调用太频繁", limited["result"]["text"])
        self.assertEqual(self.post({"token": self.secret, "tool": "kb_search", "arguments": []}).status_code, 400)
        self.assertEqual(self.post({"token": self.secret, "tool": ""}).status_code, 400)
        self.assertEqual(self.post({"token": self.secret, "tool": "a\nb"}).status_code, 400)

    def test_a_slow_tool_times_out_and_the_session_is_still_closed(self):
        import time as _time

        def slow(*args, **kwargs):
            _time.sleep(0.5)
            return "迟到的结果", True

        with patch.object(mcp_probe, "TRY_TIMEOUT", 0.1), patch.object(mcp_server, "call_tool", side_effect=slow):
            result = self.post({"token": self.secret, "tool": "kb_catalog"}).json()
        rows = {r["step"]: r for r in result["steps"]}
        self.assertEqual(rows["tools/call"]["code"], "timeout")
        self.assertTrue(rows["close"]["ok"])
        self.assertEqual(self.gate.tracker.live(self.token["id"]), 0)


if __name__ == "__main__":
    unittest.main()
