"""对外接入页的总开关、删令牌、清除调用记录和操作记录（app/access.py、app/mcp_server.py、app/approval.py）。

审批口令由工具服务核对（ops_client.verify_passphrase）。这里把它换成一个假的：只有 GOOD 算对，并记下收到了什么；
真的工具服务那一侧（POST /tools/approval/verify）由 tests/test_approval_verify.py 管。
"""
import contextlib
import io
import json
import time
import unittest
from datetime import timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

import tests.support  # noqa: F401
from tests.test_mcp_export import ACCEPT, BASIC, INIT, ExportCase, bearer, make_app, reset_access

from app import access, approval, mcp_server
from app import main as app_main
from app import main as app_main
from app.agent import ops_client

GOOD = "the right passphrase"
ORIGIN = {"Origin": "http://testserver"}


class FakeVerifier:
    """假的工具服务：verify_support 能用，verify_passphrase 只认 GOOD；记下每次核对的 action、target。"""

    def __init__(self, reason=""):
        self.reason = reason
        self.calls = []

    def support(self, timeout=5):
        return {"supported": True, "reason": self.reason}

    def verify(self, passphrase, action, target, caller="", timeout=None):
        self.calls.append((action, target))
        if passphrase != GOOD:
            raise ops_client.OpsUnavailable("审批口令不对，还能再试 4 次", status=403)


class AccessAdminCase(ExportCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(reset_access)
        with access.lock:
            access.db.execute("DELETE FROM access_changes")
            access.db.commit()
        approval._hits.clear()
        self.app, self.gate, _ = make_app()
        self.http = TestClient(self.app)
        self.http.__enter__()
        self.addCleanup(self.http.__exit__, None, None, None)
        self.verifier = FakeVerifier()
        for p in (patch.object(ops_client, "verify_support", side_effect=lambda timeout=5: self.verifier.support()),
                  patch.object(ops_client, "verify_passphrase", side_effect=self.verifier.verify)):
            p.start()
            self.addCleanup(p.stop)
        self.token, self.secret = access.issue("张三的 Claude Code", ["knowledge", "sop"])

    def post(self, path, body):
        return self.http.post(path, auth=BASIC, json=body, headers=ORIGIN)

    def open_session(self):
        response = self.http.post("/mcp", json=INIT, headers=bearer(self.secret))
        self.assertEqual(response.status_code, 200, response.text)
        return response.headers["mcp-session-id"]


class SwitchTests(AccessAdminCase):
    def test_open_by_default_and_the_status_says_so(self):
        status = self.http.get("/api/mcp", auth=BASIC).json()
        self.assertTrue(status["switch"]["on"])
        self.assertIsNone(status["switch"]["at"])
        self.assertEqual(status["switch"]["reopen"], "")
        self.assertTrue(access.is_open())

    def test_closing_needs_no_passphrase_refuses_mcp_before_tokens_and_drops_sessions(self):
        self.open_session()
        self.assertEqual(self.gate.tracker.live(self.token["id"]), 1)
        closed = self.post("/api/mcp/switch", {"on": False})
        self.assertEqual(closed.status_code, 200, closed.text)
        self.assertFalse(closed.json()["switch"]["on"])
        self.assertEqual(self.verifier.calls, [])                       # 关不核对口令
        self.assertEqual(self.gate.tracker.live(self.token["id"]), 0)   # 连着的会话马上关掉
        with patch.object(access, "verify", side_effect=AssertionError("关着时不该碰令牌库")):
            for headers in (bearer(self.secret), ACCEPT):
                refused = self.http.post("/mcp", json=INIT, headers=headers)
                self.assertEqual(refused.status_code, 403)
                self.assertEqual(refused.json(), {"error": "disabled", "error_description": "对外接入已被管理员在页面上关闭"})
                self.assertNotIn("www-authenticate", refused.headers)
        state = access.switch_state()
        self.assertEqual((state["on"], state["user"], state["ip"]), (False, "tester", "testclient"))
        self.assertEqual([c["kind"] for c in access.list_changes()], ["switch-off"])
        # 再关一次：什么都不变，不多记
        self.assertFalse(self.post("/api/mcp/switch", {"on": False}).json()["changed"])
        self.assertEqual(len(access.list_changes()), 1)

    def test_source_check_still_comes_first(self):
        access.set_switch(False)
        with patch.object(mcp_server, "MCP_CLIENTS", ["127.0.0.1"]):
            mcp_server._client_networks.cache_clear()
            with TestClient(self.app, client=("203.0.113.7", 50000)) as http, self.assertLogs("kb", "WARNING"):
                refused = http.post("/mcp", json=INIT, headers=bearer(self.secret))
            self.assertEqual(refused.json()["error"], "client_not_allowed")     # 公网看不出开关开没开
        mcp_server._client_networks.cache_clear()

    def test_reopening_needs_the_passphrase_and_never_echoes_it(self):
        access.set_switch(False)
        with self.assertLogs("kb", "INFO") as logged:
            missing = self.post("/api/mcp/switch", {"on": True})
            wrong = self.post("/api/mcp/switch", {"on": True, "passphrase": "guess-1"})
            self.assertFalse(access.is_open())
            right = self.post("/api/mcp/switch", {"on": True, "passphrase": GOOD})
        self.assertEqual((missing.status_code, missing.json()["detail"]), (400, "没有输入审批口令"))
        self.assertEqual(wrong.status_code, 403)
        self.assertTrue(wrong.json()["passphrase"])
        self.assertEqual(right.status_code, 200, right.text)
        self.assertTrue(access.is_open())
        self.assertEqual(self.verifier.calls, [("mcp-open", "对外接入"), ("mcp-open", "对外接入")])
        for text in ("\n".join(logged.output), missing.text, wrong.text, right.text):
            self.assertNotIn("guess-1", text)
            self.assertNotIn(GOOD, text)
        self.assertEqual([c["kind"] for c in access.list_changes()], ["switch-on", "switch-off"])
        self.assertEqual(self.http.post("/mcp", json=INIT, headers=bearer(self.secret)).status_code, 200)
        # 已经开着：不核对，也不消耗次数；不带口令照样是 400
        self.assertFalse(self.post("/api/mcp/switch", {"on": True, "passphrase": "x"}).json()["changed"])
        self.assertEqual(self.post("/api/mcp/switch", {"on": True}).status_code, 400)
        self.assertEqual(len(self.verifier.calls), 2)

    def test_reopening_is_unavailable_with_an_old_tool_service_or_page_config_off(self):
        access.set_switch(False)
        for reason in (ops_client.OLD_SERVICE_VERIFY, "页面配置在服务器上关了（OPS_PAGE_CONFIG=off）：页面上只能看"):
            with self.subTest(reason=reason):
                self.verifier.reason = reason
                self.assertEqual(self.http.get("/api/mcp", auth=BASIC).json()["switch"]["reopen"], reason)
                refused = self.post("/api/mcp/switch", {"on": True, "passphrase": GOOD})
                self.assertEqual((refused.status_code, refused.json()["detail"]), (403, reason))
                self.assertFalse(access.is_open())
                self.assertEqual(self.post("/api/mcp/switch", {"on": False}).status_code, 200)   # 关照样能关
        self.assertEqual(self.verifier.calls, [])

    def test_unexpected_answers_from_the_tool_service_never_count_as_passing(self):
        access.set_switch(False)
        for status in (404, 500, 502, 503):
            with self.subTest(status=status):
                with patch.object(ops_client, "verify_passphrase",
                                  side_effect=ops_client.OpsUnavailable("x", status=status)):
                    refused = self.post("/api/mcp/switch", {"on": True, "passphrase": GOOD})
                self.assertGreaterEqual(refused.status_code, 400)
                self.assertFalse(access.is_open())
        with patch.object(ops_client, "verify_passphrase", side_effect=RuntimeError("boom")), \
                self.assertLogs("kb", "WARNING"):
            self.assertEqual(self.post("/api/mcp/switch", {"on": True, "passphrase": GOOD}).status_code, 502)
        self.assertFalse(access.is_open())

    def test_bad_bodies_and_the_same_origin_rule(self):
        for body in ({}, {"on": "true"}, {"on": 1}):
            with self.subTest(body=body):
                self.assertEqual(self.post("/api/mcp/switch", body).status_code, 400)
        with TestClient(app_main.SameOriginOnly(self.app)) as guarded, self.assertLogs("kb", "WARNING"):
            cross = guarded.post("/api/mcp/switch", auth=BASIC, json={"on": False},
                                 headers={"Origin": "http://evil.example"})
        self.assertEqual(cross.status_code, 403)
        self.assertTrue(access.is_open())
        self.assertEqual(self.http.post("/api/mcp/switch", json={"on": False}).status_code, 401)
        self.assertTrue(access.is_open())

    def test_token_admin_keeps_working_while_switched_off(self):
        access.set_switch(False)
        issued = self.post("/api/mcp/tokens", {"name": "李四", "scopes": ["knowledge"]})
        self.assertEqual(issued.status_code, 200)
        token_id = issued.json()["token"]["id"]
        self.assertEqual(self.http.get("/api/mcp/tokens", auth=BASIC).status_code, 200)
        self.assertEqual(self.http.get("/api/mcp/calls", auth=BASIC).status_code, 200)
        self.assertEqual(self.http.delete(f"/api/mcp/tokens/{token_id}", auth=BASIC, headers=ORIGIN).status_code, 200)
        self.assertEqual(self.post(f"/api/mcp/tokens/{token_id}/remove", {}).status_code, 200)

    def test_cli_escape_hatch_opens_and_reports(self):
        access.set_switch(False, "tester", "1.2.3.4")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            self.assertEqual(access._cli(["open"]), 0)
            self.assertTrue(access.is_open())
            self.assertEqual(access.list_changes()[0]["user"], "cli")
            self.assertEqual(access._cli(["status"]), 0)
            self.assertEqual(access._cli(["close"]), 2)      # 关只在页面上关（要断开运行中应用里的连接）
        self.assertTrue(access.is_open())
        self.assertIn("已打开", out.getvalue())


class TokenRemoveTests(AccessAdminCase):
    def test_only_revoked_or_expired_tokens_can_be_removed_and_their_calls_stay(self):
        client = access.verify(self.secret)
        access.record_call(client, "tool", "kb_search", {"query": "x"}, 10, 5, True)
        refused = self.post(f"/api/mcp/tokens/{self.token['id']}/remove", {})
        self.assertEqual(refused.status_code, 409)
        self.assertIn("先吊销", refused.json()["detail"])
        access.revoke(self.token["id"])
        self.assertEqual(self.post(f"/api/mcp/tokens/{self.token['id']}/remove", {}).status_code, 200)
        self.assertIsNone(access.get(self.token["id"]))
        calls = access.recent_calls(10)
        self.assertEqual([(c["token_id"], c["client"]) for c in calls], [(self.token["id"], "张三的 Claude Code")])
        self.assertEqual(self.post(f"/api/mcp/tokens/{self.token['id']}/remove", {}).status_code, 404)
        change = access.list_changes()[0]
        self.assertEqual(change["kind"], "token-delete")
        self.assertIn("张三的 Claude Code", change["detail"])

    def test_expired_tokens_can_be_removed_and_names_are_cleaned_in_the_record(self):
        token, _ = access.issue("坏\x1b[31m名字", ["knowledge"], expires_days=1)
        with access.lock:
            access.db.execute("UPDATE mcp_tokens SET expires_at = ? WHERE id = ?",
                              (access._iso(access._now() - timedelta(days=1)), token["id"]))
            access.db.commit()
        self.assertEqual(self.post(f"/api/mcp/tokens/{token['id']}/remove", {}).status_code, 200)
        detail = access.list_changes()[0]["detail"]
        self.assertNotIn("\x1b", detail)
        self.assertIn("已过期", detail)


class PurgeTests(AccessAdminCase):
    def setUp(self):
        super().setUp()
        other, _ = access.issue("李四", ["knowledge"])
        self.other = other
        mine, theirs = access.verify(self.secret), access.Client(other["id"], "李四", frozenset({"knowledge"}), None, 60, 20000)
        for client in (mine, mine, theirs):
            access.record_call(client, "tool", "kb_search", {"query": "q"}, 10, 5, True)
        with access.lock:       # 一条 40 天以前的
            access.db.execute("UPDATE mcp_calls SET at = ? WHERE id = (SELECT MIN(id) FROM mcp_calls)",
                              (access._iso(access._now() - timedelta(days=40)),))
            access.db.commit()

    def test_bad_scopes_are_refused_before_the_passphrase_is_checked(self):
        for body in ({"scope": "one", "id": 1}, {"scope": "before"}, {"scope": "before", "days": 0},
                     {"scope": "before", "days": True}, {"scope": "before", "days": "30"}, {"scope": "token"},
                     {"scope": "token", "token_id": "../x"}):
            with self.subTest(body=body):
                self.assertEqual(self.post("/api/mcp/calls/purge", {**body, "passphrase": GOOD}).status_code, 400)
        self.assertEqual(self.verifier.calls, [])
        self.assertEqual(access.count_calls(), 3)

    def test_without_the_right_passphrase_nothing_is_deleted(self):
        self.assertEqual(self.post("/api/mcp/calls/purge", {"scope": "all"}).status_code, 400)
        wrong = self.post("/api/mcp/calls/purge", {"scope": "all", "passphrase": "guess"})
        self.assertEqual(wrong.status_code, 403)
        self.assertNotIn("guess", wrong.text)
        self.verifier.reason = ops_client.OLD_SERVICE_VERIFY
        self.assertEqual(self.post("/api/mcp/calls/purge", {"scope": "all", "passphrase": GOOD}).status_code, 403)
        self.assertEqual(access.count_calls(), 3)
        self.assertEqual(access.list_changes(), [])

    def test_each_scope_deletes_its_rows_and_leaves_a_record(self):
        before = self.post("/api/mcp/calls/purge", {"scope": "before", "days": 30, "passphrase": GOOD})
        self.assertEqual(before.json(), {"purged": 1, "total": 2})
        by_token = self.post("/api/mcp/calls/purge", {"scope": "token", "token_id": self.other["id"], "passphrase": GOOD})
        self.assertEqual(by_token.json(), {"purged": 1, "total": 1})
        everything = self.post("/api/mcp/calls/purge", {"scope": "all", "passphrase": GOOD})
        self.assertEqual(everything.json(), {"purged": 1, "total": 0})
        records = access.list_changes()
        self.assertEqual([(c["kind"], c["count"]) for c in records], [("calls-purge", 1)] * 3)
        self.assertEqual([c["detail"] for c in records], ["清除了全部调用记录", f"清除了令牌「李四」（{self.other['id']}）的调用记录",
                                                          "清除了30 天以前的调用记录"])
        self.assertTrue(all(c["user"] == "tester" and c["ip"] == "testclient" for c in records))
        self.assertNotIn(GOOD, json.dumps(records, ensure_ascii=False))
        self.assertEqual([t for t, _ in self.verifier.calls], ["mcp-audit-purge"] * 3)

    def test_the_record_and_the_deletion_share_one_transaction(self):
        plan = access.purge_plan({"scope": "all"})
        with patch.object(access, "_change", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                access.purge(plan)
        access.db.rollback()
        self.assertEqual(access.count_calls(), 3)

    def test_records_cannot_be_deleted_from_the_page(self):
        access.set_switch(False)
        for method in ("delete", "put", "patch", "post"):
            with self.subTest(method=method):
                response = getattr(self.http, method)("/api/mcp/changes", auth=BASIC, headers=ORIGIN)
                self.assertEqual(response.status_code, 405)
        paths = {getattr(r, "path", "") for r in self.app.routes}
        self.assertFalse([p for p in paths if "changes" in p and p != "/api/mcp/changes"])
        self.assertEqual(len(access.list_changes()), 1)
        self.assertEqual(self.http.get("/api/mcp/changes", auth=BASIC).json()["changes"][0]["kind"], "switch-off")

    def test_passphrase_endpoints_are_rate_limited_per_address(self):
        for _ in range(approval.PER_MINUTE):
            self.post("/api/mcp/calls/purge", {"scope": "all", "passphrase": "guess"})
        self.assertEqual(self.post("/api/mcp/calls/purge", {"scope": "all", "passphrase": GOOD}).status_code, 429)
        self.assertEqual(access.count_calls(), 3)


class DisconnectRaceTests(AccessAdminCase):
    def test_a_request_authenticated_while_switching_off_does_not_get_in(self):
        """认令牌（有 await）期间关掉了：进 SDK 之前再挡一次。"""
        real = access.verify

        def slow(token):
            result = real(token)
            access.set_switch(False)
            self.gate.closings += 1          # 页面关开关时 disconnect_all 做的
            time.sleep(0.01)
            return result

        with patch.object(access, "verify", side_effect=slow):
            refused = self.http.post("/mcp", json=INIT, headers=bearer(self.secret))
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(self.gate.tracker.live(self.token["id"]), 0)


if __name__ == "__main__":
    unittest.main()
