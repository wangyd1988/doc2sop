"""页面审批（应用这一层）、防跨站请求伪造、工作台汇总。

审批接口接一个真起的工具服务（deploy/ops_readonly.py 的 Handler）：口令原样转交、由工具服务核对，状态码原样转回页面；
口令不出现在任何回复和日志里（请求体手动解析，FastAPI 的 422 会回显输入）。
/api/ 下会改状态的请求，带了别的网站的 Origin（没有就看 Referer）一律 403；同源的页面、不带这两个头的 curl 照常。
"""
import contextlib
import io
import json
import logging
import os
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import tests.support  # noqa: F401
from tests.support import clear_graph

from app import graph, main as app_main, playbooks, workbench
from app.agent import ops_client
from app.config import WEB_PASSWORD, WEB_USER
from app.main import PAGES, app, cross_site

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    import importlib.util
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

POSIX = os.name == "posix"
PASS = "correct horse battery staple"
WRONG = "not the passphrase at all"
NEW = "a brand new approval passphrase"
CONFIG = "tools:\n  - {name: one, desc: 看内存, binary: free, argv: [free, -m], params: {}}\n"
FORM = {"name": "pod_list", "label": "看 Pod", "desc": "列出 Pod", "binary": "kubectl",
        "argv": ["kubectl", "get", "pods", "-A"], "params": {}}


class _WithOps(unittest.TestCase):
    """真起一个工具服务，应用的 ops_client 指向它。"""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        self.main.write_text(CONFIG, encoding="utf-8")
        (self.dir / "scripts").mkdir()
        self.passfile = self.dir / "approval.hash"
        self.printed = io.StringIO()
        redirect = contextlib.redirect_stdout(self.printed)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        patchers = [
            patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
                                    "mmtime": None, "includes": [], "tools": {}, "problems": [], "mcp_servers": {},
                                    "connections": {}, "hosts": None, "held": []}),
            patch.dict(ops._approval, {"failures": 0, "locked_until": 0.0, "logged": None}),
            patch.dict(ops.SCRYPT_PARAMS, {"p": 1}),
            patch.dict(os.environ, {"OPS_APPROVAL_FILE": str(self.passfile), "OPS_CLI": ""}),
            patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"),
            patch.object(ops._monitor, "wake", lambda: None),
            patch.object(ops.Handler, "token", "t0k"),
        ]
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

    def set_passphrase(self, text=PASS):
        ops._write_private(str(self.passfile), json.dumps(ops.new_approval_record(text)))

    def propose(self, tool=None):
        return ops.propose_tool(dict(tool or FORM))

    def post(self, path, body=None, **kwargs):
        if body is not None:
            kwargs["json"] = body
        return self.client.post(path, auth=self.auth, **kwargs)

    def assertNoPassphrase(self, *texts):
        for text in texts + (self.printed.getvalue(),):
            self.assertNotIn(PASS, text)
            self.assertNotIn(WRONG, text)
            self.assertNotIn(NEW, text)


class ApprovalProxyTests(_WithOps):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def test_approve_passes_the_tool_services_answer_through(self):
        item = self.propose()
        with self.assertLogs("kb", level="DEBUG") as logs:
            wrong = self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": WRONG})
            right = self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": PASS})
        self.assertEqual((wrong.status_code, wrong.json()["detail"]), (403, "审批口令不对，还能再试 4 次"))
        self.assertEqual(right.status_code, 200, right.text)
        body = right.json()
        self.assertEqual(body["tool"]["name"], "pod_list")
        self.assertEqual(self.main.read_text(encoding="utf-8").splitlines()[body["written"]["line"] - 1],
                         "  - name: pod_list")
        self.assertIn("pod_list", ops.all_tools())
        self.assertIn(f"caller=web user={WEB_USER} ip=testclient", self.printed.getvalue())
        self.assertNoPassphrase(wrong.text, right.text, "\n".join(logs.output))

    def test_bad_bodies_are_refused_without_echoing_anything(self):
        item = self.propose()
        url = f"/api/tools/pending/{item['id']}/approve"
        cases = [
            (self.post(url, content=('{"passphrase": "' + PASS + '",').encode(),
                       headers={"Content-Type": "application/json"}), 400, "请求体不是合法 JSON"),
            (self.post(url, {"passphrase": 12345}), 400, "没有输入审批口令"),
            (self.post(url, [PASS]), 400, "请求体必须是 JSON 对象"),
            (self.post(url, {"passphrase": PASS, "pad": "x" * (app_main.APPROVAL_BODY_MAX + 1)}), 413, "请求体太大"),
            (self.post("/api/tools/propose-approve", {"tool": {**FORM, "name": "x" * 80}, "passphrase": PASS}),
             400, "申请内容不合法"),
        ]
        for response, status, needle in cases:
            with self.subTest(needle=needle):
                self.assertEqual(response.status_code, status, response.text)
                self.assertIn(needle, response.json()["detail"])
                self.assertNoPassphrase(response.text)
        self.assertEqual(ops._approval["failures"], 0)
        self.assertEqual(len(ops.list_pending()), 1)

    def test_lock_and_unset_states_reach_the_page_with_their_codes(self):
        item = self.propose()
        url = f"/api/tools/pending/{item['id']}/approve"
        codes = [self.post(url, {"passphrase": WRONG}).status_code for _ in range(5)]
        self.assertEqual(codes, [403, 403, 403, 403, 423])
        self.assertEqual(self.post(url, {"passphrase": PASS}).status_code, 423)
        status = self.client.get("/api/tools/approval", auth=self.auth).json()
        self.assertEqual((status["locked"], status["unlock_minutes"]), (True, 15))
        self.passfile.unlink()
        with patch.dict(ops._approval, {"failures": 0, "locked_until": 0.0}):
            response = self.post(url, {"passphrase": PASS})
        self.assertEqual(response.status_code, 409)
        self.assertIn("set-approval-passphrase", response.json()["detail"])

    def test_propose_and_approve_in_one_step(self):
        wrong = self.post("/api/tools/propose-approve", {"tool": FORM, "passphrase": WRONG})
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(ops.list_pending(), [])
        right = self.post("/api/tools/propose-approve", {"tool": FORM, "passphrase": PASS})
        self.assertEqual(right.status_code, 200, right.text)
        self.assertEqual(right.json()["tool"]["name"], "pod_list")
        self.assertEqual(ops.list_pending(), [])
        self.assertEqual(ops.all_tools()["pod_list"]["argv"], FORM["argv"])
        self.assertNoPassphrase(wrong.text, right.text)

    def test_a_failed_write_after_queueing_tells_the_page_which_request_is_left(self):
        with patch.object(ops, "_check_insertion", side_effect=ops.ConfigError("插入后的加载结果不对")):
            response = self.post("/api/tools/propose-approve", {"tool": FORM, "passphrase": PASS})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["pending"], ops.list_pending()[0]["id"])
        self.assertIn("申请已提交", response.json()["detail"])

    def test_reject_and_the_pending_list(self):
        script = self.dir / "scripts" / "report.sh"
        script.write_text("#!/bin/sh\ndf -h\n", encoding="utf-8", newline="\n")
        script.chmod(0o755)
        self.main.write_text(CONFIG + "  - {name: disk_report, desc: 磁盘, script: report.sh}\n", encoding="utf-8")
        ops.refresh(force=True)
        item = self.propose()
        listed = self.client.get("/api/tools/pending", auth=self.auth).json()
        self.assertEqual(set(listed), {"pending", "held", "approval"})
        self.assertEqual(listed["pending"][0]["detail"]["kind"], "command")
        self.assertEqual(listed["held"][0]["script"], "report.sh")
        self.assertTrue(listed["approval"]["configured"])
        rejected = self.post(f"/api/tools/pending/{item['id']}/reject")
        self.assertEqual(rejected.json(), {"rejected": "pod_list", "id": item["id"]})
        self.assertEqual(self.post(f"/api/tools/pending/{item['id']}/reject").status_code, 404)
        trust = self.post("/api/tools/scripts/report.sh/trust", {"passphrase": PASS, "sha256": listed["held"][0]["sha256"]})
        self.assertEqual(trust.status_code, 200, trust.text)
        self.assertEqual(trust.json()["usable"], ["disk_report"])
        self.assertEqual(self.post("/api/tools/scripts/report.sh/trust",
                                   {"passphrase": PASS, "sha256": listed["held"][0]["sha256"]}).status_code, 404)

    def test_an_unreachable_or_old_tool_service(self):
        item = self.propose()
        with patch.object(ops_client, "OPS_URL", "http://127.0.0.1:9"):
            response = self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": PASS})
            self.assertEqual(response.status_code, 502)
            listed = self.client.get("/api/tools/pending", auth=self.auth).json()
            self.assertFalse(listed["approval"]["configured"])

        def old(path, payload=None, timeout=30, headers=None):
            if path in ("/tools/review", "/tools/approval", "/tools/approve"):
                raise ops_client.OpsUnavailable("Not found", status=404)
            return {"pending": [item]}

        with patch.object(ops_client, "_request", side_effect=old):
            listed = self.client.get("/api/tools/pending", auth=self.auth).json()
            self.assertEqual(listed["pending"], [item])
            self.assertEqual(listed["approval"]["problem"], ops_client.OLD_SERVICE)
            response = self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": PASS})
            self.assertEqual((response.status_code, response.json()["detail"]), (501, ops_client.OLD_SERVICE))


class SetPassphraseProxyTests(_WithOps):
    """页面上设置、修改审批口令：应用只转交（手动解析请求体，不回显、不记日志），只多查一条「不能和网页登录密码相同」。"""

    URL = "/api/tools/approval/passphrase"

    def test_set_the_first_time_then_change_with_the_current_one(self):
        with self.assertLogs("kb", level="DEBUG") as logs:
            first = self.post(self.URL, {"new": PASS})
            again = self.post(self.URL, {"new": NEW})
            wrong = self.post(self.URL, {"new": NEW, "current": WRONG})
            right = self.post(self.URL, {"new": NEW, "current": PASS})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["first"])
        approval = first.json()["approval"]
        self.assertEqual((approval["configured"], approval["set_by"], approval["set_from"]), (True, "page", "testclient"))
        self.assertEqual(again.status_code, 409)
        self.assertIn("要改得先输旧口令", again.json()["detail"])
        self.assertEqual((wrong.status_code, wrong.json()["detail"]), (403, "审批口令不对，还能再试 4 次"))
        self.assertEqual(right.status_code, 200, right.text)
        self.assertFalse(right.json()["first"])
        self.assertIsNone(ops.check_passphrase(NEW, "批准", "x"))
        status = self.client.get("/api/tools/approval", auth=self.auth).json()
        self.assertEqual((status["configured"], status["set_by"], status["page_set"]), (True, "page", True))
        self.assertIn(f"首次设置了审批口令 caller=web user={WEB_USER} ip=testclient", self.printed.getvalue())
        self.assertIn(f"修改了审批口令 caller=web user={WEB_USER} ip=testclient", self.printed.getvalue())
        self.assertNoPassphrase(first.text, again.text, wrong.text, right.text, "\n".join(logs.output))

    def test_wrong_current_passphrases_lock_like_approvals(self):
        self.set_passphrase()
        item = self.propose()
        codes = [self.post(self.URL, {"new": NEW, "current": WRONG}).status_code for _ in range(3)]
        codes += [self.post(f"/api/tools/pending/{item['id']}/approve", {"passphrase": WRONG}).status_code
                  for _ in range(2)]
        self.assertEqual(codes, [403, 403, 403, 403, 423])
        locked = self.post(self.URL, {"new": NEW, "current": PASS})
        self.assertEqual(locked.status_code, 423)
        self.assertIn("分钟后解锁", locked.json()["detail"])
        status = self.client.get("/api/tools/approval", auth=self.auth).json()
        self.assertEqual((status["locked"], status["unlock_minutes"]), (True, 15))
        self.assertNoPassphrase(locked.text)

    def test_the_new_passphrase_cannot_be_the_web_password(self):
        response = self.post(self.URL, {"new": WEB_PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertIn("不能和网页登录密码相同", response.json()["detail"])
        self.assertNotIn(WEB_PASSWORD, response.text)
        self.assertFalse(self.passfile.exists())
        self.set_passphrase()
        response = self.post(self.URL, {"new": WEB_PASSWORD, "current": PASS})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ops._approval["failures"], 0)   # 在应用这一层就拦下，不经过口令核对
        self.assertIsNone(ops.check_passphrase(PASS, "批准", "x"))

    def test_bad_bodies_are_refused_without_echoing_or_logging_anything(self):
        short = "tiny-secret"   # 11 个字符：工具服务拒绝，回复里也不带它
        with self.assertLogs("kb", level="DEBUG") as logs:
            cases = [
                (self.post(self.URL, content=('{"new": "' + NEW + '", "current": "' + PASS + '",').encode(),
                           headers={"Content-Type": "application/json"}), 400, "请求体不是合法 JSON"),
                (self.post(self.URL, {"new": 123456789012345}), 400, "没有输入新的审批口令"),
                (self.post(self.URL, {"current": PASS}), 400, "没有输入新的审批口令"),
                (self.post(self.URL, {"new": NEW, "current": ["x"]}), 400, "旧口令必须是文本"),
                (self.post(self.URL, [NEW]), 400, "请求体必须是 JSON 对象"),
                (self.post(self.URL, {"new": NEW, "pad": "x" * (app_main.APPROVAL_BODY_MAX + 1)}), 413, "请求体太大"),
                (self.post(self.URL, {"new": short}), 400, "至少 12 个字符"),
            ]
            app_main.log.info("marker")   # assertLogs 要求至少一条
        output = "\n".join(logs.output)
        for response, status, needle in cases:
            with self.subTest(needle=needle):
                self.assertEqual(response.status_code, status, response.text)
                self.assertIn(needle, response.json()["detail"])
                self.assertNoPassphrase(response.text)
                self.assertNotIn(short, response.text)
        self.assertNoPassphrase(output)
        self.assertNotIn(short, output + self.printed.getvalue())
        self.assertFalse(self.passfile.exists())

    def test_cross_site_requests_are_refused(self):
        response = self.post(self.URL, {"new": NEW}, headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("跨站请求被拒绝", response.json()["detail"])
        self.assertFalse(self.passfile.exists())
        self.assertEqual(self.post(self.URL, {"new": NEW}, headers={"Referer": "http://evil.example/x"}).status_code, 403)
        self.assertFalse(self.passfile.exists())
        same = self.post(self.URL, {"new": NEW}, headers={"Origin": "http://testserver"})
        self.assertEqual(same.status_code, 200, same.text)

    def test_an_old_tool_service_degrades(self):
        """上一版工具服务：有 /tools/approval，没有设置口令的接口——状态里没有 page_set，页面不给表单；硬发过去回 501。"""
        previous = {"configured": False, "locked": False, "unlock_minutes": 0, "problem": "", "max_failures": 5,
                    "lock_minutes": 15, "command": "python3 /opt/ops/ops_readonly.py set-approval-passphrase"}

        def old(path, payload=None, timeout=30, headers=None):
            if path == "/tools/approval":
                return {"approval": previous}
            raise ops_client.OpsUnavailable("Not found", status=404)

        with patch.object(ops_client, "_request", side_effect=old):
            status = self.client.get("/api/tools/approval", auth=self.auth).json()
            self.assertFalse(status.get("page_set"))
            response = self.post(self.URL, {"new": NEW})
        self.assertEqual((response.status_code, response.json()["detail"]), (501, ops_client.OLD_SERVICE_SET))
        self.assertIn("工具服务版本较旧", ops_client.OLD_SERVICE_SET)
        self.assertNoPassphrase(response.text)
        with patch.object(ops_client, "OPS_URL", "http://127.0.0.1:9"):   # 连不上：502，带着原因
            response = self.post(self.URL, {"new": NEW})
        self.assertEqual(response.status_code, 502)
        self.assertFalse(self.passfile.exists())


class OverviewTests(_WithOps):
    def setUp(self):
        super().setUp()
        clear_graph()

    def test_the_workbench_summary(self):
        self.propose()
        hosts = {"configured": True, "list": {
            "local": {"via": "local"},
            "gw": {"via": "ssh", "status": {"reachable": False, "error": "主机 gw：主机 gw 的 host key 还没登记"}},
            "db": {"via": "ssh", "status": {"reachable": True, "error": ""}},
            "new": {"via": "ssh", "status": None}}}
        described = ops_client.describe_tools()
        with patch.object(ops_client, "describe_tools", return_value={**described, "hosts": hosts}):
            data = self.client.get("/api/overview", auth=self.auth).json()
        self.assertEqual(set(data), {"knowledge", "tools", "sops", "access", "approval", "pending", "recent",
                                     "examples", "tool_labels"})
        self.assertEqual([t["name"] for t in data["pending"]["tools"]], ["pod_list"])
        self.assertEqual(data["pending"]["tools"][0]["kind"], "command")
        self.assertEqual(data["pending"]["hosts"], [{"name": "gw", "error": "host key 还没登记"}])
        self.assertEqual((data["tools"]["hosts"]["total"], data["tools"]["hosts"]["online"]), (4, 2))
        self.assertEqual(data["tools"]["sources"]["hosts"], 3)
        self.assertFalse(data["approval"]["configured"])
        self.assertEqual(data["tool_labels"]["one"], "one")

    def test_examples_without_packs_come_from_docs_tools_and_live_sops(self):
        book = playbooks.save(None, "内存巡检", "内存紧张时", [{"tool": "one", "args": {}, "checkpoint": "看可用内存",
                                                             "evidence": "先看内存"}], {"one"}, enabled=True)
        self.addCleanup(playbooks.delete, book)
        knowledge = {"documents": 2, "chunks": 9, "categories": [{"name": "运维手册", "documents": 2}]}
        items = workbench.examples(knowledge, {"one": "看内存"}, playbooks.usable({"one"}), {"one": "内存"})
        kinds = {item["kind"] for item in items}
        self.assertLessEqual({"knowledge", "data", "sop"}, kinds)
        sop = next(item for item in items if item["kind"] == "sop")
        self.assertEqual(sop["playbook"], {"id": book, "name": "内存巡检"})
        self.assertIn("用「内存」查一下", next(item for item in items if item["kind"] == "data")["text"])
        self.assertIn("「运维手册」", " ".join(item["text"] for item in items))

    def test_host_reasons_drop_the_repeated_name(self):
        self.assertEqual(workbench.host_reason("gw", "主机 gw：主机 gw 的 host key 还没登记"), "host key 还没登记")
        self.assertEqual(workbench.host_reason("gw", "连不上：超时"), "连不上：超时")
        self.assertEqual(workbench.host_reason("gw", ""), "连不上")

    def test_recent_conversations_say_which_sop_and_how_many_data_calls(self):
        from app import conversations
        book = playbooks.save(None, "内存巡检", "内存紧张时", [{"tool": "one", "args": {}, "checkpoint": "看可用内存",
                                                             "evidence": "先看内存"}], {"one"}, enabled=True)
        self.addCleanup(playbooks.delete, book)
        conv = conversations.create("内存够不够")
        self.addCleanup(conversations.delete, conv["id"])
        conversations.add_message(conv["id"], "user", "内存够不够")
        run = graph.start_execution(conv["id"], "内存够不够", book)
        for tool in ("one", "kb_search", "one"):
            graph.record_tool_call(run, tool, {}, "输出", True, 5)
        graph.finish_execution(run, "够", message_id=conversations.add_message(conv["id"], "assistant", "够"))
        recent = next(item for item in workbench._recent() if item["id"] == conv["id"])
        self.assertEqual((recent["playbook"], recent["calls"]), ("内存巡检", 2))   # kb_search 是知识类，不算


class SameOriginTests(unittest.TestCase):
    """别的网站借浏览器里缓存的 Basic 凭据发写请求：Origin（没有就看 Referer）和 Host 对不上就 403。"""

    def setUp(self):
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def test_cross_site_writes_are_refused_before_anything_else(self):
        for method, path in (("POST", "/api/proposals/p1/approve"), ("POST", "/api/tools/pending/a1/approve"),
                             ("DELETE", "/api/documents/x.md"), ("POST", "/api/tools/propose-approve"),
                             ("POST", "/api/tools/approval/passphrase"), ("POST", "/api/ask"), ("PUT", "/api/settings")):
            with self.subTest(path=path):
                response = self.client.request(method, path, auth=self.auth, headers={"Origin": "https://evil.example"})
                self.assertEqual(response.status_code, 403)
                self.assertIn("跨站请求被拒绝", response.json()["detail"])
        # 没有登录也是 403：在认证之前就拦下
        self.assertEqual(self.client.post("/api/proposals/p1/approve", headers={"Origin": "http://evil.example"})
                         .status_code, 403)

    def test_referer_is_the_fallback_and_null_origins_are_cross_site(self):
        refused = self.client.post("/api/proposals/p1/reject", auth=self.auth,
                                   headers={"Referer": "http://evil.example/page.html"})
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(self.client.post("/api/proposals/p1/reject", auth=self.auth,
                                          headers={"Origin": "null"}).status_code, 403)

    def test_same_origin_pages_and_plain_clients_pass(self):
        for headers in ({"Origin": "http://testserver"}, {"Referer": "http://testserver/tools?tab=pending"}, {}):
            with self.subTest(headers=headers):
                response = self.client.post("/api/proposals/p1/approve", auth=self.auth, headers=headers)
                self.assertEqual(response.status_code, 404)   # 过了中间件，提议不存在
        response = self.client.get("/api/conversations", auth=self.auth, headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 200)        # 只读请求不拦

    def test_host_and_port_matching(self):
        def blocked(origin, host, method="POST", path="/api/x"):
            return cross_site(method, path, {"origin": origin, "host": host})

        self.assertFalse(blocked("http://kb.internal:8765", "kb.internal:8765"))
        self.assertTrue(blocked("http://kb.internal:9000", "kb.internal:8765"))      # 同主机的别的端口也算跨站
        self.assertFalse(blocked("https://kb.example.com", "kb.example.com"))       # 反向代理：默认端口省掉
        self.assertFalse(blocked("http://KB.Example.com", "kb.example.com:80"))
        self.assertFalse(blocked("http://[::1]:8765", "[::1]:8765"))
        self.assertTrue(blocked("http://127.0.0.1:8765", "localhost:8765"))
        self.assertTrue(blocked("javascript:alert(1)", "kb.internal"))
        self.assertTrue(blocked("http://kb.internal", ""))
        self.assertFalse(blocked("https://evil.example", "kb.internal", method="GET"))
        self.assertFalse(blocked("https://evil.example", "kb.internal", method="HEAD"))
        self.assertFalse(blocked("https://evil.example", "kb.internal", path="/mcp"))   # 对外 MCP 自己拒绝带 Origin 的
        self.assertTrue(blocked("https://evil.example", "kb.internal", method="OPTIONS"))
        self.assertFalse(cross_site("POST", "/api/x", {"host": "kb.internal"}))         # curl：两个头都没有

    def test_the_middleware_can_be_built_the_old_starlette_way(self):
        """老版本的 Starlette 用 cls(app=…) 建中间件：参数名不对整个应用都起不来。"""
        inner = object()
        self.assertIs(app_main.SameOriginOnly(app=inner).app, inner)
        self.assertIs(app_main.SameOriginOnly(inner).app, inner)


class PageTests(unittest.TestCase):
    def test_every_nav_page_serves_the_single_page_app(self):
        client = TestClient(app)
        self.addCleanup(client.close)
        for path in ("/",) + PAGES:
            with self.subTest(path=path):
                response = client.get(path, auth=(WEB_USER, WEB_PASSWORD))
                self.assertEqual(response.status_code, 200)
                self.assertIn('<nav id="side">', response.text)

    def test_the_page_uses_the_real_approval_endpoints_and_wording(self):
        page = (REPO / "app" / "web" / "index.html").read_text(encoding="utf-8")
        for needle in ("/api/overview", "/api/tools/pending", "/api/tools/propose-approve", "/api/tools/approval",
                       "/api/tools/approval/passphrase", 'autocomplete="${auto}"', "'current-password'",
                       "'new-password'", "data-setpass", "还没设审批口令", "忘了口令",
                       "没有检测到风险", "id=\"navRecent\"", "homePlaceholder", "unlock_minutes", "data-pb"):
            self.assertIn(needle, page)
        for gone in ("无风险", "/api/tools/held", "locked_until", "只读不写"):
            self.assertNotIn(gone, page)


if __name__ == "__main__":
    unittest.main()
