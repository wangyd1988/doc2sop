"""工具服务「只核对口令」的接口（POST /tools/approval/verify）：应用自己存的、由口令把关的设置（自动执行的发件邮箱、
收件组、告警令牌）存之前先来这里核对。和批准共用输错计数、锁定；不合规的请求和 OPS_PAGE_CONFIG=off 不算一次尝试；
GET 同一个地址只回「页面配置开没开」，给应用探测新旧，要令牌。口令不进任何输出。
"""
import contextlib
import io
import json
import os
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch

from tests.test_page_approval import COMMAND, PASS, WRONG, _Page, ops, quiet

CALLER = "web user=admin ip=10.1.2.3"


def verify(passphrase, action="邮件设置", target="发件服务器 smtp.qq.com:465", **extra):
    return quiet(ops.page_verify, {"passphrase": passphrase, "action": action, "target": target, **extra}, CALLER)


class VerifyTests(_Page):
    def setUp(self):
        super().setUp()
        self.set_passphrase()

    def test_the_right_passphrase_passes_and_nothing_is_written(self):
        before = sorted(p.name for p in self.dir.rglob("*"))
        result, printed = verify(PASS)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(sorted(p.name for p in self.dir.rglob("*")), before)
        lines = [line for line in printed.splitlines() if line.startswith("[approval]")]
        self.assertEqual(lines, [f"[approval] 邮件设置 发件服务器 smtp.qq.com:465：口令正确 caller={CALLER}"])

    def test_wrong_passphrases_share_the_lockout_with_approvals(self):
        for left in (4, 3, 2):
            error, _ = verify(WRONG)
            self.assertEqual((error.status, str(error)), (403, f"审批口令不对，还能再试 {left} 次"))
        item = self.propose(COMMAND)
        error, _ = quiet(ops.page_approve, {"id": item["id"], "passphrase": WRONG}, CALLER)
        self.assertEqual(error.status, 403)                      # 第 4 次，记在同一个计数上
        error, _ = verify(WRONG)
        self.assertEqual(error.status, 423)                      # 第 5 次：锁定
        error, printed = verify(PASS)
        self.assertEqual(error.status, 423)                      # 锁定中，对的也不核对
        self.assertIn("没有核对", printed)
        error, _ = quiet(ops.page_approve, {"id": item["id"], "passphrase": PASS}, CALLER)
        self.assertEqual(error.status, 423)                      # 批准那边也锁着
        with patch.object(ops.time, "time", return_value=time.time() + ops.APPROVAL_LOCK + 1):
            self.assertEqual(verify(PASS)[0], {"ok": True})

    def test_malformed_requests_are_refused_before_any_attempt_is_counted(self):
        for payload in ({"passphrase": WRONG, "target": "x"},                          # 缺 action
                        {"passphrase": WRONG, "action": "邮件设置"},                   # 缺 target
                        {"passphrase": WRONG, "action": "  ", "target": "x"},          # action 是空的
                        {"passphrase": WRONG, "action": "a" * 41, "target": "x"},
                        {"passphrase": WRONG, "action": "邮件设置", "target": "x" * 121},
                        {"passphrase": WRONG, "action": "邮件设置\n[approval] 伪造", "target": "x"},
                        {"passphrase": WRONG, "action": "邮件设置", "target": "x\u2028y"},
                        {"passphrase": WRONG, "action": 1, "target": "x"}):
            error, printed = quiet(ops.page_verify, payload, CALLER)
            self.assertIsInstance(error, ops.ConfigError, payload)
            self.assertNotIsInstance(error, ops.Forbidden)
            self.assertNotIn("[approval]", printed)
        error, _ = verify("")
        self.assertEqual((error.status, str(error)), (400, "没有输入审批口令"))
        self.assertEqual(ops._approval["failures"], 0)
        error, _ = verify(WRONG)
        self.assertEqual(str(error), "审批口令不对，还能再试 4 次")      # 前面的都没算

    def test_page_config_off_refuses_without_checking(self):
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            error, printed = verify(WRONG)
        self.assertIsInstance(error, ops.Forbidden)
        self.assertIn("OPS_PAGE_CONFIG=off", str(error))
        self.assertEqual((ops._approval["failures"], printed), (0, ""))

    def test_an_unset_passphrase_is_409(self):
        self.passfile.unlink()
        error, printed = verify(PASS)
        self.assertEqual(error.status, 409)
        self.assertIn("还没有设置审批口令", str(error))
        self.assertIn("没有核对", printed)


class VerifyHttpTests(_Page):
    def setUp(self):
        super().setUp()
        self.set_passphrase()
        server = ops.ThreadingHTTPServer(("127.0.0.1", 0), ops.Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}"
        token = patch.object(ops.Handler, "token", "t0k")
        token.start()
        self.addCleanup(token.stop)
        self.printed = io.StringIO()
        redirect = contextlib.redirect_stdout(self.printed)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def http(self, path, payload=None, token="t0k"):
        request = urllib.request.Request(self.url + path, json.dumps(payload).encode() if payload is not None else None,
                                         {"X-Ops-Token": token, "Content-Type": "application/json",
                                          "X-Ops-Caller": CALLER})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_post_and_get_over_http(self):
        body = {"passphrase": PASS, "action": "邮件设置", "target": "收件组 运维值班"}
        self.assertEqual(self.http("/tools/approval/verify", body, token="bad")[0], 401)
        self.assertEqual(self.http("/tools/approval/verify", token="bad")[0], 401)       # GET 也要令牌
        self.assertEqual(self.http("/tools/approval/verify"), (200, {"page_config": True}))
        self.assertEqual(self.http("/tools/approval/verify", body), (200, {"ok": True}))
        self.assertEqual(self.http("/tools/approval/verify", {**body, "passphrase": WRONG}),
                         (403, {"error": "审批口令不对，还能再试 4 次"}))
        self.assertEqual(self.http("/tools/approval/verify", {**body, "action": ""})[0], 400)
        with patch.dict(os.environ, {"OPS_PAGE_CONFIG": "off"}):
            self.assertEqual(self.http("/tools/approval/verify"), (200, {"page_config": False}))
            status, answer = self.http("/tools/approval/verify", body)
            self.assertEqual(status, 403)
            self.assertIn("OPS_PAGE_CONFIG=off", answer["error"])
        log = self.printed.getvalue()
        self.assertIn(f"[approval] 邮件设置 收件组 运维值班：口令正确 caller={CALLER}", log)
        self.assertNotIn(PASS, log)
        self.assertNotIn(WRONG, log)
        self.assertEqual(log.count("[approval]"), 2)          # GET、令牌错、字段错、开关关着都不记