"""MCP 第四种工具类型：最小 stdio 客户端、发现与审批、执行与校验。

被测对象是 deploy/ops_readonly.py 里的 MCP 分节，陪练是 deploy/mcp/holiday_mcp.py（纯标准库的
玩具 server）。所有用例都用当前解释器起 server 子进程，Windows 上同样能跑。
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("ops_readonly", ROOT / "deploy" / "ops_readonly.py")
ops = sys.modules.get("ops_readonly") or importlib.util.module_from_spec(_SPEC)
if "ops_readonly" not in sys.modules:
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

SERVER = str(ROOT / "deploy" / "mcp" / "holiday_mcp.py")


def server_config(**env):
    return {"label": "节假日", "command": sys.executable, "args": [SERVER],
            "env": {"HOLIDAY_MCP_TEST_HOOKS": "1", **env}, "cwd": ""}


class ClientTests(unittest.TestCase):
    """最小客户端：握手、分页列表、调用、超时、崩溃重拉、环境隔离。"""

    def setUp(self):
        self.server = ops.McpServer("holiday", server_config())
        self.addCleanup(self.server.stop)

    def test_initialize_then_list_with_pagination(self):
        self.server.start()
        self.assertTrue(self.server.online)
        self.assertEqual(self.server.protocol, "2025-06-18")
        self.assertEqual(self.server.server_info.get("name"), "holiday-mcp")
        # 玩具 server 每页 2 条，4 个工具要翻两页才拿全
        self.assertEqual(sorted(self.server.tools),
                         ["date_info", "delete_holiday", "echo", "holiday_calendar"])
        self.assertTrue(self.server.tools["holiday_calendar"]["annotations"]["readOnlyHint"])

    def test_call_returns_content_and_structured(self):
        result = self.server.call("date_info", {"day": "2026-10-01"})
        self.assertFalse(result["isError"])
        self.assertIn("星期四", result["content"][0]["text"])
        self.assertEqual(result["structuredContent"]["weekday"], 4)

    def test_server_side_error_is_raised(self):
        self.server.start()
        with self.assertRaises(ops.McpError) as caught:
            self.server.request("no/such/method")
        self.assertIn("-32601", str(caught.exception))

    def test_request_times_out_instead_of_hanging(self):
        self.server.start()
        started = time.monotonic()
        with self.assertRaises(ops.McpError) as caught:
            self.server.call("echo", {"text": "__hang__"}, timeout=1)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("超时", str(caught.exception))

    def test_crash_is_reported_and_next_call_relaunches(self):
        self.server.start()
        first_pid = self.server.proc.pid
        with self.assertRaises(ops.McpError) as caught:
            self.server.call("echo", {"text": "__crash__"})
        self.assertIn("退出", str(caught.exception))
        self.assertFalse(self.server.online)
        # 崩溃不是「连接失败」，不进退避：下一次调用直接重拉
        result = self.server.call("echo", {"text": "back"})
        self.assertEqual(result["content"][0]["text"], "back")
        self.assertNotEqual(self.server.proc.pid, first_pid)

    def test_child_env_excludes_service_credentials(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env_file = Path(tmp.name) / "env.json"
        with patch.dict(ops.os.environ, {"OPS_TOKEN": "service-token",
                                         "OPS_SECRET_GATEWAY_URL": "https://gw.example",
                                         "OPS_SECRET_HOLIDAY": "holiday-key-123456",
                                         "SOME_RANDOM_VAR": "leak-me"}):
            config = server_config(HOLIDAY_TOKEN="${OPS_SECRET_HOLIDAY}", PLAIN="x")
            config["args"] = config["args"] + ["--env-file", str(env_file)]
            server = ops.McpServer("holiday", config)
            self.addCleanup(server.stop)
            server.start()
        seen = json.loads(env_file.read_text(encoding="utf-8"))
        self.assertNotIn("OPS_TOKEN", seen)
        self.assertNotIn("OPS_SECRET_GATEWAY_URL", seen)
        self.assertNotIn("OPS_SECRET_HOLIDAY", seen)
        self.assertNotIn("SOME_RANDOM_VAR", seen)
        self.assertEqual(seen["HOLIDAY_TOKEN"], "holiday-key-123456")
        self.assertEqual(seen["PLAIN"], "x")
        self.assertIn("PATH", seen)
        # 解析出来的密钥值进了脱敏名单
        self.assertEqual(server.secrets, ["holiday-key-123456"])

    def test_missing_secret_is_a_clear_failure(self):
        with patch.dict(ops.os.environ, {}, clear=False):
            ops.os.environ.pop("OPS_SECRET_NOPE", None)
            server = ops.McpServer("holiday", server_config(TOKEN="${OPS_SECRET_NOPE}"))
            self.addCleanup(server.stop)
            with self.assertRaises(ops.McpError) as caught:
                server.start()
        self.assertIn("OPS_SECRET_NOPE", str(caught.exception))
        self.assertFalse(server.online)

    def test_missing_command_backs_off(self):
        server = ops.McpServer("ghost", {"label": "", "command": "no-such-mcp-binary-xyz",
                                         "args": [], "env": {}, "cwd": ""})
        with self.assertRaises(ops.McpError):
            server.start()
        self.assertEqual(server.failures, 1)
        self.assertGreater(server.next_retry, time.monotonic())
        # 退避期内再 start 直接报同一个原因，不会真的再去拉
        with self.assertRaises(ops.McpError) as caught:
            server.start()
        self.assertIn("no-such-mcp-binary-xyz", str(caught.exception))

    def test_stop_terminates_child(self):
        self.server.start()
        proc = self.server.proc
        self.server.stop()
        self.assertIsNotNone(proc.poll())
        self.assertFalse(self.server.alive())
        self.assertFalse(self.server.status()["online"])


class ServerConfigTests(unittest.TestCase):
    """mcp_servers 的结构校验。"""

    def check(self, raw):
        problems = []
        servers = ops._check_mcp_servers({"mcp_servers": raw}, problems)
        return servers, problems

    def test_good_entry(self):
        servers, problems = self.check({"holiday": {"command": "python3", "args": ["x.py"],
                                                    "env": {"TOKEN": "${OPS_SECRET_H}"},
                                                    "label": "节假日", "cwd": "/opt"}})
        self.assertEqual(problems, [])
        self.assertEqual(servers["holiday"]["label"], "节假日")
        self.assertEqual(servers["holiday"]["args"], ["x.py"])

    def test_bad_entries_are_skipped_not_fatal(self):
        servers, problems = self.check({
            "Bad-Id": {"command": "x"},
            "nocmd": {},
            "leak": {"command": "x", "env": {"TOKEN": "${OTHER_VAR}"}},
            "own": {"command": "x", "env": {"OPS_TOKEN": "abc"}},
            "ok": {"command": "x"}})
        self.assertEqual(list(servers), ["ok"])
        self.assertEqual(len(problems), 4)
        self.assertTrue(any("不合法" in p for p in problems))
        self.assertTrue(any("OPS_SECRET_" in p for p in problems))
        self.assertTrue(any("OPS_TOKEN" in p for p in problems))

    def test_registry_replaces_changed_server(self):
        registry = ops.McpRegistry()
        self.addCleanup(registry.shutdown)
        registry.configure({"a": {"label": "a", "command": "x", "args": [], "env": {}, "cwd": ""}})
        first = registry.get("a")
        registry.configure({"a": {"label": "a", "command": "x", "args": [], "env": {}, "cwd": ""}})
        self.assertIs(registry.get("a"), first)
        registry.configure({"a": {"label": "a", "command": "y", "args": [], "env": {}, "cwd": ""}})
        self.assertIsNot(registry.get("a"), first)
        registry.configure({})
        self.assertIsNone(registry.get("a"))


if __name__ == "__main__":
    unittest.main()
