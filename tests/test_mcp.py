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


class ApprovalFlowTests(unittest.TestCase):
    """发现 → pending → 宿主机批准 → 出现在 /tools。默认拒绝，每一步都要留下依据。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.main = Path(self.tmp.name) / "ops_tools.yaml"
        patcher = patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None,
                                          "tmtime": None, "imtime": None, "mmtime": None,
                                          "includes": [], "tools": {}, "problems": [],
                                          "mcp_servers": {}})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(lambda: ops._mcp.configure({}))
        self.write_main()

    def write_main(self, extra_env="", tools="tools: []\n", include=""):
        env = "{HOLIDAY_MCP_TEST_HOOKS: '1'" + (", " + extra_env if extra_env else "") + "}"
        body = (f"mcp_servers:\n  holiday:\n    label: 节假日\n    command: {json.dumps(sys.executable)}\n"
                f"    args: [{json.dumps(SERVER)}]\n    env: {env}\n" + include + tools)
        self.main.write_text(body, encoding="utf-8")
        # 同一秒内重写文件 mtime 可能不变，强制重载
        ops.refresh(force=True)

    def connect(self):
        ops._mcp.sync()
        return ops._mcp.get("holiday")

    def pending_by_name(self):
        return {(i.get("tool") or {}).get("name"): i for i in ops.list_pending()}

    def test_discovery_fills_pending_with_review_labels(self):
        server = self.connect()
        self.assertTrue(server.online)
        pending = self.pending_by_name()
        self.assertEqual(sorted(pending), ["holiday__date_info", "holiday__echo",
                                           "holiday__holiday_calendar"])
        calendar = pending["holiday__holiday_calendar"]
        self.assertEqual(calendar["author"], "mcp:holiday")
        self.assertEqual(calendar["review"], {"readonly": "declared", "suspicious_name": False,
                                              "reason": "新发现"})
        self.assertEqual(calendar["tool"]["mcp"], {"server": "holiday", "tool": "holiday_calendar"})
        self.assertEqual(calendar["tool"]["group"], "节假日")
        self.assertEqual(calendar["tool"]["label"], "法定节假日")
        self.assertTrue(calendar["tool"]["readonly_declared"])
        self.assertTrue(calendar["tool"]["schema_hash"].startswith("sha256:"))
        self.assertEqual(calendar["tool"]["params"] if "params" in calendar["tool"] else None, None)
        self.assertEqual(pending["holiday__echo"]["review"]["readonly"], "undeclared")
        # 破坏性工具连 pending 都不进，只在 server 备注里留一句
        self.assertTrue(any("delete_holiday" in n for n in server.notes))

    def test_discovery_is_idempotent(self):
        self.connect()
        first = ops.list_pending()
        ops._mcp.sync(force=True)
        self.assertEqual(ops.list_pending(), first)

    def test_unapproved_tools_are_invisible_and_not_executable(self):
        self.connect()
        self.assertEqual(ops.available_tools(), {})
        result = ops.run_tool("holiday__holiday_calendar", {"year": 2026})
        self.assertFalse(result["ok"])
        self.assertIn("未知工具", result["error"])

    def test_declared_readonly_tool_approves_without_flag(self):
        self.connect()
        spec = ops.approve_pending("holiday__holiday_calendar")
        self.assertEqual(spec["type"], "mcp")
        self.assertNotIn("holiday__holiday_calendar", self.pending_by_name())
        # 写进了兄弟文件，不碰手写主文件
        approved = ops._read_yaml(ops._mcp_file())["tools"]
        self.assertEqual([t["name"] for t in approved], ["holiday__holiday_calendar"])
        self.assertIn("approved_at", approved[0])
        self.assertEqual(ops._read_yaml(self.main)["tools"], [])
        listed = ops.available_tools()
        self.assertIn("holiday__holiday_calendar", listed)
        self.assertEqual(listed["holiday__holiday_calendar"]["input_schema"]["required"], ["year"])
        self.assertEqual(listed["holiday__holiday_calendar"]["params"]["year"]["type"], "int")
        full = ops.describe_tools()["holiday__holiday_calendar"]
        self.assertEqual(full["readonly"], "declared")
        self.assertTrue(full["runnable"])
        self.assertTrue(full["schema_locked"])
        self.assertEqual(full["command"], "MCP holiday / holiday_calendar")

    def test_undeclared_tool_needs_attestation(self):
        self.connect()
        with self.assertRaises(ops.ConfigError) as caught:
            ops.approve_pending("holiday__echo")
        self.assertIn("--attest-readonly", str(caught.exception))
        self.assertIn("holiday__echo", self.pending_by_name())
        spec = ops.approve_pending("holiday__echo", attest_readonly=True)
        self.assertTrue(spec["readonly_attested"])
        self.assertEqual(ops.describe_tools()["holiday__echo"]["readonly"], "attested")
        self.assertTrue(ops._read_yaml(ops._mcp_file())["tools"][0]["readonly_attested"])

    def test_schema_drift_disables_and_requeues(self):
        self.connect()
        ops.approve_pending("holiday__echo", attest_readonly=True)
        self.assertTrue(ops.describe_tools()["holiday__echo"]["runnable"])
        old_hash = ops._read_yaml(ops._mcp_file())["tools"][0]["schema_hash"]

        # server 升级：echo 多了一个参数。配置里 env 变了，server 会被重拉并重新发现
        self.write_main(extra_env="HOLIDAY_MCP_SCHEMA_VARIANT: '1'")
        self.connect()
        full = ops.describe_tools()["holiday__echo"]
        self.assertFalse(full["runnable"])
        self.assertEqual(full["reason"], "schema 已变更，需重新批准")
        self.assertNotIn("holiday__echo", ops.available_tools())
        item = self.pending_by_name()["holiday__echo"]
        self.assertEqual(item["review"]["reason"], "schema 已变更，需重新批准")
        self.assertNotEqual(item["tool"]["schema_hash"], old_hash)
        self.assertIn("times", item["tool"]["input_schema"]["properties"])

        # 重新批准 = 替换旧条目，不是多一条
        ops.approve_pending("holiday__echo", attest_readonly=True)
        approved = ops._read_yaml(ops._mcp_file())["tools"]
        self.assertEqual(len(approved), 1)
        self.assertNotEqual(approved[0]["schema_hash"], old_hash)
        self.assertTrue(ops.describe_tools()["holiday__echo"]["runnable"])

    def test_description_change_is_not_drift(self):
        tool = {"inputSchema": {"type": "object", "properties": {"a": {"type": "string",
                                                                      "description": "one"}}},
                "annotations": {"readOnlyHint": True}}
        changed = json.loads(json.dumps(tool))
        changed["inputSchema"]["properties"]["a"]["description"] = "two"
        changed["description"] = "new words"
        self.assertEqual(ops._mcp_hash(tool), ops._mcp_hash(changed))
        changed["inputSchema"]["properties"]["a"]["type"] = "integer"
        self.assertNotEqual(ops._mcp_hash(tool), ops._mcp_hash(changed))
        # 只读标注变了也算漂移：从只读变成不只读必须重新看
        flipped = json.loads(json.dumps(tool))
        flipped["annotations"]["readOnlyHint"] = False
        self.assertNotEqual(ops._mcp_hash(tool), ops._mcp_hash(flipped))

    def test_offline_server_keeps_tool_visible_but_not_available(self):
        self.connect()
        ops.approve_pending("holiday__holiday_calendar")
        ops._mcp.get("holiday").stop("测试：停掉")
        full = ops.describe_tools()["holiday__holiday_calendar"]
        self.assertFalse(full["runnable"])
        self.assertIn("离线", full["reason"])
        self.assertNotIn("holiday__holiday_calendar", ops.available_tools())
        status = ops.mcp_status()["holiday"]
        self.assertFalse(status["online"])
        self.assertEqual(status["approved"], 1)

    def test_handwritten_allowlist_entry_works_without_discovery(self):
        """管理员直接手写条目（名字自由）——拼假 SOP 不改一个字就能换成 MCP 来源。"""
        self.write_main(tools=(
            "tools:\n"
            "  - name: holiday_calendar\n"
            "    label: 法定节假日\n"
            "    group: 日历\n"
            "    desc: 法定节假日\n"
            "    mcp: {server: holiday, tool: holiday_calendar}\n"
            "  - name: date_info\n"
            "    desc: 星期几\n"
            "    mcp: {server: holiday, tool: date_info}\n"
            "    restrict: {day: {pattern: date}}\n"))
        self.connect()
        listed = ops.available_tools()
        self.assertIn("holiday_calendar", listed)
        self.assertIn("date_info", listed)
        full = ops.describe_tools()
        self.assertFalse(full["holiday_calendar"]["schema_locked"])
        self.assertEqual(full["holiday_calendar"]["readonly"], "declared")
        self.assertEqual(full["holiday_calendar"]["group"], "日历")
        self.assertEqual(full["date_info"]["group"], "节假日")   # 没写 group 就用 server 显示名
        self.assertEqual(full["date_info"]["params"]["day"]["pattern"], "date")
        # 手写过的两个不再重复进 pending；echo 还是要审
        self.assertEqual(sorted(self.pending_by_name()), ["holiday__echo"])

    def test_entry_for_unknown_server_is_skipped(self):
        self.write_main(tools="tools:\n  - name: x\n    desc: d\n    mcp: {server: ghost, tool: t}\n")
        self.assertNotIn("x", ops.all_tools())
        self.assertTrue(any("未声明的 MCP server ghost" in p for p in ops._state["problems"]))

    def test_included_file_cannot_declare_servers(self):
        included = Path(self.tmp.name) / "pack.yaml"
        included.write_text("mcp_servers:\n  evil: {command: rm}\ntools: []\n", encoding="utf-8")
        self.write_main(include="include: [pack.yaml]\n")
        self.assertIsNone(ops._mcp.get("evil"))
        self.assertTrue(any("mcp_servers 已忽略" in p for p in ops._state["problems"]))

    def test_web_cannot_propose_mcp_tools(self):
        with self.assertRaises(ops.ConfigError) as caught:
            ops.propose_tool({"name": "sneaky", "desc": "x", "mcp": {"server": "holiday", "tool": "echo"}})
        self.assertIn("页面不能申请 MCP 工具", str(caught.exception))

    def test_name_conversion_is_deterministic(self):
        self.assertEqual(ops._mcp_tool_name("gh", "list_issues"), "gh__list_issues")
        self.assertEqual(ops._mcp_tool_name("gh", "ListIssues"), "gh__list_issues")
        self.assertEqual(ops._mcp_tool_name("gh", "list-issues"), "gh__list_issues")
        self.assertEqual(ops._mcp_tool_name("gh", "123go"), "gh__t_123go")
        self.assertEqual(ops._mcp_tool_name("gh", "***"), "gh__tool")
        self.assertLessEqual(len(ops._mcp_tool_name("gh", "x" * 100)), 64)
        self.assertTrue(ops.TOOL_NAME.match(ops._mcp_tool_name("gh", "x" * 100)))
        self.assertTrue(ops._suspicious_name("deleteRepo"))
        self.assertTrue(ops._suspicious_name("create-issue"))
        self.assertFalse(ops._suspicious_name("list_issues"))


if __name__ == "__main__":
    unittest.main()
