"""工具与部署机解耦（第 1 期）：工具 = 能力 + 实现。

覆盖：分层写法 impl 的解析（与老写法等价、不认识的字段整条拒绝）、内置函数（date_info 与 GNU date 逐字一致）、
os 判断（不适用 ≠ 缺命令）、连接与凭据引用（短名字、老写法、脱敏）、页面按实现类型申请（不查本机 PATH，
builtin / MCP 不能申请，接口只能借已有连接带凭据）。
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph  # noqa: F401  (sets env before app imports)

from app import packs, playbooks
from app.agent import ops_client
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)

DATE_FORMAT = "+%Y-%m-%d %A 第%V周"
# 改造前 date_info 的定义（命令型），对照用
LEGACY_DATE_INFO = {"name": "date_info", "label": "日期是星期几", "group": "日历",
                    "desc": "查某个日期是星期几、当年第几周。推算请假天数、跨周末时用它，不要自己心算星期。",
                    "binary": "date", "argv": ["date", "-d", "{day}", DATE_FORMAT],
                    "params": {"day": {"type": "str", "pattern": "date", "required": True,
                                       "desc": "日期，格式 YYYY-MM-DD"}}}


class _Configured(unittest.TestCase):
    """每个用例一份临时主配置；工具服务的全局状态在用例结束后还原。"""

    MAIN = "tools: []\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        patcher = patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None,
                                          "imtime": None, "mmtime": None, "includes": [], "tools": {},
                                          "problems": [], "mcp_servers": {}, "connections": {}})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.write(self.MAIN)

    def write(self, body):
        self.main.write_text(body, encoding="utf-8")
        ops.refresh(force=True)
        return ops._state["tools"], ops._state["problems"]

    def assertProblem(self, needle):
        self.assertTrue(any(needle in p for p in ops._state["problems"]), ops._state["problems"])

    def check_error(self, raw, needle):
        with self.assertRaises(ops.ConfigError) as caught:
            ops._check_tool(raw)
        self.assertIn(needle, str(caught.exception))


# --- 分层写法 -----------------------------------------------------------------------

class ImplFormatTests(_Configured):
    PARAMS = {"name": {"type": "str", "pattern": "name", "required": True, "desc": "容器名"}}

    def test_layered_entries_load_exactly_like_their_legacy_twins(self):
        script = self.dir / "scripts" / "check.sh"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        os.chmod(script, 0o755)
        pairs = [
            ({"name": "logs", "binary": "docker", "argv": ["docker", "logs", "{name}"], "os": "linux",
              "params": self.PARAMS},
             {"name": "logs", "impl": {"type": "command", "argv": ["docker", "logs", "{name}"], "os": "linux"},
              "params": self.PARAMS}),
            ({"name": "item", "http": {"url": "https://api.example.com/items/{name}", "query": {"lang": "zh"},
                                       "pick": ["data.title"]}, "params": self.PARAMS},
             {"name": "item", "impl": {"type": "http", "url": "https://api.example.com/items/{name}",
                                       "query": {"lang": "zh"}, "pick": ["data.title"]}, "params": self.PARAMS}),
            ({"name": "cal", "mcp": {"server": "holiday", "tool": "holiday_calendar"}},
             {"name": "cal", "impl": {"type": "mcp", "server": "holiday", "tool": "holiday_calendar"}}),
            ({"name": "health", "script": "check.sh", "group": "容器", "os": ["linux"]},
             {"name": "health", "impl": {"type": "script", "script": "check.sh", "os": ["linux"]}, "group": "容器"}),
        ]
        for legacy, layered in pairs:
            with self.subTest(tool=legacy["name"]):
                self.assertEqual(ops._check_tool(layered), ops._check_tool(legacy))

    def test_unknown_impl_fields_reject_the_entry_instead_of_being_ignored(self):
        """via: ssh 被悄悄忽略、当成本机执行，比加载失败危险得多。"""
        self.check_error({"name": "disk", "impl": {"type": "command", "argv": ["df", "-h"], "via": "ssh"}}, "via")
        self.check_error({"name": "q", "impl": {"type": "http", "url": "https://a.example/x", "target": "db1"}},
                         "target")
        self.check_error({"name": "d", "impl": {"type": "sql", "query": "SELECT 1"}}, "只能是")
        self.check_error({"name": "d", "impl": "builtin"}, "必须是映射")

    def test_the_two_spellings_cannot_be_mixed(self):
        self.check_error({"name": "disk", "binary": "df", "impl": {"type": "command", "argv": ["df", "-h"]}},
                         "只能选一种")

    def test_os_belongs_to_command_and_script_implementations(self):
        self.check_error({"name": "disk", "os": "linux", "impl": {"type": "command", "argv": ["df", "-h"]}},
                         "写在 impl 里")
        self.check_error({"name": "x", "os": "linux", "http": {"url": "https://a.example/x"}}, "不能声明 os")
        self.check_error({"name": "x", "os": "linux", "mcp": {"server": "s", "tool": "t"}}, "不能声明 os")
        self.check_error({"name": "x", "impl": {"type": "builtin", "func": "date_info", "os": "linux"}}, "os")
        self.check_error({"name": "x", "binary": "df", "argv": ["df"], "os": "solaris"}, "linux、darwin、windows")
        spec = ops._check_tool({"name": "x", "binary": "df", "argv": ["df"], "os": ["Linux", "darwin", "linux"]})
        self.assertEqual(spec["os"], ["linux", "darwin"])
        self.assertEqual(ops._check_tool({"name": "x", "binary": "df", "argv": ["df"]})["os"], [])

    def test_layered_commands_keep_every_safety_rule(self):
        self.check_error({"name": "x", "impl": {"type": "command", "argv": ["bash", "-c", "id"]}}, "能执行任意命令")
        self.check_error({"name": "x", "impl": {"type": "command", "argv": ["docker", "rm", "a"]}}, "写操作")
        self.check_error({"name": "x", "impl": {"type": "command", "argv": ["cat", "{p}"]}}, "未声明的参数")
        self.check_error({"name": "x", "impl": {"type": "command", "binary": "docker", "argv": ["bash", "-c", "id"]}},
                         "第一项")
        self.check_error({"name": "x", "impl": {"type": "command", "argv": []}}, "非空列表")

    def test_interpreters_are_caught_behind_paths_suffixes_and_versions(self):
        for binary in ("/bin/bash", "/usr/bin/python3.12", "C:\\Tools\\bash.exe", "perl5.36", "/usr/bin/env",
                       "/usr/bin/python3.13t", "python3.7m", "python3-dbg", "/usr/bin/python3.12-dbg", "pypy3",
                       "busybox", "cmd.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pwsh"):
            with self.subTest(binary=binary):
                self.check_error({"name": "x", "binary": binary, "argv": [binary, "-c", "id"]}, "能执行任意命令")
        for binary in ("df", "/usr/bin/df", "docker", "kubectl", "ip6tables", "smartctl"):
            with self.subTest(binary=binary):
                self.assertEqual(ops._check_tool({"name": "x", "binary": binary, "argv": [binary]})["binary"], binary)

    def test_a_huge_proposal_cannot_stall_the_service(self):
        """页面申请的 binary、argv 没有长度上限：校验只能是线性的，太长的直接拒绝。"""
        started = time.monotonic()
        self.assertFalse(ops._interpreter("1" * 200000 + "x"))
        self.check_error({"name": "x", "impl": {"type": "command", "binary": "1" * 200000 + "x", "argv": ["df"]}},
                         "太长")
        self.check_error({"name": "x", "impl": {"type": "command", "argv": ["df", "a" * 5000]}}, "太长")
        self.check_error({"name": "x", "impl": {"type": "command", "argv": ["df"] * 65}}, "太长")
        self.assertLess(time.monotonic() - started, 2)

    def test_one_bad_layered_entry_does_not_drop_the_others(self):
        tools, problems = self.write(
            "tools:\n"
            "  - {name: good, impl: {type: command, argv: [free, -m]}}\n"
            "  - {name: bad, impl: {type: command, argv: [free, -m], via: ssh}}\n")
        self.assertEqual(sorted(tools), ["good"])
        self.assertEqual(len(problems), 1)
        self.assertIn("via", problems[0])


# --- 内置函数 -----------------------------------------------------------------------

class BuiltinTests(_Configured):
    MAIN = ("tools:\n"
            "  - name: date_info\n"
            "    label: 日期是星期几\n"
            "    group: 日历\n"
            "    desc: 查某个日期是星期几、当年第几周。推算请假天数、跨周末时用它，不要自己心算星期。\n"
            "    impl: {type: builtin, func: date_info}\n"
            "    params:\n"
            "      day: {type: str, pattern: date, required: true, desc: 日期，格式 YYYY-MM-DD}\n")

    # 在 Ubuntu 24.04 上用 LC_ALL=C date -d DAY '+%Y-%m-%d %A 第%V周' 跑出来的结果
    GNU = {"2026-10-01": "2026-10-01 Thursday 第40周", "2026-01-01": "2026-01-01 Thursday 第01周",
           "2027-01-01": "2027-01-01 Friday 第53周", "2020-12-31": "2020-12-31 Thursday 第53周",
           "2021-01-03": "2021-01-03 Sunday 第53周", "2024-02-29": "2024-02-29 Thursday 第09周",
           "0999-01-01": "0999-01-01 Tuesday 第01周", "0001-01-01": "0001-01-01 Monday 第01周",
           "0000-01-01": "0000-01-01 Saturday 第52周", "9999-12-31": "9999-12-31 Friday 第52周"}

    def test_output_is_word_for_word_the_old_date_command(self):
        for day, expected in self.GNU.items():
            with self.subTest(day=day):
                result = ops.run_tool("date_info", {"day": day})
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["output"], expected)
                self.assertEqual(result["command"], f"内置函数 date_info(day={day})")

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("date"), "需要 Linux 上的 GNU date")
    def test_output_matches_gnu_date_day_by_day(self):
        """目标平台上逐日对照：跨三个年头（含 53 周的年份）外加世纪、闰年和极端年份。"""
        if "GNU" not in subprocess.run(["date", "--version"], capture_output=True, text=True).stdout:
            self.skipTest("不是 GNU date")
        days = [(date(2024, 12, 1) + timedelta(n)).isoformat() for n in range(800)]
        days += ["0000-01-01", "0000-02-29", "0001-01-01", "0999-12-31", "1900-03-01", "2000-02-29", "9999-12-31"]
        env = {**os.environ, "LC_ALL": "C"}
        done = subprocess.run(["date", "-f", "-", DATE_FORMAT], input="\n".join(days) + "\n",
                              capture_output=True, encoding="utf-8", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        expected = done.stdout.splitlines()
        self.assertEqual(len(expected), len(days))
        for day, line in zip(days, expected):
            self.assertEqual(ops._builtin_date_info({"day": day}), line, day)
        for bad in ("2026-02-30", "2025-02-29", "2026-13-01", "2026-00-10", "2026-10-00"):
            with self.subTest(bad=bad):
                gnu = subprocess.run(["date", "-d", bad, DATE_FORMAT], capture_output=True, env=env)
                self.assertNotEqual(gnu.returncode, 0)
                self.assertFalse(ops.run_tool("date_info", {"day": bad})["ok"])

    def test_bad_input_fails_cleanly(self):
        for args, needle in [({"day": "2026-02-30"}, "日期不存在：2026-02-30"),
                             ({"day": "2026-10-01; rm -rf /"}, "不合法"),
                             ({"day": "20261001"}, "不合法"),
                             ({}, "缺少必填参数：day")]:
            with self.subTest(args=args):
                result = ops.run_tool("date_info", args)
                self.assertFalse(result["ok"])
                self.assertIn(needle, result["error"])

    def test_needs_no_command_and_runs_on_any_os(self):
        def no_processes(*args, **kwargs):
            raise AssertionError("内置函数不该起子进程")

        for host in ("linux", "darwin", "windows"):
            with self.subTest(host=host), patch.object(ops, "HOST_OS", host), \
                    patch.object(ops.shutil, "which", return_value=None), \
                    patch.object(ops.subprocess, "run", no_processes):
                self.assertIn("date_info", ops.available_tools())
                described = ops.describe_tools()["date_info"]
                self.assertEqual((described["type"], described["runnable"], described["builtin"]),
                                 ("builtin", True, "date_info"))
                self.assertEqual(described["command"], "内置函数 date_info")
                self.assertTrue(ops.run_tool("date_info", {"day": "2026-10-01"})["ok"])

    def test_advertised_exactly_like_the_old_date_command(self):
        """/tools 只增不改：换成内置实现后，模型和应用看到的 date_info 一个字段都不变。"""
        new = ops.available_tools()["date_info"]
        self.write(json.dumps({"tools": [LEGACY_DATE_INFO]}, ensure_ascii=False))
        with patch.object(ops.shutil, "which", return_value="/usr/bin/date"):
            old = ops.available_tools()["date_info"]
        self.assertEqual(new, old)

    def test_params_must_match_the_function(self):
        base = {"name": "d", "impl": {"type": "builtin", "func": "date_info"}}
        self.check_error({**base, "params": {"day": {"type": "int", "required": True}}}, "类型要和内置函数")
        self.check_error({**base, "params": {"day": {"type": "str", "pattern": "name", "required": True}}},
                         "类型要和内置函数")
        self.check_error({**base, "params": {"when": {"type": "str", "pattern": "date", "required": True}}},
                         "参数要和内置函数")
        self.check_error({**base, "params": {}}, "参数要和内置函数")
        self.check_error({"name": "d", "impl": {"type": "builtin", "func": "shell"}}, "不是内置函数")
        # 不写 params / label / desc：用函数自带的
        spec = ops._check_tool(base)
        self.assertEqual(spec["params"]["day"],
                         {"type": "str", "desc": "日期，格式 YYYY-MM-DD", "required": True, "pattern": "date"})
        self.assertEqual((spec["label"], spec["group"]), ("日期是星期几", "日历"))
        self.assertTrue(spec["desc"])
        # 写了的说明照用（场景包、主配置可以按自己的口吻改）
        spec = ops._check_tool({**base, "desc": "看星期", "params": {
            "day": {"type": "str", "pattern": "date", "required": True, "desc": "哪天"}}})
        self.assertEqual((spec["desc"], spec["params"]["day"]["desc"]), ("看星期", "哪天"))


# --- os -----------------------------------------------------------------------------

class OsTests(_Configured):
    MAIN = ("tools:\n"
            "  - {name: linux_only, os: linux, binary: free, argv: [free, -m]}\n"
            "  - {name: win_only, impl: {type: command, argv: [ipconfig, /all], os: windows}}\n"
            "  - {name: anywhere, binary: uptime, argv: [uptime]}\n")

    def run_quietly(self, name):
        with patch.object(ops.subprocess, "run", side_effect=AssertionError("不该执行")) as run:
            result = ops.run_tool(name, {})
        self.assertFalse(run.called)
        return result

    def test_a_tool_for_another_os_is_not_applicable_rather_than_missing(self):
        with patch.object(ops, "HOST_OS", "windows"), patch.object(ops.shutil, "which", return_value="C:\\x.exe"):
            self.assertEqual(sorted(ops.available_tools()), ["anywhere", "win_only"])
            described = ops.describe_tools()["linux_only"]
            self.assertEqual((described["runnable"], described["applicable"], described["os"]),
                             (False, False, ["linux"]))
            self.assertIn("不适用于这台机器", described["reason"])
            self.assertNotIn("本机没有", described["reason"])
            result = self.run_quietly("linux_only")
            self.assertFalse(result["ok"])
            self.assertIn("不适用于这台机器", result["error"])
            self.assertTrue(ops.describe_tools()["win_only"]["applicable"])

    def test_os_mismatch_is_reported_before_a_missing_command(self):
        with patch.object(ops, "HOST_OS", "windows"), patch.object(ops.shutil, "which", return_value=None):
            described = ops.describe_tools()
            self.assertIn("不适用于这台机器", described["linux_only"]["reason"])
            self.assertEqual(described["anywhere"]["reason"], "本机没有 uptime，该工具不可用")
            self.assertTrue(described["anywhere"]["applicable"])

    def test_a_matching_os_behaves_exactly_as_before(self):
        class Done:
            returncode, stdout, stderr = 0, "Mem: 1", ""

        with patch.object(ops, "HOST_OS", "linux"), patch.object(ops.shutil, "which", return_value="/usr/bin/free"), \
                patch.object(ops.subprocess, "run", return_value=Done()) as run:
            self.assertEqual(sorted(ops.available_tools()), ["anywhere", "linux_only"])
            self.assertNotIn("reason", ops.describe_tools()["linux_only"])
            self.assertEqual(ops.run_tool("linux_only", {})["output"], "Mem: 1")
            self.assertEqual(run.call_args[0][0], ["free", "-m"])
        with patch.object(ops, "HOST_OS", "linux"):
            self.assertIn("不适用于这台机器", self.run_quietly("win_only")["error"])

    def test_os_lists_cover_several_systems(self):
        self.write("tools:\n  - {name: unixy, binary: uptime, argv: [uptime], os: [linux, darwin]}\n")
        with patch.object(ops.shutil, "which", return_value="/usr/bin/uptime"):
            for host, expected in (("linux", True), ("darwin", True), ("windows", False)):
                with self.subTest(host=host), patch.object(ops, "HOST_OS", host):
                    self.assertEqual("unixy" in ops.available_tools(), expected)

    def test_the_ops_inspection_pack_is_linux_only(self):
        self.write(f"include: [{(REPO / 'packs' / 'ops-inspection' / 'tools.yaml').as_posix()}]\ntools: []\n")
        with patch.object(ops.shutil, "which", return_value="/usr/bin/x"):
            with patch.object(ops, "HOST_OS", "windows"):
                self.assertEqual(ops.available_tools(), {})
                self.assertTrue(all(not t["applicable"] for t in ops.describe_tools().values()))
            with patch.object(ops, "HOST_OS", "linux"):
                self.assertEqual(sorted(ops.available_tools()),
                                 ["container_stats", "host_disk", "host_resources", "host_uptime", "list_containers"])


# --- 连接与凭据引用 -------------------------------------------------------------------

class ConnectionTests(_Configured):
    TOKEN, LEGACY, ENV_URL = "prom-secret-token-123", "legacy-secret-value", "https://prom.internal:9090"
    MAIN = ("connections:\n"
            "  - name: prom\n"
            "    type: http\n"
            "    label: 监控\n"
            "    base: https://prom.example.internal:9090/\n"
            "    headers: {Authorization: 'Bearer ${prom_token}', X-Legacy: '${OPS_SECRET_LEGACY}'}\n"
            "  - {name: prom_env, type: http, base: '${prom_url}/prefix'}\n"
            "tools:\n"
            "  - name: prom_up\n"
            "    impl: {type: http, conn: prom, url: /api/v1/query, query: {query: up},"
            " pick: ['data.result[].metric.instance']}\n"
            "  - name: prom_series\n"
            "    http: {conn: prom, url: '/api/v1/series/{job}', headers: {X-Legacy: fixed}}\n"
            "    params: {job: {type: str, pattern: name, required: true}}\n"
            "  - {name: via_env, impl: {type: http, conn: prom_env, url: /status}}\n")

    def setUp(self):
        env = patch.dict(ops.os.environ, {"OPS_SECRET_PROM_TOKEN": self.TOKEN, "OPS_SECRET_LEGACY": self.LEGACY,
                                          "OPS_SECRET_PROM_URL": self.ENV_URL, "OPS_TOKEN": "service-own-token"})
        env.start()
        self.addCleanup(env.stop)
        super().setUp()

    def test_tools_share_the_connection_address_and_credentials(self):
        self.assertEqual(ops._state["problems"], [])
        tools = ops.all_tools()
        url, headers, _ = ops.build_request(tools["prom_up"], {})
        self.assertEqual(url, "https://prom.example.internal:9090/api/v1/query?query=up")
        self.assertEqual((headers["Authorization"], headers["X-Legacy"]), ("Bearer " + self.TOKEN, self.LEGACY))
        url, headers, _ = ops.build_request(tools["prom_series"], {"job": "node"})
        self.assertEqual(url, "https://prom.example.internal:9090/api/v1/series/node")
        self.assertEqual(headers["X-Legacy"], "fixed")             # 工具自己写的同名请求头覆盖连接的
        self.assertEqual(headers["Authorization"], "Bearer " + self.TOKEN)
        with self.assertRaises(ValueError):
            ops.build_request(tools["prom_series"], {"job": "../admin"})
        url, _, used = ops.build_request(tools["via_env"], {})
        self.assertEqual(url, self.ENV_URL + "/prefix/status")
        self.assertIn(self.ENV_URL, used)                          # 来自凭据的地址也当敏感信息
        self.assertEqual(ops.describe_connections()["prom"]["used_by"], ["prom_series", "prom_up"])

    def test_credentials_are_named_not_spelled_out(self):
        self.assertEqual(ops._secret_env("prom_token"), "OPS_SECRET_PROM_TOKEN")
        self.assertEqual(ops._secret_env("OPS_SECRET_LEGACY"), "OPS_SECRET_LEGACY")
        for bad in ("OPS_TOKEN", "HOME", "Prom_Token"):
            with self.subTest(ref=bad):
                self.assertIsNone(ops._secret_env(bad))
                self.check_error({"name": "x", "http": {"url": "https://a.example/x",
                                                        "headers": {"Authorization": "Bearer ${%s}" % bad}}},
                                 ops.SECRET_PREFIX)
        # 短名字不只给连接用：普通接口工具、老写法的地址前缀照常
        _, problems = self.write(
            "tools:\n"
            "  - {name: short, http: {url: 'https://a.example/x', headers: {Authorization: 'Bearer ${prom_token}'}}}\n"
            "  - {name: legacy_base, http: {url: '${OPS_SECRET_PROM_URL}/x'}}\n")
        self.assertEqual(problems, [])
        _, headers, _ = ops.build_request(ops.all_tools()["short"], {})
        self.assertEqual(headers["Authorization"], "Bearer " + self.TOKEN)
        self.assertEqual(ops.build_request(ops.all_tools()["legacy_base"], {})[0], self.ENV_URL + "/x")

    def test_secrets_never_reach_the_model_the_page_or_errors(self):
        """接口把用到的凭据（含来自凭据的地址）回显出来，也到不了模型；页面上只有名字和模板。"""
        echoed = json.dumps({"data": {"result": [{"metric": {"instance": f"{self.TOKEN} {self.LEGACY}"}}]}})
        with patch.object(ops, "_http_get", return_value=(200, echoed.encode())):
            result = ops.run_tool("prom_up", {})
        with patch.object(ops, "_http_get", return_value=(200, f"served by {self.ENV_URL}".encode())):
            env_result = ops.run_tool("via_env", {})
        self.assertTrue(result["ok"] and env_result["ok"])
        self.assertIn("***", result["output"])
        self.assertEqual(env_result["output"], "served by ***")
        with patch.object(ops, "_http_get", side_effect=OSError(f"connect to {self.ENV_URL} failed")):
            failed = ops.run_tool("via_env", {})
        self.assertFalse(failed["ok"])
        page = {"tools": ops.describe_tools(), "connections": ops.describe_connections(),
                "advertised": ops.available_tools()}
        for text in (json.dumps(result, ensure_ascii=False), json.dumps(env_result, ensure_ascii=False),
                     json.dumps(failed, ensure_ascii=False), json.dumps(page, ensure_ascii=False)):
            for secret in (self.TOKEN, self.LEGACY, self.ENV_URL):
                self.assertNotIn(secret, text)
        # 页面看到的是名字和模板：连接的请求头只有名字
        self.assertEqual(page["connections"]["prom"],
                         {"type": "http", "label": "监控", "base": "https://prom.example.internal:9090",
                          "headers": ["Authorization", "X-Legacy"], "used_by": ["prom_series", "prom_up"]})
        self.assertEqual(page["connections"]["prom_env"]["base"], "${prom_url}/prefix")
        self.assertIn("Authorization", page["tools"]["prom_up"]["command"])
        self.assertIn("连接 prom", page["tools"]["prom_up"]["command"])
        self.assertEqual(page["tools"]["prom_up"]["conn"], "prom")

    def test_a_missing_credential_names_both_spellings(self):
        with patch.dict(ops.os.environ, {"OPS_SECRET_PROM_TOKEN": ""}):
            result = ops.run_tool("prom_up", {})
        self.assertFalse(result["ok"])
        self.assertIn("prom_token", result["error"])
        self.assertIn("OPS_SECRET_PROM_TOKEN", result["error"])
        with patch.dict(ops.os.environ, {"OPS_SECRET_PROM_URL": "ftp://files.internal"}):
            self.assertIn("不是合法的 http(s) 地址", ops.run_tool("via_env", {})["error"])

    def test_query_credentials_by_name_and_their_encoded_echoes_are_scrubbed(self):
        """${weather_key} 里的 {weather_key} 不是模型参数；放进查询串的凭据是编码过的，回显出来也要脱敏。"""
        key = "Ab+Cd/Ef=Gh123"
        _, problems = self.write(
            "tools:\n"
            "  - name: weather\n"
            "    http: {url: 'https://api.example.com/v1/now', query: {city: '{city}', key: '${weather_key}'}}\n"
            "    params: {city: {type: str, pattern: name, required: true}}\n"
            "  - {name: via_conn, impl: {type: http, conn: prom, url: /q, query: {token: '${prom_token}'}}}\n"
            "connections:\n  - {name: prom, type: http, base: 'https://prom.example.internal'}\n")
        self.assertEqual(problems, [])
        with patch.dict(ops.os.environ, {"OPS_SECRET_WEATHER_KEY": key}):
            url, _, _ = ops.build_request(ops.all_tools()["weather"], {"city": "beijing"})
            self.assertEqual(url, "https://api.example.com/v1/now?city=beijing&key=Ab%2BCd%2FEf%3DGh123")
            with patch.object(ops, "_http_get", side_effect=lambda u, h: (200, f"you asked {u}".encode())):
                result = ops.run_tool("weather", {"city": "beijing"})
        self.assertTrue(result["ok"])
        for text in (result["command"], result["output"]):
            self.assertNotIn("Ab%2BCd%2FEf%3DGh123", text)
            self.assertNotIn(key, text)
        self.assertIn("key=***", result["command"])
        url, _, _ = ops.build_request(ops.all_tools()["via_conn"], {})
        self.assertEqual(url, "https://prom.example.internal/q?token=" + self.TOKEN)

    def test_bad_connections_are_reported_and_skipped(self):
        self.write(
            "connections:\n"
            "  - {name: ok, type: http, base: 'https://ok.example/'}\n"
            "  - {name: ok, type: http, base: 'https://dup.example'}\n"
            "  - {name: Bad-Name, type: http, base: 'https://a.example'}\n"
            "  - {name: db, type: mysql, base: 'https://a.example'}\n"
            "  - {name: notype, base: 'https://a.example'}\n"
            "  - {name: param, type: http, base: 'https://{host}.example'}\n"
            "  - {name: query, type: http, base: 'https://a.example/x?y=1'}\n"
            "  - {name: userinfo, type: http, base: 'https://user:pass@a.example'}\n"
            "  - {name: hdr, type: http, base: 'https://a.example', headers: {X-User: '{who}'}}\n"
            "  - {name: own, type: http, base: 'https://a.example', headers: {X-T: '${OPS_TOKEN}'}}\n"
            "tools:\n"
            "  - {name: uses_ok, impl: {type: http, conn: ok, url: /x}}\n")
        self.assertEqual(sorted(ops._state["connections"]), ["ok"])
        self.assertEqual(ops._state["connections"]["ok"]["base"], "https://ok.example")
        for needle in ("连接名重复", "Bad-Name", "type 必须是 http", "主机名部分",
                       "不能带参数、查询串", "只能写固定值", ops.SECRET_PREFIX):
            with self.subTest(needle=needle):
                self.assertProblem(needle)
        self.assertEqual(len(ops._state["problems"]), 9)
        self.assertIn("uses_ok", ops.all_tools())
        self.write("connections: {prom: {base: 'https://a.example'}}\ntools: []\n")
        self.assertProblem("connections 必须是列表")

    def test_tools_cannot_reach_around_their_connection(self):
        self.check_error({"name": "x", "impl": {"type": "http", "conn": "prom", "url": "https://evil.example/x"}},
                         "只写路径")
        self.check_error({"name": "x", "impl": {"type": "http", "conn": "prom", "url": "/x?debug=1"}}, "查询串")
        self.check_error({"name": "x", "impl": {"type": "http", "conn": "Prom!", "url": "/x"}}, "conn 不合法")
        self.write("tools:\n  - {name: lost, impl: {type: http, conn: nope, url: /x}}\n"
                   "  - {name: fine, impl: {type: builtin, func: date_info}}\n")
        self.assertEqual(sorted(ops.all_tools()), ["fine"])
        self.assertProblem("未声明的连接 nope")

    def test_included_files_cannot_declare_connections(self):
        (self.dir / "pack.yaml").write_text(
            "connections:\n  - {name: sneaky, type: http, base: 'https://evil.example'}\n"
            "tools:\n"
            "  - {name: pack_up, impl: {type: http, conn: prom, url: /api/v1/query}}\n"
            "  - {name: pack_sneaky, impl: {type: http, conn: sneaky, url: /steal}}\n", encoding="utf-8")
        self.write("include: [pack.yaml]\n"
                   "connections:\n  - {name: prom, type: http, base: 'https://prom.example.internal:9090'}\n"
                   "tools: []\n")
        self.assertEqual(sorted(ops.all_tools()), ["pack_up"])     # 包里的工具可以借主文件的连接
        self.assertProblem("connections 已忽略")
        self.assertProblem("未声明的连接 sneaky")

    def test_a_shipped_pack_with_connections_is_flagged(self):
        root = self.dir / "packs"
        folder = root / "conn-pack"
        (folder / "docs").mkdir(parents=True)
        (folder / "docs" / "手册.md").write_text("# 手册", encoding="utf-8")
        (folder / "pack.yaml").write_text("id: conn-pack\nname: 包\nsummary: 一句话\nexamples: [问]\ncategory: 演示\n",
                                          encoding="utf-8")
        (folder / "tools.yaml").write_text(
            "connections:\n  - {name: x, type: http, base: 'https://a.example'}\n"
            "tools:\n  - {name: t_one, impl: {type: builtin, func: date_info}}\n"
            "  - {name: t_two, impl: {type: script, script: a.sh}}\n", encoding="utf-8")
        found = packs.discover(root)["conn-pack"]
        self.assertTrue(any("connections" in p for p in found["problems"]), found["problems"])
        self.assertTrue(any("t_two 是脚本型工具" in p for p in found["problems"]), found["problems"])
        self.assertEqual(found["tools"], ["t_one"])


# --- 页面按实现类型申请 ---------------------------------------------------------------

class ProposalTests(_Configured):
    MAIN = ("connections:\n"
            "  - {name: prom, type: http, base: 'https://prom.example.internal:9090',"
            " headers: {Authorization: 'Bearer ${prom_token}'}}\n"
            "tools:\n"
            "  - {name: existing, binary: uptime, argv: [uptime]}\n")
    COMMAND = {"name": "net_info", "label": "网卡", "desc": "看网卡配置",
               "impl": {"type": "command", "argv": ["ipconfig", "/all"], "os": ["windows"]}, "params": {}}
    HTTP = {"name": "prom_query", "desc": "查一个 PromQL",
            "impl": {"type": "http", "conn": "prom", "url": "/api/v1/query", "query": {"query": "{q}"}},
            "params": {"q": {"type": "str", "pattern": "name", "required": True, "desc": "指标名"}}}

    def setUp(self):
        env = patch.dict(ops.os.environ, {"OPS_SECRET_PROM_TOKEN": "prom-secret-token-123"})
        env.start()
        self.addCleanup(env.stop)
        super().setUp()
        # 证明申请不看本机 PATH：这台机器上什么命令都没有
        which = patch.object(ops.shutil, "which", return_value=None)
        which.start()
        self.addCleanup(which.stop)

    def test_command_proposals_declare_os_and_skip_the_path_check(self):
        item = ops.propose_tool(self.COMMAND)
        self.assertEqual(item["tool"]["impl"]["os"], ["windows"])
        self.assertNotIn("net_info", ops.all_tools())               # 批准前仍然惰性
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            ops._print_pending()
        self.assertIn("命令：ipconfig /all", printed.getvalue())
        self.assertIn("适用系统：windows", printed.getvalue())
        ops.approve_pending(item["id"])
        written = self.main.read_text(encoding="utf-8")
        self.assertIn("impl:", written)
        self.assertIn("connections:", written)                      # 追加不动原有内容
        with patch.object(ops, "HOST_OS", "linux"):
            described = ops.describe_tools()["net_info"]
            self.assertEqual((described["runnable"], described["applicable"]), (False, False))
            self.assertIn("不适用于这台机器", described["reason"])

    def test_http_proposals_borrow_credentials_only_through_a_connection(self):
        item = ops.propose_tool(self.HTTP)
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            ops._print_pending()
        self.assertIn("接口：GET [连接 prom] /api/v1/query?query={q}", printed.getvalue())
        ops.approve_pending(item["id"])
        url, headers, _ = ops.build_request(ops.all_tools()["prom_query"], {"q": "up"})
        self.assertEqual(url, "https://prom.example.internal:9090/api/v1/query?query=up")
        self.assertEqual(headers["Authorization"], "Bearer prom-secret-token-123")

    def test_http_proposals_still_cannot_carry_credentials(self):
        impl = self.HTTP["impl"]
        for bad, needle in [({**impl, "headers": {"Authorization": "x"}}, "请求头"),
                            ({**impl, "query": {"k": "${prom_token}"}}, "凭据"),
                            ({**impl, "notes": {"404": "x"}}, "notes"),
                            ({**impl, "url": "https://evil.example/x"}, "只写路径"),
                            ({**impl, "conn": "nope"}, "未声明的连接 nope")]:
            with self.subTest(needle=needle), self.assertRaises(ops.ConfigError) as caught:
                ops.propose_tool({**self.HTTP, "impl": bad})
            self.assertIn(needle, str(caught.exception))
        self.assertEqual(ops.list_pending(), [])

    def test_builtin_and_mcp_tools_cannot_be_proposed(self):
        for raw, needle in [({"impl": {"type": "builtin", "func": "date_info"}}, "内置函数"),
                            ({"impl": {"type": "mcp", "server": "s", "tool": "t"}}, "MCP"),
                            ({"mcp": {"server": "s", "tool": "t"}}, "MCP"),
                            ({"impl": {"type": "sql", "query": "SELECT 1"}}, "只能是")]:
            with self.subTest(raw=raw), self.assertRaises(ops.ConfigError) as caught:
                ops.propose_tool({"name": "nope", "desc": "x", **raw})
            self.assertIn(needle, str(caught.exception))
        self.assertEqual(ops.list_pending(), [])

    def test_form_errors_use_form_wording(self):
        with self.assertRaises(ops.ConfigError) as caught:
            ops.propose_tool({**self.COMMAND, "impl": {"type": "command", "argv": ["ipconfig"], "os": "beos"}})
        self.assertTrue(str(caught.exception).startswith("适用系统只能是"), str(caught.exception))
        with self.assertRaises(ops.ConfigError) as caught:
            ops.propose_tool({**self.COMMAND, "impl": {"type": "command", "argv": ["cat", "{p}"]}})
        self.assertIn("「参数」", str(caught.exception))

    def test_the_pages_legacy_shaped_payloads_carry_os_and_conn(self):
        """页面发的是老写法加 os / conn：工具服务按同样的规则校验，批准后和新写法效果一样。"""
        command = ops.propose_tool({"name": "ip_addr", "desc": "看网卡地址", "binary": "ip", "argv": ["ip", "addr"],
                                    "os": ["linux"], "params": {}})
        http = ops.propose_tool({"name": "prom_metric", "desc": "查指标", "params": self.HTTP["params"],
                                 "http": {"url": "/api/v1/query", "query": {"query": "{q}"}, "conn": "prom"}})
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            ops._print_pending()
        self.assertIn("命令：ip addr", printed.getvalue())
        self.assertIn("适用系统：linux", printed.getvalue())
        self.assertIn("接口：GET [连接 prom] /api/v1/query?query={q}", printed.getvalue())
        ops.approve_pending(command["id"])
        ops.approve_pending(http["id"])
        tools = ops.all_tools()
        self.assertEqual(tools["ip_addr"]["os"], ["linux"])
        self.assertEqual(tools["prom_metric"]["connection"]["name"], "prom")
        with self.assertRaises(ops.ConfigError):
            ops.propose_tool({"name": "bad_os", "desc": "x", "binary": "ip", "argv": ["ip"], "os": ["beos"]})

    def test_approval_rechecks_the_connection(self):
        item = ops.propose_tool(self.HTTP)
        self.write("tools:\n  - {name: existing, binary: uptime, argv: [uptime]}\n")   # 管理员删了连接
        with self.assertRaises(ops.ConfigError) as caught:
            ops.approve_pending(item["id"])
        self.assertIn("未声明的连接 prom", str(caught.exception))
        self.assertNotIn("prom_query", self.main.read_text(encoding="utf-8"))


class PageApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def test_the_page_proposes_by_implementation_type(self):
        """页面按实现类型分栏，发出去的是老写法加 os / conn：新老工具服务都认。新写法 impl 也照样转发。"""
        with patch.object(ops_client, "propose", return_value={"pending": {"id": "abc"}}) as propose:
            def sent(body):
                response = self.client.post("/api/tools/propose", json=body, auth=self.auth)
                self.assertEqual(response.status_code, 200, response.text)
                return propose.call_args[0][0]

            command = sent({"name": "net_info", "desc": "看网卡", "binary": "ip", "argv": ["ip", "addr"],
                            "os": ["linux"], "params": {}})
            self.assertEqual((command["binary"], command["argv"], command["os"]), ("ip", ["ip", "addr"], ["linux"]))
            self.assertFalse({"impl", "script", "http"} & set(command))
            plain = sent({"name": "who_is_on", "desc": "看登录用户", "binary": "who", "argv": ["who"], "params": {}})
            self.assertNotIn("os", plain)                       # 没勾适用系统就是不限，不往配置里写空列表
            http = sent({"name": "prom_metric", "desc": "查指标", "os": ["linux"], "params": {},
                         "http": {"url": "/api/v1/query", "query": {"query": "{metric}"}, "conn": "prom"}})
            self.assertEqual(http["http"]["conn"], "prom")
            self.assertFalse({"os", "binary", "argv", "impl"} & set(http))
            layered = sent({**ProposalTests.COMMAND, "binary": "stray", "argv": ["stray"], "os": ["linux"]})
            self.assertEqual(layered["impl"], ProposalTests.COMMAND["impl"])
            self.assertFalse({"binary", "argv", "script", "http", "os"} & set(layered))

    def test_the_overview_carries_connections_and_the_host_os(self):
        detail = {"tools": {"t": {"desc": "x", "enabled": True, "runnable": False, "applicable": False,
                                  "reason": "不适用于这台机器", "group": "g"}},
                  "connections": {"prom": {"type": "http", "label": "", "base": "${prom_url}",
                                           "headers": ["Authorization"], "used_by": []}},
                  "host": {"os": "linux"}, "pending": 0, "mcp_servers": {}}
        with patch.object(ops_client, "describe_tools", return_value=detail):
            got = self.client.get("/api/tools?group=g", auth=self.auth).json()
        self.assertEqual(got["connections"], detail["connections"])
        self.assertEqual(got["host"], {"os": "linux"})
        self.assertEqual(got["tools"]["t"]["reason"], "不适用于这台机器")
        self.assertEqual(got["live"], 0)


# --- 场景包 -------------------------------------------------------------------------

class LeavePackTests(_Configured):
    def test_the_leave_pack_runs_on_a_machine_without_gnu_date(self):
        """请假拼假包从此不要求 GNU date：一台什么命令都没有的 Windows 机器上，工具照常下发，SOP 一个字不改照常通过校验。"""
        self.write(f"include: [{(REPO / 'packs' / 'leave-planning' / 'tools.yaml').as_posix()}]\ntools: []\n")
        self.assertEqual(ops._state["problems"], [])
        with patch.object(ops, "HOST_OS", "windows"), patch.object(ops.shutil, "which", return_value=None):
            available = ops.available_tools()
            self.assertEqual(sorted(available), ["date_info", "holiday_calendar"])
            self.assertEqual(ops.all_tools()["date_info"]["type"], "builtin")
            self.assertEqual(ops.run_tool("date_info", {"day": "2026-10-08"})["output"], "2026-10-08 Thursday 第41周")
        for sop in json.loads((REPO / "packs" / "leave-planning" / "sops.json").read_text(encoding="utf-8")):
            _, _, steps = playbooks.validate(sop["name"], sop["trigger"], sop["steps"], set(available))
            self.assertEqual([s["tool"] for s in steps], ["holiday_calendar", "date_info"])


if __name__ == "__main__":
    unittest.main()
