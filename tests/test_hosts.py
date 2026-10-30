"""工具与部署机解耦（第 2 期）：远程主机。

覆盖：hosts 只认主文件、字段写错报错、凭据引用；target 的枚举和字符串两种形态、默认主机规则、@组展开和各项上限；
受控模式（工具名 + 参数 + 指纹，交给主机上的执行器）、直连模式的转义；host key 不认识或变了就失败、不降级；
私钥只按名字出现（不进日志、/tools 和页面）；enroll / push / status；不配 hosts 时一切照旧。
"""
import contextlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)
core = ops.ops_exec

POSIX = os.name == "posix"
REAL_RUN = subprocess.run      # _Hosts 把 subprocess.run 换成了假的；真要起进程的用例用它
# host key 的 base64（ssh-keyscan 给出的样子）
ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7"
TOOLS = textwrap.dedent("""\
    tools:
      - {name: host_disk, label: 磁盘用量, desc: 看磁盘, impl: {type: command, argv: [df, -h], os: linux}}
      - name: container_logs
        desc: 看日志
        impl: {type: command, argv: [docker, logs, --tail, "{lines}", "{name}"], os: linux}
        params:
          name: {type: str, pattern: name, required: true, desc: 容器名}
          lines: {type: int, default: 100, max: 500}
      - {name: gateway_only, desc: 网关专用, impl: {type: command, argv: [uptime], groups: [gateway]}}
      - {name: today, impl: {type: builtin, func: date_info}}
    """)
HOSTS = textwrap.dedent("""\
    hosts:
      defaults: {user: opsread, key: "${ssh_key}", os: linux}
      list:
        - {name: b, address: 10.0.0.2, groups: [gateway, prod]}
        - {name: c, address: 10.0.0.3, groups: [prod], mode: direct}
    """)


class FakeTransport:
    """假的 SSH。受控模式：请求交给进程内的执行器（和主机上跑的是同一份代码，白名单由 push 的生成函数给出）；
    直连模式：把命令行按 POSIX shell 的规则拆开再执行。记下每次调用和最大并发。"""

    def __init__(self, test):
        self.test = test
        self.calls, self.fail, self.allowlists = [], {}, {}
        self.delay, self.active, self.peak = 0.0, 0, 0
        self.lock = threading.Lock()

    def run(self, host, command, data=b"", timeout=None):
        with self.lock:
            self.calls.append((host["name"], command, data))
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            if host["name"] in self.fail:
                return self.fail[host["name"]]
            self.test.where.host = host["name"]
            if host["mode"] == "guarded":
                self.test.assertEqual(command, ops.GUARDED_COMMAND)
                text = self.allowlists.get(host["name"]) or ops.allowlist_for(host)
                tools, info, problems = core.parse_allowlist(json.loads(text))
                reply = core.handle(json.loads(data.decode("ascii")), tools, info, problems)
                return 0, (json.dumps(reply, ensure_ascii=True) + "\n").encode("ascii"), ""
            if command.startswith("for b in") or command.startswith("printf 'posix"):
                names = shlex.split(command.split(";")[0][len("for b in"):]) if command.startswith("for") else []
                out = "".join(f"have:{name}\n" for name in names if name != "kubectl") + "posix:42\n"
                return 0, out.encode(), ""
            done = core.run_argv(shlex.split(command), utf8=True)
            return done.get("exit_code", 1), done.get("output", "").encode("utf-8"), done.get("error", "")
        finally:
            self.test.where.host = "local"
            with self.lock:
                self.active -= 1


class _Hosts(unittest.TestCase):
    MAIN = TOOLS + HOSTS

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.main = self.dir / "ops_tools.yaml"
        self.where = threading.local()
        self.where.host = "local"
        self.ran = []
        self.transport = FakeTransport(self)
        self.wakes = []

        def fake_run(argv, **kwargs):
            host = getattr(self.where, "host", "local")
            self.ran.append((host, list(argv)))
            out = f"{host}: {' '.join(argv)}\n"
            return subprocess.CompletedProcess(argv, 0, out.encode() if "universal_newlines" not in kwargs else out, b""
                                               if "universal_newlines" not in kwargs else "")

        for patcher in (
                patch.dict(ops._state, {"path": self.main, "mtime": None, "omtime": None, "tmtime": None,
                                        "imtime": None, "mmtime": None, "includes": [], "tools": {}, "problems": [],
                                        "mcp_servers": {}, "connections": {}, "hosts": None}),
                patch.object(ops, "HOST_OS", "linux"),
                patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"),
                patch.object(ops.subprocess, "run", fake_run),
                patch.object(ops, "_transport", self.transport),
                patch.object(ops._monitor, "wake", lambda: self.wakes.append(1)),
                patch.dict(ops._host_status, {}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.write(self.MAIN)
        self.wakes.clear()

    def write(self, body):
        self.main.write_text(body, encoding="utf-8")
        ops.refresh(force=True)
        return ops._state["tools"], ops._state["problems"]

    def assertProblem(self, needle):
        self.assertTrue(any(needle in p for p in ops._state["problems"]), ops._state["problems"])

    def schema(self, name):
        return ops.available_tools()[name]["inputSchema"]


# --- 配置 ---------------------------------------------------------------------------

class LegacyTests(_Hosts):
    """不配 hosts：/tools 一个字段都不变，命令在本机跑；带了 target 的调用拒绝，而不是悄悄在本机执行。"""
    MAIN = TOOLS

    def test_no_hosts_means_no_target_and_local_execution(self):
        self.assertIsNone(ops._state["hosts"])
        tools = ops.available_tools()
        for name in ("host_disk", "container_logs", "gateway_only"):
            self.assertNotIn("target", tools[name]["params"])
            self.assertNotIn("target", tools[name]["inputSchema"]["properties"])
        result = ops.run_tool("host_disk", {})
        self.assertEqual((result["ok"], result["output"], "host" in result), (True, "local: df -h", False))
        self.assertEqual(ops.describe_hosts(), {"configured": False})
        self.assertNotIn("hosts", ops.describe_tools()["host_disk"])

    def test_a_target_without_a_host_list_is_refused(self):
        result = ops.run_tool("host_disk", {"target": "b"})
        self.assertFalse(result["ok"])
        self.assertIn("没有配置主机清单", result["error"])
        self.assertEqual(self.ran, [])
        self.assertTrue(ops.run_tool("host_disk", {"target": ""})["ok"])

    def test_a_tool_with_its_own_target_parameter_keeps_working(self):
        self.write("tools:\n  - {name: ping, binary: ping, argv: [ping, -c, '1', '{target}'],"
                   " params: {target: {type: str, pattern: name, required: true}}}\n")
        self.assertTrue(ops.run_tool("ping", {"target": "web01"})["ok"])
        self.assertEqual(self.ran[-1], ("local", ["ping", "-c", "1", "web01"]))


class ConfigTests(_Hosts):
    def test_a_valid_list_with_the_implicit_local_host(self):
        cfg = ops._state["hosts"]
        self.assertEqual(list(cfg["hosts"]), ["local", "b", "c"])
        self.assertEqual(cfg["default"], "local")
        self.assertEqual(cfg["groups"], {"gateway": ["b"], "prod": ["b", "c"], "all": ["local", "b", "c"]})
        b = cfg["hosts"]["b"]
        self.assertEqual((b["via"], b["user"], b["key"], b["os"], b["mode"], b["port"]),
                         ("ssh", "opsread", "ssh_key", "linux", "guarded", 22))
        self.assertEqual(cfg["hosts"]["c"]["mode"], "direct")
        self.assertEqual(ops._state["problems"], [])

    def test_only_the_main_file_may_declare_hosts(self):
        pack = self.dir / "pack.yaml"
        pack.write_text("hosts:\n  list: [{name: evil, address: 6.6.6.6, user: x, key: '${k}', os: linux}]\n"
                        "tools: []\n", encoding="utf-8")
        self.write(TOOLS.replace("tools:\n", f"include: [{pack.as_posix()}]\ntools:\n", 1))
        self.assertIsNone(ops._state["hosts"])
        self.assertProblem("hosts 已忽略")

    def test_wrong_fields_are_reported_and_the_host_skipped(self):
        bad = [
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, via: winrm}", "via 只能是"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, mode: yolo}", "mode 只能是"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: windows}", "Windows"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: solaris}", "要写 os"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}'}", "要写 os"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, port: 0}", "port"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, port: 'abc'}", "port"),
            ("{name: x, address: '-oProxyCommand=id', user: u, key: '${k}', os: linux}", "address 不合法"),
            ("{name: x, address: 'root@1.2.3.4', user: u, key: '${k}', os: linux}", "address 不合法"),
            ("{name: x, address: 1.2.3.4, user: '-u', key: '${k}', os: linux}", "user"),
            ("{name: x, address: 1.2.3.4, user: u, key: /root/.ssh/id_ed25519, os: linux}", "凭据引用"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${HOME}', os: linux}", "凭据引用"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, password: hunter2}", "不认识的字段"),
            ("{name: X_1, address: 1.2.3.4, user: u, key: '${k}', os: linux}", "主机名不合法"),
            ("{name: local, address: 1.2.3.4, user: u, key: '${k}', os: linux}", "local 留给本机"),
            ("{name: me, via: local, address: 1.2.3.4}", "不能写 address"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, groups: [all]}", "groups"),
            ("{name: x, address: 1.2.3.4, user: u, key: '${k}', os: linux, tools: [Bad-Name]}", "tools"),
        ]
        for entry, needle in bad:
            with self.subTest(entry=entry):
                self.write(TOOLS + f"hosts:\n  list:\n    - {entry}\n")
                self.assertNotIn("x", ops._state["hosts"]["hosts"])
                self.assertProblem(needle)

    def test_list_level_problems(self):
        self.write(TOOLS + textwrap.dedent("""\
            hosts:
              colour: blue
              enum_max: 0
              default: nowhere
              defaults: {user: u, key: "${k}", os: linux}
              list:
                - {name: b, address: 10.0.0.2}
                - {name: b, address: 10.0.0.9}
                - {name: a, via: local}
                - {name: a2, via: local}
                - {name: d, address: 10.0.0.4, tools: [no_such_tool]}
            """))
        cfg = ops._state["hosts"]
        self.assertEqual(list(cfg["hosts"]), ["b", "a", "d"])
        self.assertEqual((cfg["local"], cfg["default"], cfg["enum_max"]), ("a", "a", 30))
        for needle in ("不认识的字段 colour", "enum_max", "hosts.default", "主机名重复", "只能有一台", "不存在的工具"):
            self.assertProblem(needle)
        self.write(TOOLS + "hosts:\n  defaults: {name: x}\n  list: []\n")
        self.assertProblem("整个 defaults 已忽略")
        self.write(TOOLS + "hosts: [b]\n")
        self.assertEqual(list(ops._state["hosts"]["hosts"]), ["local"])
        self.assertProblem("已按只有本机处理")

    def test_target_is_reserved_for_command_tools_once_hosts_exist(self):
        self.write(TOOLS + "  - {name: ping, binary: ping, argv: [ping, '{target}'],"
                           " params: {target: {type: str, pattern: name, required: true}}}\n" + HOSTS)
        self.assertNotIn("ping", ops._state["tools"])
        self.assertProblem("这个名字是保留的")

    def test_tool_groups_belong_to_command_implementations(self):
        def error(raw, needle):
            with self.assertRaises(ops.ConfigError) as caught:
                ops._check_tool(raw)
            self.assertIn(needle, str(caught.exception))

        self.assertEqual(ops._check_tool({"name": "x", "binary": "df", "argv": ["df"], "groups": ["web"]})["groups"],
                         ["web"])
        self.assertEqual(ops._check_tool({"name": "x", "impl": {"type": "command", "argv": ["df"], "groups": "web"}})
                         ["groups"], ["web"])
        error({"name": "x", "groups": ["web"], "impl": {"type": "command", "argv": ["df"]}}, "写在 impl 里")
        error({"name": "x", "groups": ["web"], "http": {"url": "https://a.example/x"}}, "不是命令型工具")
        error({"name": "x", "binary": "df", "argv": ["df"], "groups": ["Web!"]}, "组名不合法")
        error({"name": "x", "binary": "df", "argv": ["df"], "groups": ["all"]}, "保留名")
        error({"name": "x", "impl": {"type": "http", "url": "https://a.example/x", "groups": ["w"]}}, "不认识的字段")
        self.assertEqual(ops._check_tool({"name": "x", "binary": "df", "argv": ["df"]})["groups"], [])


# --- target 参数 ------------------------------------------------------------------------

class TargetTests(_Hosts):
    def test_enum_form_marks_the_entity_and_defaults_to_this_machine(self):
        prop = self.schema("host_disk")["properties"]["target"]
        self.assertEqual(prop["enum"], ["local", "b", "c", "@gateway", "@prod", "@all"])
        self.assertEqual((prop["x-entity"], prop["x-default"], prop["type"]), ("host", "local", "string"))
        # 默认值只在说明和 x-default 里，不放进 schema 的 default：否则应用每次都把 local 填进去、记成出网污点
        self.assertNotIn("default", prop)
        self.assertIn("不填就是 local", prop["description"])
        self.assertNotIn("target", self.schema("host_disk").get("required", []))
        params = ops.available_tools()["host_disk"]["params"]["target"]
        self.assertEqual((params["type"], params["required"], "default" in params), ("enum", False, False))
        # 只在 gateway 组的主机上跑的工具：只剩 b 一台，b 就是它的默认
        prop = self.schema("gateway_only")["properties"]["target"]
        self.assertEqual((prop["enum"], prop["x-default"]), (["b", "@gateway", "@prod"], "b"))
        # 别的工具不受影响
        self.assertNotIn("target", self.schema("today")["properties"])
        self.assertNotIn(ops.LIST_TARGETS, ops.available_tools())

    def test_string_form_and_list_targets_beyond_the_threshold(self):
        self.write(self.MAIN.replace("hosts:\n", "hosts:\n  enum_max: 2\n"))
        prop = self.schema("host_disk")["properties"]["target"]
        self.assertNotIn("enum", prop)
        self.assertEqual(prop["pattern"], ops.HOST_REF.pattern)
        self.assertIn("list_targets", prop["description"])
        tools = ops.available_tools()
        self.assertIn(ops.LIST_TARGETS, tools)
        self.assertEqual(tools[ops.LIST_TARGETS]["_meta"]["doc2sop"]["category"], "data")
        listed = ops.run_tool(ops.LIST_TARGETS, {})
        self.assertTrue(listed["ok"])
        for needle in ("共 3 台", "b | linux | gateway,prod | 受控", "c | linux | prod | 直连", "local | linux | - | 本机",
                       "@prod（2 台）"):
            self.assertIn(needle, listed["output"])
        self.assertIn("@prod 里 2 台", ops.run_tool(ops.LIST_TARGETS, {"group": "@prod"})["output"])
        self.assertFalse(ops.run_tool(ops.LIST_TARGETS, {"group": "nope"})["ok"])
        self.assertTrue(ops.run_tool("host_disk", {"target": "b"})["ok"])

    def test_default_host_rules(self):
        cases = [
            # 不写 default：本机
            ("", "local", False),
            # 写了主机或组：用它
            ("  default: c\n", "c", False),
            ("  default: '@prod'\n", "@prod", False),
            # 没有本机、没写默认、能跑的不止一台：必填
            ("  local: false\n", None, True),
        ]
        for extra, default, required in cases:
            with self.subTest(extra=extra):
                self.write(self.MAIN.replace("hosts:\n", "hosts:\n" + extra))
                prop = self.schema("host_disk")["properties"]["target"]
                self.assertEqual(prop.get("x-default"), default)
                self.assertEqual("target" in self.schema("host_disk").get("required", []), required)
        # 本机不适用（工具服务跑在 Windows 上）：默认落到唯一能跑的远程主机……
        self.write(TOOLS + "hosts:\n  list:\n    - {name: b, address: 10.0.0.2, user: u, key: '${k}', os: linux}\n")
        with patch.object(ops, "HOST_OS", "windows"):
            prop = self.schema("host_disk")["properties"]["target"]
            self.assertEqual((prop["enum"], prop["x-default"]), (["b"], "b"))
            self.assertTrue(ops.run_tool("host_disk", {})["ok"])
            self.assertEqual(self.transport.calls[-1][0], "b")

    def test_omitting_a_required_target_is_refused(self):
        self.write(self.MAIN.replace("hosts:\n", "hosts:\n  local: false\n"))
        result = ops.run_tool("host_disk", {})
        self.assertFalse(result["ok"])
        self.assertIn("缺少必填参数：target", result["error"])
        self.assertIn("可选：b、c、@gateway、@prod、@all", result["error"])
        self.assertEqual(self.transport.calls, [])

    def test_unknown_or_malformed_targets(self):
        for target, needle in (("z", "没有主机 z"), ("@nope", "没有主机分组 @nope"), ("b;id", "不合法"),
                               ("-oProxyCommand=x", "不合法"), ("../b", "不合法")):
            with self.subTest(target=target):
                result = ops.run_tool("host_disk", {"target": target})
                self.assertFalse(result["ok"])
                self.assertIn(needle, result["error"])
        self.assertEqual(self.transport.calls, [])
        self.assertIn("不能在主机 local 上跑", ops.run_tool("gateway_only", {"target": "local"})["error"])

    def test_known_unavailable_hosts_drop_out_of_the_enum(self):
        ops.check_hosts()
        self.assertEqual(self.schema("host_disk")["properties"]["target"]["enum"],
                         ["local", "b", "c", "@gateway", "@prod", "@all"])
        # b 的白名单里没有 host_disk：确定不行，从枚举里拿掉；c 连不上：不确定，留着（调用时会拿到具体原因）
        b = ops._state["hosts"]["hosts"]["b"]
        spec = ops.all_tools()["container_logs"]
        self.transport.allowlists["b"] = core.render_allowlist("b", [("container_logs", spec["argv"], spec["params"])])
        self.transport.fail["c"] = (255, b"", "ssh: connect to host 10.0.0.3 port 22: Connection refused")
        ops.check_hosts()
        self.assertEqual(self.schema("host_disk")["properties"]["target"]["enum"], ["local", "c", "@prod", "@all"])
        states = ops.describe_tools()["host_disk"]["hosts"]
        self.assertEqual(states["b"]["state"], "no")
        self.assertIn("白名单里没有，需要 push", states["b"]["reason"])
        self.assertEqual(states["c"]["state"], "unknown")
        self.assertIn("Connection refused", states["c"]["reason"])
        self.assertEqual(ops._host_tool_state(spec, b), ("ok", ""))

    def test_an_omitted_target_never_drifts_to_another_host(self):
        """默认主机只按配置定：后台检查说它跑不了，不填 target 的调用照样去它那里、带着它的原因失败，不会悄悄换到本机。"""
        self.write(self.MAIN.replace("hosts:\n", "hosts:\n  default: b\n"))
        self.assertEqual(ops.run_tool("host_disk", {})["host"], "b")
        spec = ops.all_tools()["container_logs"]
        self.transport.allowlists["b"] = core.render_allowlist("b", [("container_logs", spec["argv"], spec["params"])])
        ops.check_hosts()
        self.assertEqual(ops._host_tool_state(ops.all_tools()["host_disk"], ops._state["hosts"]["hosts"]["b"])[0], "no")
        prop = self.schema("host_disk")["properties"]["target"]
        self.assertEqual(prop["x-default"], "b")
        self.assertIn("b", prop["enum"])      # 默认主机总在枚举里，schema 自洽
        calls = len(self.transport.calls)
        result = ops.run_tool("host_disk", {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["host"], "b")
        self.assertIn("没有开放工具 host_disk", result["error"])
        self.assertEqual(self.transport.calls[calls][0], "b")
        self.assertFalse([r for r in self.ran if r[0] == "local" and r[1][0] == "df"])

    def test_remote_calls_finish_before_the_app_gives_up(self):
        """应用等 /exec 30 秒：单台远程调用和整组调用都要在那之前给出结果。"""
        self.assertLess(ops.TIMEOUT + ops.SSH_SLACK, 30)
        self.assertLess(ops.GROUP_DEADLINE, 30)


# --- 执行 ---------------------------------------------------------------------------

class ExecutionTests(_Hosts):
    def test_the_default_target_runs_here_exactly_as_before(self):
        result = ops.run_tool("container_logs", {"name": "kb-app"})
        self.assertEqual(result, {"ok": True, "command": "docker logs --tail 100 kb-app",
                                  "output": "local: docker logs --tail 100 kb-app", "exit_code": 0, "host": "local"})
        self.assertEqual(self.transport.calls, [])

    def test_guarded_mode_sends_only_name_args_and_fingerprint(self):
        result = ops.run_tool("container_logs", {"name": "kb-app", "lines": 999, "target": "b"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["output"], "b: docker logs --tail 500 kb-app")
        self.assertEqual(result["host"], "b")
        host, command, data = self.transport.calls[-1]
        request = json.loads(data)
        self.assertEqual((host, command), ("b", ops.GUARDED_COMMAND))
        self.assertEqual(request, {"v": core.PROTOCOL, "op": "exec", "tool": "container_logs",
                                   "args": {"name": "kb-app", "lines": "500"},
                                   "fp": ops._fingerprint(ops.all_tools()["container_logs"])})
        # 参数在这边就挡住，不用连主机
        calls = len(self.transport.calls)
        self.assertIn("不合法", ops.run_tool("container_logs", {"name": "a;b", "target": "b"})["error"])
        self.assertEqual(len(self.transport.calls), calls)

    def test_a_stale_allowlist_is_refused_by_the_host(self):
        spec = ops.all_tools()["container_logs"]
        old = {**spec["params"], "lines": {**spec["params"]["lines"], "max": 200}}
        self.transport.allowlists["b"] = core.render_allowlist("b", [("container_logs", spec["argv"], old)])
        result = ops.run_tool("container_logs", {"name": "kb-app", "target": "b"})
        self.assertFalse(result["ok"])
        self.assertIn("重新 push", result["error"])
        self.assertEqual(self.wakes, [1])
        result = ops.run_tool("host_disk", {"target": "b"})
        self.assertIn("没有开放工具 host_disk", result["error"])

    def test_direct_mode_quotes_every_argument(self):
        result = ops.run_tool("container_logs", {"name": "kb-app", "target": "c"})
        self.assertTrue(result["ok"], result)
        host, command, data = self.transport.calls[-1]
        self.assertEqual((host, command, data), ("c", "docker logs --tail 100 kb-app", b""))
        self.assertEqual(result["output"], "c: docker logs --tail 100 kb-app")

    def test_host_failures_come_back_as_reasons(self):
        self.transport.fail["b"] = (255, b"", "@@@@@@@@@@@@@@@@\n@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\n"
                                              "Host key verification failed.")
        result = ops.run_tool("host_disk", {"target": "b"})
        self.assertFalse(result["ok"])
        self.assertIn("host key 和登记的不一致", result["error"])
        self.assertEqual(len(self.transport.calls), 1, "host key 不对时不能换个方式再试")
        self.transport.fail["b"] = (127, b"", "sh: 1: doc2sop-ops-exec: not found")
        self.assertIn("没有按受控模式回应", ops.run_tool("host_disk", {"target": "b"})["error"])
        self.transport.fail["c"] = (255, b"", "opsread@10.0.0.3: Permission denied (publickey).")
        self.assertIn("拒绝登录", ops.run_tool("host_disk", {"target": "c"})["error"])
        self.transport.fail["c"] = (127, b"", "sh: 1: df: not found")
        self.assertIn("主机 c 上没有 df", ops.run_tool("host_disk", {"target": "c"})["error"])

    def test_script_tools_only_run_here(self):
        (self.dir / "scripts").mkdir()
        script = self.dir / "scripts" / "check.sh"
        script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        os.chmod(script, 0o755)
        with patch.object(ops.os, "access", return_value=True):
            ops.trust_script("check.sh")
            self.write(self.MAIN.replace("tools:\n", "tools:\n  - {name: health, script: check.sh}\n", 1))
            self.assertNotIn("target", ops.available_tools()["health"]["inputSchema"]["properties"])
            self.assertTrue(ops.run_tool("health", {})["ok"])
            self.assertIn("只能在本机", ops.run_tool("health", {"target": "b"})["error"])
            self.write(self.MAIN.replace("tools:\n", "tools:\n  - {name: health, script: check.sh}\n", 1)
                       .replace("hosts:\n", "hosts:\n  local: false\n"))
            self.assertNotIn("health", ops.available_tools())
            self.assertIn("hosts.local: false", ops.run_tool("health", {})["error"])


class GroupTests(_Hosts):
    MAIN = TOOLS + textwrap.dedent("""\
        hosts:
          parallel: 2
          max_targets: 4
          defaults: {user: opsread, key: "${ssh_key}", os: linux}
          list:
            - {name: a, via: local, groups: [web]}
            - {name: w1, address: 10.0.1.1, groups: [web]}
            - {name: w2, address: 10.0.1.2, groups: [web], mode: direct}
            - {name: w3, address: 10.0.1.3, groups: [web]}
            - {name: mac, address: 10.0.1.9, groups: [web], os: darwin}
            - {name: big1, address: 10.0.2.1, groups: [big]}
            - {name: big2, address: 10.0.2.2, groups: [big]}
            - {name: big3, address: 10.0.2.3, groups: [big]}
            - {name: big4, address: 10.0.2.4, groups: [big]}
            - {name: big5, address: 10.0.2.5, groups: [big]}
        """)

    def test_a_group_runs_on_each_host_with_segments_and_a_summary(self):
        self.transport.delay = 0.05
        self.transport.fail["w3"] = (255, b"", "ssh: connect to host 10.0.1.3 port 22: Connection timed out")
        result = ops.run_tool("host_disk", {"target": "@web"})
        self.assertTrue(result["ok"])
        output = result["output"]
        for needle in ("== a（成功）==\nlocal: df -h", "== w1（成功）==\nw1: df -h", "== w2（成功）==\nw2: df -h",
                       "== w3（失败）==\n连不上主机 w3", "（@web：共 4 台，成功 3 台，失败 1 台；不适用、已跳过 1 台：mac）"):
            self.assertIn(needle, output)
        self.assertTrue(output.endswith("）"))
        self.assertEqual(result["hosts"], {"a": True, "w1": True, "w2": True, "w3": False})
        self.assertLessEqual(self.transport.peak, 2, "并发不超过 parallel")
        self.assertNotIn("mac", [call[0] for call in self.transport.calls])

    def test_a_slow_host_does_not_hold_up_the_group(self):
        """整组有总时限：到点没回来的主机记成超时，已经回来的照常返回，不让应用那边先等超时、全丢。"""
        real_run = self.transport.run

        def slow_w1(host, command, data=b"", timeout=None):
            if host["name"] == "w1":
                time.sleep(1.5)
            return real_run(host, command, data, timeout)

        started = time.monotonic()
        with patch.object(ops, "GROUP_DEADLINE", 0.5), patch.object(self.transport, "run", slow_w1):
            result = ops.run_tool("host_disk", {"target": "@web"})
        self.assertLess(time.monotonic() - started, 1.4)
        self.assertTrue(result["ok"])
        self.assertIn("== w1（失败）==\n超过 0.5 秒没有结果", result["output"])
        self.assertIn("== w2（成功）==\nw2: df -h", result["output"])
        self.assertIn("成功 3 台，失败 1 台", result["output"])

    def test_a_long_skipped_list_is_cut_short(self):
        names = [f"m{i:03d}" for i in range(800)]
        self.write(TOOLS + "hosts:\n  defaults: {user: u, key: '${k}', os: darwin}\n  list:\n" + "".join(
            f"    - {{name: {name}, address: 10.1.{i // 250}.{i % 250 + 1}}}\n" for i, name in enumerate(names)))
        # 800 台 darwin 主机，df -h 的工具只适用于 linux：本机一台能跑，其余全跳过
        result = ops.run_tool("host_disk", {"target": "@all"})
        self.assertTrue(result["ok"])
        self.assertLessEqual(len(result["output"]), ops.MAX_OUTPUT)
        self.assertIn("已跳过 800 台：m000、m001", result["output"])
        self.assertIn("等 800 台", result["output"])
        self.assertIn("== local（成功）==\nlocal: df -h", result["output"])

    def test_limits_and_failures(self):
        result = ops.run_tool("host_disk", {"target": "@big"})
        self.assertFalse(result["ok"])
        self.assertIn("超过单次上限 4 台", result["error"])
        self.assertEqual(self.transport.calls, [])
        self.assertIn("没有能运行", ops.run_tool("gateway_only", {"target": "@web"})["error"])
        self.assertIn("缺少必填参数：name", ops.run_tool("container_logs", {"target": "@web"})["error"])
        self.assertEqual(self.transport.calls, [])
        for name in ("w1", "w2", "w3"):
            self.transport.fail[name] = (255, b"", "ssh: connect to host x port 22: Connection refused")
        with patch.object(ops.shutil, "which", lambda name: None if name == "df" else f"/usr/bin/{name}"):
            result = ops.run_tool("host_disk", {"target": "@web"})
        self.assertFalse(result["ok"])
        self.assertIn("成功 0 台，失败 4 台", result["output"])

    def test_the_whole_output_stays_under_the_cap_and_keeps_the_summary(self):
        def noisy(argv, **kwargs):
            out = "x" * (ops.MAX_OUTPUT * 2)
            return subprocess.CompletedProcess(argv, 0, out if "universal_newlines" in kwargs else out.encode(), "")

        with patch.object(ops.subprocess, "run", noisy):
            result = ops.run_tool("host_disk", {"target": "@web"})
        self.assertLessEqual(len(result["output"]), ops.MAX_OUTPUT + 50)
        self.assertTrue(result["output"].endswith("失败 0 台；不适用、已跳过 1 台：mac）"))
        self.assertEqual(result["output"].count("这台的输出已截断"), 4)


# --- 直连模式的转义 -----------------------------------------------------------------------

class QuotingTests(unittest.TestCase):
    NASTY = ["a;b", "$(id)", "`id`", "x\ny", "*", "?", "[a-z]", "~", "-rf", "--", "'", '"', "\\", "$HOME", "a b",
             "{{.Names}}\t{{.Image}}", "镜像={{.Config.Image}}", "", "&&", "|", ">x", "<x", "#c"]

    def test_quoted_words_split_back_exactly(self):
        command = ops._quote_argv(["printf", "%s|"] + self.NASTY)
        self.assertEqual(shlex.split(command), ["printf", "%s|"] + self.NASTY)

    @unittest.skipUnless(POSIX and shutil.which("sh"), "需要 POSIX sh")
    def test_a_real_shell_sees_only_literal_words(self):
        command = ops._quote_argv(["printf", "%s\\0"] + self.NASTY)
        done = subprocess.run(["sh", "-c", command], stdout=subprocess.PIPE, cwd=tempfile.gettempdir(), timeout=10)
        self.assertEqual(done.stdout.decode("utf-8").split("\0")[:-1], self.NASTY)

    def test_parameter_values_cannot_smuggle_options_or_metacharacters(self):
        spec = ops._check_tool({"name": "logs", "impl": {"type": "command", "argv": ["docker", "logs", "{name}"]},
                                "params": {"name": {"type": "str", "pattern": "name", "required": True}}})
        for evil in ("-rf", "--privileged", "a;b", "$(id)", "`id`", "a\nb", "*", "a b"):
            with self.subTest(evil=evil), self.assertRaises(ValueError):
                ops.build_argv(spec, {"name": evil})


# --- host key 与凭据 ---------------------------------------------------------------------

class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = self.dir / "doc2sop_secret_key_file"
        self.key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n", encoding="utf-8")
        os.chmod(self.key, 0o600)
        self.host = {"name": "b", "via": "ssh", "address": "10.0.0.2", "port": 2222, "user": "opsread",
                     "key": "ssh_key", "os": "linux", "mode": "guarded", "groups": [], "tools": None}
        for patcher in (patch.dict(ops._state, {"path": self.dir / "ops_tools.yaml"}),
                        patch.dict(os.environ, {"OPS_SECRET_SSH_KEY": str(self.key)}),
                        patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}")):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.seen = []

        def fake(argv, data, timeout, limit, env=None):
            self.seen.append((argv, env))
            return 0, b'{"ops_exec": "1.0", "ok": true}\n', f"Warning: Identity file {self.key} not accessible".encode()

        patcher = patch.object(ops, "_communicate", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_ssh(self):
        return ops.SshTransport().run(self.host, ops.GUARDED_COMMAND, b"{}")

    def test_unenrolled_hosts_are_never_contacted(self):
        with self.assertRaisesRegex(ops.HostError, "还没登记"):
            self.run_ssh()
        self.assertEqual(self.seen, [])

    def test_the_ssh_command_line_pins_the_host_key_and_the_identity(self):
        ops._write_known_hosts("b", "ssh-ed25519", ED25519)
        code, out, err = self.run_ssh()
        argv, env = self.seen[-1]
        joined = " ".join(argv)
        for needle in ("-F " + os.devnull, "StrictHostKeyChecking=yes", "HostKeyAlias=b", "UpdateHostKeys=no",
                       "BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no",
                       "ForwardAgent=no", "ClearAllForwardings=yes", "ControlMaster=no", "ProxyCommand=none",
                       f"UserKnownHostsFile={self.dir / 'ops_tools.known_hosts'}", "GlobalKnownHostsFile="):
            self.assertIn(needle, joined)
        self.assertNotIn("accept-new", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertEqual(argv[-7:], ["-p", "2222", "-l", "opsread", "--", "10.0.0.2", ops.GUARDED_COMMAND])
        self.assertNotIn("OPS_SECRET_SSH_KEY", env)
        # stderr 里回显的私钥路径被换掉
        self.assertNotIn(str(self.key), err)

    def test_known_hosts_must_not_be_writable_by_others(self):
        ops._write_known_hosts("b", "ssh-ed25519", ED25519)
        if not POSIX:
            self.skipTest("权限位只在类 Unix 上有意义")
        os.chmod(self.dir / "ops_tools.known_hosts", 0o666)
        with self.assertRaisesRegex(ops.HostError, "权限过宽"):
            self.run_ssh()

    def test_the_private_key_is_checked_and_only_named_in_errors(self):
        ops._write_known_hosts("b", "ssh-ed25519", ED25519)
        cases = [(patch.dict(os.environ, {}, clear=True), "没有配置"),
                 (patch.dict(os.environ, {"OPS_SECRET_SSH_KEY": str(self.dir / "missing")}), "读不到"),
                 (patch.dict(os.environ, {"OPS_SECRET_SSH_KEY": str(self.dir)}), "不是普通文件")]
        if POSIX:
            link = self.dir / "link"
            os.symlink(self.key, link)
            cases.append((patch.dict(os.environ, {"OPS_SECRET_SSH_KEY": str(link)}), "不是普通文件"))
        for patcher, needle in cases:
            with self.subTest(needle=needle), patcher, self.assertRaises(ops.HostError) as caught:
                self.run_ssh()
            self.assertIn(needle, str(caught.exception))
            self.assertIn("${ssh_key}", str(caught.exception))
            self.assertNotIn(str(self.dir), str(caught.exception))
        if POSIX:
            os.chmod(self.key, 0o640)
            with self.assertRaisesRegex(ops.HostError, "权限过宽"):
                self.run_ssh()
        self.assertEqual(self.seen, [])

    def test_enroll_only_pins_a_fingerprint_the_admin_confirmed(self):
        keys = [("ssh-ed25519", ED25519, ops.key_fingerprint(ED25519)),
                ("ssh-rsa", RSA, ops.key_fingerprint(RSA))]
        with patch.object(ops, "scan_host_keys", return_value=keys), \
                patch.object(ops, "_cli_hosts", return_value=[self.host]), \
                patch.object(ops, "public_key", return_value=("ssh-ed25519 AAAAtool doc2sop", "")), \
                patch("sys.stdout", new_callable=io.StringIO) as out:
            with self.assertRaisesRegex(ops.ConfigError, "对不上"):
                ops.enroll("b", "SHA256:wrong")
            self.assertEqual(ops._pinned_keys("b"), [])
            with patch.object(ops.sys.stdin, "isatty", return_value=False), \
                    self.assertRaisesRegex(ops.ConfigError, "--fingerprint"):
                ops.enroll("b")
            self.assertEqual(ops.enroll("b", keys[1][2]), keys[1][2])
            self.assertEqual(ops._pinned_keys("b"), [("ssh-rsa", RSA)])
            # host key 变了：不加 --replace 不改
            with self.assertRaisesRegex(ops.ConfigError, "--replace"):
                ops.enroll("b", keys[0][2])
            ops.enroll("b", keys[0][2], replace=True, source="203.0.113.7")
            self.assertEqual(ops._pinned_keys("b"), [("ssh-ed25519", ED25519)])
            direct = ops.install_snippet(dict(self.host, mode="direct"), "203.0.113.7")
        printed = out.getvalue()
        self.assertIn('restrict,from="203.0.113.7",command="/usr/bin/python3 -I /opt/ops-readonly/ops_exec.py --stdio"'
                      ' ssh-ed25519 AAAAtool doc2sop', printed)
        # 家目录也归 root：家目录的主人能给 ~/.ssh 改名、另放一把不带限制的公钥
        for snippet in (printed, direct):
            self.assertIn("useradd -M --shell /bin/sh opsread\n  install -d -o root -g root -m 0755 ~opsread ~opsread/.ssh",
                          snippet)
            self.assertNotIn("--create-home", snippet)
        self.assertIn("rm -r ~opsread /opt/ops-readonly && userdel opsread", printed)
        self.assertIn('restrict,from="203.0.113.7" ssh-ed25519 AAAAtool doc2sop', direct)
        self.assertNotIn("command=", direct)
        self.assertIn("push --target b", printed)
        self.assertIn("撤销", printed)


class SecretsTests(_Hosts):
    """私钥的路径和内容不进 /tools、页面、日志；页面只看得到主机的地址、账号、模式。"""

    def test_key_paths_never_leave_the_tool_service(self):
        secret_path = str(self.dir / "very_secret_key_path")
        ops._write_known_hosts("b", "ssh-ed25519", ED25519)
        with patch.dict(os.environ, {"OPS_SECRET_SSH_KEY": secret_path}), \
                patch("sys.stdout", new_callable=io.StringIO) as log:
            ops.refresh(force=True)
            with patch.object(ops, "_transport", ops.SshTransport()):
                failed = ops.run_tool("host_disk", {"target": "b"})
                ops.check_hosts()
            payloads = [ops.available_tools(), ops.describe_tools(), ops.describe_hosts(), failed]
        text = json.dumps(payloads, ensure_ascii=False) + log.getvalue()
        self.assertNotIn(secret_path, text)
        self.assertNotIn("very_secret", text)
        hosts = ops.describe_hosts()["list"]
        self.assertEqual((hosts["b"]["address"], hosts["b"]["user"], hosts["b"]["mode"], hosts["c"]["readonly"]),
                         ("10.0.0.2", "opsread", "guarded", "账号权限"))
        self.assertNotIn("key", hosts["b"])


# --- 命令行 -------------------------------------------------------------------------------

class CliTests(_Hosts):
    def test_push_print_writes_what_each_host_should_allow(self):
        out_dir = self.dir / "export"
        with patch("sys.stdout", new_callable=io.StringIO) as printed:
            self.assertEqual(ops.push(out=str(out_dir)), 0)
        self.assertIn("c：直连模式，不用白名单", printed.getvalue())
        self.assertFalse((out_dir / "c").exists())
        self.assertFalse((out_dir / "local").exists())
        document = json.loads((out_dir / "b" / "allowlist.json").read_text(encoding="utf-8"))
        tools, info, problems = core.parse_allowlist(document)
        self.assertEqual((sorted(tools), problems, info["host"]),
                         (["container_logs", "gateway_only", "host_disk"], [], "b"))
        for name, spec in tools.items():
            self.assertEqual(spec["fp"], ops._fingerprint(ops.all_tools()[name]))
        self.assertEqual((out_dir / "b" / "ops_exec.py").read_bytes(), Path(core.__file__).read_bytes())
        script = (out_dir / "b" / "install.sh").read_text(encoding="utf-8")
        for needle in ("set -eu", "install -d -o root -g root -m 0755", 'chmod 0644 "$tmp"', 'chmod 0755 "$tmp"',
                       "--check"):
            self.assertIn(needle, script)
        # 主机限定了开放的工具，白名单就只有这些
        self.write(self.MAIN.replace("groups: [gateway, prod]}", "groups: [gateway, prod], tools: [host_disk]}"))
        with patch("sys.stdout", new_callable=io.StringIO):
            ops.push(target="b", out=str(out_dir))
        self.assertEqual([t["name"] for t in json.loads((out_dir / "b" / "allowlist.json").read_text("utf-8"))["tools"]],
                         ["host_disk"])

    @unittest.skipUnless(POSIX and shutil.which("sh") and shutil.which("base64"), "需要 POSIX sh 和 base64")
    def test_the_install_script_really_installs_both_files(self):
        script = ops.install_script(ops.allowlist_for(ops._state["hosts"]["hosts"]["b"]))
        target = self.dir / "opt"
        script = script.replace("dir=/opt/ops-readonly", f"dir={target}").replace(
            "install -d -o root -g root -m 0755", "install -d -m 0755").replace('chown root:root "$tmp"', "true")
        done = REAL_RUN(["sh", "-s"], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr.decode())
        self.assertEqual((target / "ops_exec.py").read_bytes(), Path(core.__file__).read_bytes())
        self.assertIn("3 个工具", done.stdout.decode())

    def test_status_lists_every_host(self):
        spec = ops.all_tools()["container_logs"]
        self.transport.allowlists["b"] = core.render_allowlist("b", [("container_logs", spec["argv"], spec["params"])])
        with patch("sys.stdout", new_callable=io.StringIO) as printed:
            bad = ops.status()
        text = printed.getvalue()
        self.assertEqual(bad, 0)
        for needle in ("■ local：本机", "■ b：opsread@10.0.0.2:22，受控", "✓ 连通；执行器 1.0；白名单 sha256:",
                       "能跑 1 个：container_logs", "host_disk（白名单里没有，需要 push（主机上有这个命令））",
                       "■ c：opsread@10.0.0.3:22，直连（只读靠账号权限）", "能跑 2 个：container_logs、host_disk"):
            self.assertIn(needle, text)
        self.transport.fail["c"] = (255, b"", "ssh: connect to host 10.0.0.3 port 22: No route to host")
        with patch("sys.stdout", new_callable=io.StringIO) as printed:
            self.assertEqual(ops.status(target="c"), 1)
        self.assertIn("✗ 连不上主机 c", printed.getvalue())

    def test_env_file_loading_only_takes_credentials(self):
        env_file = self.dir / "ops.env"
        env_file.write_text('# x\nOPS_TOKEN=nope\nOPS_SECRET_SSH_KEY="/etc/ops-readonly/id"\n'
                            "export OPS_SECRET_OTHER='v'\nBROKEN\n", encoding="utf-8")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ops.load_env_file(env_file), 2)
            self.assertEqual(os.environ.get("OPS_SECRET_SSH_KEY"), "/etc/ops-readonly/id")
            self.assertEqual(os.environ.get("OPS_SECRET_OTHER"), "v")
            self.assertNotIn("OPS_TOKEN", os.environ)


# --- 页面与契约 ----------------------------------------------------------------------------

class DescribeTests(_Hosts):
    def test_page_sees_per_host_availability_and_the_host_list(self):
        ops.check_hosts()
        described = ops.describe_tools()
        self.assertEqual(described["gateway_only"]["groups"], ["gateway"])
        self.assertEqual(described["gateway_only"]["hosts"]["local"]["state"], "no")
        self.assertIn("分组 gateway", described["gateway_only"]["hosts"]["local"]["reason"])
        self.assertEqual(described["host_disk"]["hosts"]["b"], {"state": "ok", "reason": ""})
        self.assertIn("不填就是 local", described["host_disk"]["params"]["target"]["desc"])
        hosts = ops.describe_hosts()
        self.assertEqual((hosts["configured"], hosts["default"], hosts["local"]), (True, "local", "local"))
        self.assertEqual(hosts["list"]["b"]["status"]["executor"], core.__version__)
        self.assertTrue(hosts["list"]["b"]["status"]["allowlist"].startswith("sha256:"))
        self.assertEqual(hosts["list"]["c"]["readonly"], "账号权限")
        self.assertNotIn("status", hosts["list"]["local"])

    def test_nothing_runnable_anywhere_is_explained(self):
        with patch.object(ops.shutil, "which", lambda name: None):
            self.write(TOOLS + "hosts: {}\n")
            described = ops.describe_tools()["host_disk"]
        self.assertFalse(described["runnable"])
        self.assertIn("没有能运行它的主机：local 本机没有 df", described["reason"])
