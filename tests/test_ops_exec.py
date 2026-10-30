"""受控模式的执行器 deploy/ops_exec.py，兼工具服务的执行核心。

覆盖：白名单校验（坏条目跳过、fp 对不上拒绝）、exec / list / probe、超时、输出上限、畸形请求、
自检（不能以 root 运行；执行账号拥有或能写白名单、执行器、它们的任一级目录时拒绝启动）、回应只有 ASCII，
以及工具服务确实在用同一份核心。
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
EXEC_FILE = REPO / "deploy" / "ops_exec.py"

if "ops_exec" in sys.modules:
    core = sys.modules["ops_exec"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_exec", EXEC_FILE)
    core = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_exec"] = core
    _SPEC.loader.exec_module(core)

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _OPS = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_OPS)
    sys.modules["ops_readonly"] = ops
    _OPS.loader.exec_module(ops)

POSIX = os.name == "posix"
LOGS = {"name": "container_logs", "argv": ["docker", "logs", "--tail", "{lines}", "{name}"],
        "params": {"name": {"type": "str", "pattern": "name", "required": True},
                   "lines": {"type": "int", "default": 100, "max": 500}}}
WHO = {"name": "who_am_i", "argv": ["hostname"], "params": {}}


def allowlist(*entries, **header):
    return {"format": 1, "host": "b", "generated_at": "2026-10-30 23:00:00", **header, "tools": list(entries)}


def parsed(*entries, **header):
    return core.parse_allowlist(allowlist(*entries, **header))


def service_spec(entry, **extra):
    """同一个工具按工具服务的配置写法（impl: command）加载。"""
    return ops._check_tool({"name": entry["name"], "impl": {"type": "command", "argv": entry["argv"]},
                            "params": entry.get("params") or {}, **extra})


class Done:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class AllowlistTests(unittest.TestCase):
    def test_entries_go_through_the_same_checks_as_the_tool_service(self):
        tools, info, problems = parsed(
            LOGS, WHO,
            {"name": "shell", "argv": ["bash", "-c", "id"]},
            {"name": "rm_all", "argv": ["docker", "rm", "x"]},
            {"name": "sneaky", "argv": ["cat", "{path}"]},
            {"name": "loose", "argv": ["ls", "{p}"], "params": {"p": {"type": "str", "pattern": ".*"}}},
            {"name": "extra", "argv": ["df"], "via": "ssh"},
            {"name": "BadName", "argv": ["df"]},
            {"name": "tampered", "argv": ["df", "-h"], "fp": "sha256:" + "0" * 64},
            {"name": "who_am_i", "argv": ["uname"]})
        self.assertEqual(sorted(tools), ["container_logs", "who_am_i"])
        joined = "\n".join(problems)
        for needle in ("能执行任意命令", "写操作动词 rm", "未声明的参数 path", "pattern 必须是", "不认识的字段 via",
                       "工具名不合法", "fp 和内容对不上", "工具名重复"):
            self.assertIn(needle, joined)
        self.assertTrue(info["version"].startswith("sha256:"))
        self.assertEqual((info["timeout"], info["max_output"]), (core.TIMEOUT, core.MAX_OUTPUT))

    def test_fingerprint_covers_what_runs_and_not_the_wording(self):
        spec = service_spec(LOGS, desc="看日志")
        tools, _, _ = parsed(dict(LOGS, fp=core.fingerprint(spec["argv"], spec["params"])))
        self.assertEqual(tools["container_logs"]["fp"], ops._fingerprint(spec))
        reworded = service_spec({**LOGS, "params": {
            "name": {"type": "str", "pattern": "name", "required": True, "desc": "容器"},
            "lines": {"type": "int", "default": 100, "max": 500, "desc": "行数"}}}, desc="换个说法")
        self.assertEqual(ops._fingerprint(reworded), ops._fingerprint(spec))
        for changed in ({**LOGS, "argv": ["docker", "logs", "{name}"], "params": {"name": LOGS["params"]["name"]}},
                        {**LOGS, "params": {**LOGS["params"], "lines": {"type": "int", "default": 100, "max": 900}}}):
            self.assertNotEqual(ops._fingerprint(service_spec(changed)), ops._fingerprint(spec))

    def test_rendered_allowlists_load_back_with_the_same_fingerprints(self):
        spec = service_spec(LOGS)
        text = core.render_allowlist("b", [(spec["name"], spec["argv"], spec["params"])], "2026-10-30", 15, 9000)
        self.assertNotIn("desc", text)
        tools, info, problems = core.parse_allowlist(json.loads(text))
        self.assertEqual((sorted(tools), problems, info["host"], info["timeout"], info["max_output"]),
                         (["container_logs"], [], "b", 15, 9000))
        self.assertEqual(tools["container_logs"]["fp"], ops._fingerprint(spec))

    def test_whole_file_problems_raise(self):
        for document in ({"tools": []}, {"format": 2, "tools": []}, {"format": 1}, [], "x"):
            with self.subTest(document=document), self.assertRaises(core.ConfigError):
                core.parse_allowlist(document)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allowlist.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(core.ConfigError, "不是合法的 JSON"):
                core.load_allowlist(path)
            path.write_bytes(b" " * (core.ALLOWLIST_MAX + 1))
            with self.assertRaisesRegex(core.ConfigError, "太大"):
                core.load_allowlist(path)
            with self.assertRaisesRegex(core.ConfigError, "读不到"):
                core.load_allowlist(Path(tmp) / "missing.json")

    def test_limits_from_the_file_are_clamped(self):
        _, info, _ = parsed(timeout=99999, max_output=1)
        self.assertEqual((info["timeout"], info["max_output"]), (core.TIMEOUT_RANGE[1], core.OUTPUT_RANGE[0]))
        _, info, _ = parsed(timeout="abc")
        self.assertEqual(info["timeout"], core.TIMEOUT)


class HandleTests(unittest.TestCase):
    def setUp(self):
        self.tools, self.info, self.problems = parsed(LOGS, WHO)

    def call(self, **request):
        return core.handle({"v": core.PROTOCOL, **request}, self.tools, self.info, self.problems)

    def test_exec_builds_argv_itself_and_never_uses_a_shell(self):
        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(argv=argv, kwargs=kwargs)
            return Done("日志一行\r\n".encode("utf-8"))

        with patch.object(core.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(core.subprocess, "run", fake_run):
            reply = self.call(op="exec", tool="container_logs", args={"name": "kb-app", "lines": "20"})
        self.assertEqual(seen["argv"], ["docker", "logs", "--tail", "20", "kb-app"])
        self.assertIs(seen["kwargs"]["shell"], False)
        self.assertEqual((reply["ok"], reply["output"], reply["exit_code"], reply["ops_exec"]),
                         (True, "日志一行", 0, core.__version__))

    def test_exec_refuses_what_the_allowlist_does_not_allow(self):
        cases = [
            ({"tool": "docker_exec"}, "not_allowed"),
            ({"tool": None}, "not_allowed"),
            ({"tool": "container_logs", "args": {"name": "kb-app; rm -rf /"}}, "bad_args"),
            ({"tool": "container_logs", "args": {"name": "-rf"}}, "bad_args"),
            ({"tool": "container_logs", "args": {}}, "bad_args"),
            ({"tool": "container_logs", "args": ["kb-app"]}, "bad_request"),
            ({"tool": "container_logs", "args": {"name": "kb-app"}, "fp": "sha256:old"}, "fp_mismatch"),
        ]
        with patch.object(core.subprocess, "run", side_effect=AssertionError("不该执行")):
            for request, code in cases:
                with self.subTest(request=request):
                    reply = self.call(op="exec", **request)
                    self.assertEqual((reply["ok"], reply["code"]), (False, code))
        with patch.object(core.shutil, "which", return_value=None):
            reply = self.call(op="exec", tool="who_am_i")
        self.assertEqual((reply["code"], reply["error"]), ("missing", "本机没有 hostname，该工具不可用"))

    def test_a_matching_fingerprint_is_accepted(self):
        with patch.object(core.shutil, "which", return_value="/bin/hostname"), \
                patch.object(core.subprocess, "run", return_value=Done(b"b\n")):
            reply = self.call(op="exec", tool="who_am_i", fp=self.tools["who_am_i"]["fp"])
        self.assertTrue(reply["ok"])

    def test_timeout_and_output_cap_follow_the_allowlist(self):
        tools, info, _ = parsed(WHO, timeout=3, max_output=1000)

        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with patch.object(core.shutil, "which", return_value="/bin/hostname"):
            with patch.object(core.subprocess, "run", slow):
                reply = core.handle({"v": 1, "op": "exec", "tool": "who_am_i"}, tools, info)
            self.assertEqual((reply["ok"], reply["error"]), (False, "执行超时（3s）"))
            with patch.object(core.subprocess, "run", return_value=Done(b"x" * 5000)):
                reply = core.handle({"v": 1, "op": "exec", "tool": "who_am_i"}, tools, info)
        self.assertTrue(reply["output"].startswith("x" * 1000))
        self.assertLessEqual(len(reply["output"]), 1000 + 20)
        self.assertIn("已截断", reply["output"])

    @unittest.skipUnless(POSIX and shutil.which("sleep") and shutil.which("seq"), "需要 POSIX 的 sleep、seq")
    def test_real_commands_hit_the_real_limits(self):
        tools, info, _ = parsed({"name": "nap", "argv": ["sleep", "5"]}, {"name": "count", "argv": ["seq", "1", "50000"]},
                                timeout=1, max_output=1000)
        reply = core.handle({"v": 1, "op": "exec", "tool": "nap"}, tools, info)
        self.assertEqual(reply["error"], "执行超时（1s）")
        reply = core.handle({"v": 1, "op": "exec", "tool": "count"}, tools, info)
        self.assertTrue(reply["ok"])
        self.assertLessEqual(len(reply["output"]), 1020)

    def test_list_reports_versions_and_what_can_run_here(self):
        with patch.object(core.shutil, "which", lambda name: "/x" if name == "hostname" else None):
            reply = self.call(op="list")
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["allowlist"]["version"], self.info["version"])
        self.assertEqual(reply["tools"]["who_am_i"], {"fp": self.tools["who_am_i"]["fp"], "binary": "hostname",
                                                      "runnable": True})
        self.assertFalse(reply["tools"]["container_logs"]["runnable"])
        self.assertIn("python", reply)

    def test_probe_only_accepts_plain_command_names(self):
        with patch.object(core.shutil, "which", lambda name: "/x" if name in ("docker", "/usr/bin/df") else None):
            reply = self.call(op="probe", binaries=["docker", "kubectl", "/usr/bin/df"])
        self.assertEqual(reply["binaries"], {"docker": True, "kubectl": False, "/usr/bin/df": True})
        for bad in (["a;b"], ["$(id)"], ["a b"], ["../etc/passwd"], ["/usr/../etc"], [""], [1], "docker",
                    ["x"] * (core.PROBE_MAX + 1)):
            with self.subTest(bad=bad):
                self.assertFalse(self.call(op="probe", binaries=bad)["ok"])

    def test_malformed_requests_are_refused_with_a_reason(self):
        for request, needle in (([], "JSON 对象"), ({"op": "list"}, "协议版本"), ({"v": 2, "op": "list"}, "协议版本"),
                                ({"v": 1, "op": "shell"}, "不认识的请求"), ({"v": 1}, "不认识的请求")):
            with self.subTest(request=request):
                reply = core.handle(request, self.tools, self.info)
                self.assertFalse(reply["ok"])
                self.assertIn(needle, reply["error"])


class ServeTests(unittest.TestCase):
    """--stdio 的完整一来一回：自检 → 读请求 → 回一行 ASCII JSON。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "opt"
        self.dir.mkdir()
        self.allowlist = self.dir / "allowlist.json"
        self.allowlist.write_text(json.dumps(allowlist(WHO)), encoding="utf-8")
        self.executor = self.dir / "ops_exec.py"
        shutil.copyfile(EXEC_FILE, self.executor)

    def serve(self, data, euid=None, guard=True):
        out = io.BytesIO()
        with patch.object(core, "guard", core.guard if guard else (lambda paths, euid=None: None)):
            code = core.serve(io.BytesIO(data), out, str(self.allowlist), str(self.executor), euid)
        lines = out.getvalue().decode("ascii").splitlines()
        self.assertEqual(len(lines), 1)
        return code, json.loads(lines[0])

    def test_one_request_one_ascii_reply(self):
        with patch.object(core.shutil, "which", return_value="/bin/hostname"), \
                patch.object(core.subprocess, "run", return_value=Done("主机甲\n".encode("utf-8"))):
            code, reply = self.serve(json.dumps({"v": 1, "op": "exec", "tool": "who_am_i"}).encode(), guard=False)
        self.assertEqual((code, reply["ok"], reply["output"]), (0, True, "主机甲"))

    def test_garbage_in_is_refused_not_crashed(self):
        for data, needle in ((b"\xff\xfe", "不是合法的 JSON"), (b"{", "不是合法的 JSON"),
                             (b" " * (core.REQUEST_MAX + 1), "请求太大"), (b"", "不是合法的 JSON")):
            with self.subTest(data=data[:10]):
                code, reply = self.serve(data, guard=False)
                self.assertEqual((code, reply["ok"]), (0, False))
                self.assertIn(needle, reply["error"])
        self.allowlist.write_text("[]", encoding="utf-8")
        code, reply = self.serve(b'{"v": 1, "op": "list"}', guard=False)
        self.assertEqual((reply["code"], reply["ok"]), ("allowlist", False))

    def test_never_runs_as_root(self):
        if not hasattr(os, "geteuid"):
            code, reply = self.serve(b'{"v": 1, "op": "list"}')
            self.assertEqual((code, reply["code"]), (3, "guard"))
            return
        code, reply = self.serve(b'{"v": 1, "op": "list"}', euid=0)
        self.assertEqual((code, reply["code"]), (3, "guard"))
        self.assertIn("root", reply["error"])

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "需要以普通账号在类 Unix 上运行")
    def test_refuses_when_the_account_owns_or_can_write_its_files(self):
        # 自己的文件：随时能改 → 拒绝
        code, reply = self.serve(b'{"v": 1, "op": "list"}')
        self.assertEqual(code, 3)
        self.assertIn("属于执行账号", reply["error"])
        # 换一个「别人」的视角（euid 不是文件主人）：文件和各级目录都只读时才放行（临时目录的上一级也得锁上）
        stranger = os.geteuid() + 4242
        for path in (self.allowlist, self.executor):
            os.chmod(path, 0o444)
        root = Path(self.tmp.name)
        os.chmod(self.dir, 0o555)
        os.chmod(root, 0o555)
        self.addCleanup(os.chmod, self.dir, 0o755)
        self.addCleanup(os.chmod, root, 0o755)
        with patch.object(core.shutil, "which", return_value="/bin/hostname"):
            code, reply = self.serve(b'{"v": 1, "op": "list"}', euid=stranger)
        self.assertEqual((code, reply["ok"]), (0, True), reply)
        # 白名单能写 → 拒绝；目录能写（能换掉白名单）→ 拒绝
        os.chmod(self.allowlist, 0o644)
        code, reply = self.serve(b'{"v": 1, "op": "list"}', euid=stranger)
        self.assertEqual(code, 3)
        self.assertIn("能写", reply["error"])
        os.chmod(self.allowlist, 0o444)
        os.chmod(self.dir, 0o755)
        code, reply = self.serve(b'{"v": 1, "op": "list"}', euid=stranger)
        self.assertEqual(code, 3)
        self.assertIn(str(self.dir.resolve()), reply["error"])
        # 执行器自己能写 → 拒绝
        os.chmod(self.dir, 0o555)
        os.chmod(self.executor, 0o644)
        code, reply = self.serve(b'{"v": 1, "op": "list"}', euid=stranger)
        self.assertEqual(code, 3)
        self.assertIn("ops_exec.py", reply["error"])

    def test_check_mode_validates_without_the_guard(self):
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(core.main(["--check", str(self.allowlist)]), 0)
        self.assertIn("1 个工具", out.getvalue())
        self.allowlist.write_text(json.dumps(allowlist(WHO, {"name": "x", "argv": ["sh"]})), encoding="utf-8")
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(core.main(["--check", str(self.allowlist)]), 1)
        self.assertIn("已跳过", out.getvalue())


class SharedCoreTests(unittest.TestCase):
    """本地和远程用同一份代码：工具服务里的这些名字就是执行核心里的那几个对象。"""

    def test_the_tool_service_uses_the_executor_core(self):
        self.assertIs(sys.modules["ops_exec"], ops.ops_exec)
        for name in ("PATTERNS", "FORBIDDEN", "INTERPRETERS", "PLACEHOLDER", "TOOL_NAME", "ConfigError"):
            self.assertIs(getattr(ops, name), getattr(ops.ops_exec, name), name)
        self.assertIs(ops.build_argv, ops.ops_exec.build_argv)
        self.assertIs(ops._value, ops.ops_exec.value)
        self.assertIs(ops._check_param, ops.ops_exec.check_param)
        self.assertIs(ops._interpreter, ops.ops_exec.interpreter)

    def test_the_executor_only_uses_the_standard_library(self):
        text = EXEC_FILE.read_text(encoding="utf-8")
        imports = {line.split()[1].split(".")[0] for line in text.splitlines()
                   if line.startswith(("import ", "from "))}
        self.assertLessEqual(imports, {"argparse", "hashlib", "json", "os", "platform", "re", "shutil", "stat",
                                       "subprocess", "sys"})
