"""只读运维接口与 Agent 工具层的测试。

重点是安全边界：Agent 永远拿不到 shell，一切参数都要过白名单。
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.support import FakeReply  # noqa: F401  (sets env before app imports)

from app.agent import loop as agent_loop
from app.agent import ops_client, tools as agent_tools

# ops_readonly.py 跑在宿主机上，不属于 app 包，直接按路径加载。
_SPEC = importlib.util.spec_from_file_location(
    "ops_readonly", Path(__file__).resolve().parent.parent / "deploy" / "ops_readonly.py")
ops = importlib.util.module_from_spec(_SPEC)
sys.modules["ops_readonly"] = ops
_SPEC.loader.exec_module(ops)


class AllowlistTests(unittest.TestCase):
    """命令注入与越权调用必须在构造 argv 之前就被拒绝。"""

    def test_shell_metacharacters_are_rejected(self):
        for evil in ["kb-app; rm -rf /", "kb-app && reboot", "$(whoami)", "`id`",
                     "a|b", "a>b", "../../etc/passwd", "kb app"]:
            with self.subTest(evil=evil):
                result = ops.run_tool("container_logs", {"name": evil})
                self.assertFalse(result["ok"])
                self.assertIn("不合法", result["error"])

    def test_required_argument_cannot_be_empty(self):
        result = ops.run_tool("container_logs", {"name": ""})
        self.assertFalse(result["ok"])
        self.assertIn("缺少必填参数", result["error"])

    def test_unknown_tool_is_rejected(self):
        for name in ["docker_exec", "shell", "container_rm", ""]:
            result = ops.run_tool(name, {})
            self.assertFalse(result["ok"])
            self.assertIn("未知工具", result["error"])

    def test_write_verbs_are_not_reachable(self):
        """发布出去的配置里不存在任何写动词。"""
        sample = {"name": "safe", "resource": "pod", "namespace": "default", "lines": 10}
        for name, spec in ops.all_tools().items():
            with self.subTest(tool=name):
                argv = ops.build_argv(spec, sample)
                self.assertFalse(set(argv[1:]) & ops.FORBIDDEN,
                                 f"{name} 的命令模板包含写操作：{argv}")

    def test_line_count_is_clamped(self):
        spec = ops.all_tools()["container_logs"]
        for value, expected in [(5, "5"), (-1, "1"), (99999, "500"),
                                ("abc", "100"), (None, "100")]:
            with self.subTest(value=value):
                argv = ops.build_argv(spec, {"name": "kb-app", "lines": value})
                self.assertEqual(argv[argv.index("--tail") + 1], expected)

    def test_kubernetes_names_follow_dns_rules(self):
        spec = ops.all_tools()["kube_logs"]
        self.assertIn("my-pod-1", ops.build_argv(spec, {"name": "my-pod-1"}))
        for bad in ["MyPod", "pod;ls", "pod/../x", "-leading"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ops.build_argv(spec, {"name": bad})

    def test_arguments_never_merge_into_a_literal(self):
        """参数只能独占一个 argv 项，拼不出新的命令片段。"""
        spec = ops.all_tools()["container_logs"]
        argv = ops.build_argv(spec, {"name": "kb-app", "lines": 20})
        self.assertIn("kb-app", argv)
        self.assertFalse([part for part in argv if part.startswith("--tail=")])

    def test_commands_never_use_a_shell(self):
        """执行时必须是 argv 形式，shell=False。"""
        captured = {}

        class Done:
            returncode, stdout, stderr = 0, "ok", ""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return Done()

        with patch.object(ops.shutil, "which", return_value="/usr/bin/docker"), \
             patch.object(ops.subprocess, "run", fake_run):
            result = ops.run_tool("container_logs", {"name": "kb-app", "lines": 20})
        self.assertTrue(result["ok"])
        self.assertIsInstance(captured["argv"], list)
        self.assertIs(captured["kwargs"]["shell"], False)
        self.assertEqual(captured["argv"][:3], ["docker", "logs", "--tail"])

    def test_output_is_capped(self):
        class Done:
            returncode, stdout, stderr = 0, "x" * (ops.MAX_OUTPUT + 500), ""

        with patch.object(ops.shutil, "which", return_value="/usr/bin/free"), \
             patch.object(ops.subprocess, "run", lambda *a, **k: Done()):
            result = ops.run_tool("host_resources", {})
        self.assertLessEqual(len(result["output"]), ops.MAX_OUTPUT + 20)
        self.assertIn("已截断", result["output"])

    def test_missing_binary_is_reported_not_executed(self):
        with patch.object(ops.shutil, "which", return_value=None):
            result = ops.run_tool("kube_list", {"resource": "pod"})
        self.assertFalse(result["ok"])
        self.assertIn("没有 kubectl", result["error"])

    def test_only_runnable_tools_are_advertised(self):
        with patch.object(ops.shutil, "which", lambda binary: "/usr/bin/docker"
                          if binary == "docker" else None):
            advertised = ops.available_tools()
        self.assertIn("container_logs", advertised)
        self.assertNotIn("kube_list", advertised)

    def test_advertised_tools_carry_their_parameters(self):
        """应用侧靠这份 params 生成函数签名，不能只给描述。"""
        with patch.object(ops.shutil, "which", return_value="/usr/bin/docker"):
            meta = ops.available_tools()["container_logs"]
        self.assertTrue(meta["desc"])
        self.assertEqual(sorted(meta["params"]), ["lines", "name"])
        self.assertTrue(meta["params"]["name"]["required"])


class ConfigTests(unittest.TestCase):
    """工具定义来自配置文件，所以配置本身就是安全边界的一部分。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, body, name="tools.yaml"):
        path = Path(self.tmp.name) / name
        path.write_text(body, encoding="utf-8")
        return path

    def load(self, body):
        return ops.load_tools(self.write(body))

    def test_custom_regex_is_not_allowed(self):
        """只能引用预置正则，否则一个 .* 就把白名单废了。"""
        tools, problems = self.load(
            "tools:\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [docker, logs, '{name}']\n"
            "    params:\n"
            "      name: {type: str, pattern: '.*', required: true}\n")
        self.assertEqual(tools, {})
        self.assertIn("pattern", problems[0])

    def test_undeclared_placeholder_is_rejected(self):
        tools, problems = self.load(
            "tools:\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [docker, logs, '{nope}']\n"
            "    params: {}\n")
        self.assertEqual(tools, {})
        self.assertIn("未声明的参数", problems[0])

    def test_write_verb_in_template_is_rejected(self):
        tools, problems = self.load(
            "tools:\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [docker, rm, '-f', '{name}']\n"
            "    params:\n"
            "      name: {type: str, pattern: name, required: true}\n")
        self.assertEqual(tools, {})
        self.assertIn("写操作", problems[0])

    def test_argv_head_must_match_binary(self):
        """不能借 binary 过了存在性检查，却去执行别的命令。"""
        tools, problems = self.load(
            "tools:\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [bash, -c, whoami]\n"
            "    params: {}\n")
        self.assertEqual(tools, {})
        self.assertIn("第一项", problems[0])

    def test_optional_string_needs_a_valid_default(self):
        tools, problems = self.load(
            "tools:\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [docker, logs, '{name}']\n"
            "    params:\n"
            "      name: {type: str, pattern: name}\n")
        self.assertEqual(tools, {})
        self.assertIn("default", problems[0])

    def test_one_bad_entry_does_not_drop_the_good_ones(self):
        tools, problems = self.load(
            "tools:\n"
            "  - name: good\n"
            "    binary: free\n"
            "    argv: [free, -m]\n"
            "    params: {}\n"
            "  - name: bad\n"
            "    binary: docker\n"
            "    argv: [docker, rm, '{name}']\n"
            "    params:\n"
            "      name: {type: str, pattern: name, required: true}\n")
        self.assertEqual(sorted(tools), ["good"])
        self.assertEqual(len(problems), 1)

    def test_go_template_is_not_treated_as_a_placeholder(self):
        """docker --format 里的 {{.Names}} 不能被当成参数。"""
        tools, _ = self.load(
            "tools:\n"
            "  - name: ok\n"
            "    binary: docker\n"
            "    argv: [docker, ps, --format, '{{.Names}}']\n"
            "    params: {}\n")
        self.assertEqual(ops.build_argv(tools["ok"], {}),
                         ["docker", "ps", "--format", "{{.Names}}"])

    def test_disabled_tool_is_neither_listed_nor_runnable(self):
        path = self.write(
            "tools:\n"
            "  - {name: one, binary: free, argv: [free, -m], params: {},"
            " enabled: false}\n")
        with patch.dict(ops._state, {"path": path, "mtime": None, "tools": {}}):
            self.assertEqual(ops.available_tools(), {})
            self.assertIn("未知工具", ops.run_tool("one", {})["error"])

    def test_edits_take_effect_without_a_restart(self):
        """加一个工具只改配置，下一次调用就该看见。"""
        path = self.write(
            "tools:\n  - {name: one, binary: free, argv: [free, -m], params: {}}\n")
        with patch.dict(ops._state, {"path": path, "mtime": None, "tools": {}}):
            self.assertEqual(sorted(ops.all_tools()), ["one"])
            path.write_text(
                "tools:\n"
                "  - {name: one, binary: free, argv: [free, -m], params: {}}\n"
                "  - {name: two, binary: df, argv: [df, -h], params: {}}\n",
                encoding="utf-8")
            later = time.time() + 2
            os.utime(path, (later, later))
            self.assertEqual(sorted(ops.all_tools()), ["one", "two"])

    def test_broken_edit_keeps_the_last_good_set(self):
        """配置写坏了不能让服务当场失去全部工具。"""
        path = self.write(
            "tools:\n  - {name: one, binary: free, argv: [free, -m], params: {}}\n")
        with patch.dict(ops._state, {"path": path, "mtime": None, "tools": {}}):
            self.assertEqual(sorted(ops.all_tools()), ["one"])
            path.write_text("tools:\n  - [this is not a mapping\n", encoding="utf-8")
            later = time.time() + 2
            os.utime(path, (later, later))
            self.assertEqual(sorted(ops.all_tools()), ["one"])


class ToolLayerTests(unittest.TestCase):
    def test_no_tools_when_endpoint_not_configured(self):
        with patch.object(ops_client, "OPS_URL", ""), patch.object(ops_client, "OPS_TOKEN", ""):
            self.assertFalse(ops_client.enabled())
            self.assertEqual(ops_client.available_tools(), {})

    def test_tools_are_built_from_host_capabilities(self):
        with patch.object(agent_tools.ops_client, "available_tools", return_value={
                "container_logs": {"desc": "看日志", "params": {}},
                "host_resources": {"desc": "看内存", "params": {}}}):
            built = agent_tools.build_tools()
        self.assertEqual(sorted(t.name for t in built),
                         ["container_logs", "host_resources"])

    def test_signature_comes_from_the_host(self):
        """参数结构由宿主机下发，应用侧不再维护第二份清单。"""
        with patch.object(agent_tools.ops_client, "available_tools", return_value={
                "container_logs": {"desc": "看日志", "params": {
                    "name": {"type": "str", "required": True, "desc": "容器名"},
                    "lines": {"type": "int", "default": 100, "desc": "行数"}}}}):
            tool = agent_tools.build_tools()[0]
        fields = tool.args_schema.model_fields
        self.assertEqual(sorted(fields), ["lines", "name"])
        self.assertTrue(fields["name"].is_required())
        self.assertEqual(fields["lines"].default, 100)
        self.assertEqual(fields["name"].description, "容器名")

    def test_a_new_host_tool_needs_no_code_change(self):
        """宿主机加一个工具，应用侧不改代码、不重建镜像也能用上。"""
        with patch.object(agent_tools.ops_client, "available_tools", return_value={
                "host_disk": {"desc": "看磁盘", "params": {}}}):
            built = agent_tools.build_tools()
        self.assertEqual([t.name for t in built], ["host_disk"])
        self.assertEqual(built[0].description, "看磁盘")

    def test_tool_failure_is_returned_as_text_not_raised(self):
        """工具失败不能中断对话，要让模型看到失败原因。"""
        with patch.object(agent_tools.ops_client, "available_tools", return_value={
                "container_logs": {"desc": "看日志", "params": {
                    "name": {"type": "str", "required": True, "desc": "容器名"},
                    "lines": {"type": "int", "default": 100, "desc": "行数"}}}}), \
             patch.object(agent_tools.ops_client, "execute",
                          return_value={"ok": False, "error": "容器不存在"}):
            tool = agent_tools.build_tools()[0]
            self.assertIn("容器不存在", tool.invoke({"name": "ghost", "lines": 10}))

    def test_legacy_endpoint_response_still_works(self):
        """滚动升级期间宿主机可能还是老版本，只回一个描述字符串。"""
        with patch.object(agent_tools.ops_client, "available_tools",
                          return_value={"host_resources": "看内存"}):
            built = agent_tools.build_tools()
        self.assertEqual([t.name for t in built], ["host_resources"])

    def test_endpoint_outage_degrades_to_a_message(self):
        def boom(*args, **kwargs):
            raise ops_client.OpsUnavailable("连接被拒绝")

        with patch.object(ops_client, "_request", boom):
            result = ops_client.execute("list_containers", {})
        self.assertFalse(result["ok"])
        self.assertIn("运维接口不可用", result["output"])


class FakeTool:
    """替身工具，记录被调用的参数。"""

    def __init__(self, name, output="现场输出"):
        self.name = name
        self.output = output
        self.calls = []

    def invoke(self, args):
        self.calls.append(args)
        return self.output


class AgentLoopTests(unittest.TestCase):
    def make_model(self, script):
        """script 是每轮返回的 (tool_calls, content)。"""
        rounds = iter(script)

        class Bound:
            def invoke(_self, messages):
                calls, content = next(rounds)
                reply = FakeReply(content)
                reply.tool_calls = calls
                return reply

        class Model:
            def bind_tools(_self, tools):
                return Bound()

            def invoke(_self, messages):
                return Bound().invoke(messages)

        return Model()

    def run_agent(self, script, tools):
        with patch.object(agent_loop, "build_tools", return_value=tools), \
             patch.object(agent_loop, "chat_model", return_value=self.make_model(script)):
            return list(agent_loop.run("问题", "知识库片段", []))

    def test_tool_call_then_answer(self):
        tool = FakeTool("container_stats")
        events = self.run_agent(
            [([{"name": "container_stats", "args": {}, "id": "c1"}], ""),
             ([], "结论：内存正常")], [tool])
        kinds = [kind for kind, _ in events]
        self.assertEqual(kinds, ["tool_call", "tool_result", "delta"])
        self.assertEqual(events[-1][1], "结论：内存正常")
        self.assertEqual(tool.calls, [{}])

    def test_answer_without_tools(self):
        """闲聊不应触发工具调用。"""
        events = self.run_agent([([], "您好，有什么可以帮您？")], [FakeTool("container_stats")])
        self.assertEqual([kind for kind, _ in events], ["delta"])

    def test_rounds_are_capped(self):
        tool = FakeTool("container_logs")
        forever = [([{"name": "container_logs", "args": {"name": "a"}, "id": "x"}], "")] * 20
        events = self.run_agent(forever, [tool])
        self.assertEqual(len(tool.calls), agent_loop.MAX_ROUNDS)
        # 收口那一轮仍然调了工具，所以最后一个事件是 tool_result 而不是 delta。
        self.assertEqual(events[-1][0], "tool_result")

    def test_unknown_tool_does_not_crash(self):
        events = self.run_agent(
            [([{"name": "not_a_tool", "args": {}, "id": "z"}], ""), ([], "已说明")],
            [FakeTool("container_stats")])
        results = [payload for kind, payload in events if kind == "tool_result"]
        self.assertIn("未知工具", results[0]["preview"])

    def test_model_failure_yields_error_event(self):
        class Broken:
            def bind_tools(_self, tools):
                return _self

            def invoke(_self, messages):
                raise RuntimeError("网关超时")

        with patch.object(agent_loop, "build_tools", return_value=[FakeTool("x")]), \
             patch.object(agent_loop, "chat_model", return_value=Broken()):
            events = list(agent_loop.run("问题", "片段", []))
        self.assertEqual(events[0][0], "error")
        self.assertIn("网关超时", events[0][1])

    def test_runs_without_tools_available(self):
        """没有现场工具时退化成纯知识库问答，不能报错。"""
        events = self.run_agent([([], "仅凭知识库回答")], [])
        self.assertEqual([kind for kind, _ in events], ["delta"])

    def test_tool_result_preview_is_truncated(self):
        tool = FakeTool("container_logs", output="行\n" * 5000)
        events = self.run_agent(
            [([{"name": "container_logs", "args": {"name": "a"}, "id": "1"}], ""),
             ([], "好的")], [tool])
        preview = [p for k, p in events if k == "tool_result"][0]
        self.assertLessEqual(len(preview["preview"]), 401)
        self.assertGreater(preview["lines"], 100)


class ManagementTests(unittest.TestCase):
    """页面能改什么、不能改什么，本身就是一条安全边界。

    允许：启停、改说明（都不影响实际执行的命令）。
    禁止：改命令、加工具——后者只能提申请，由人在宿主机批准。
    """

    MAIN = ("tools:\n"
            "  - {name: one, desc: 原说明, binary: free, argv: [free, -m], params: {}}\n"
            "  - {name: two, desc: 另一个, binary: df, argv: [df, -h], params: {}}\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.main = Path(self.tmp.name) / "ops_tools.yaml"
        self.main.write_text(self.MAIN, encoding="utf-8")
        patcher = patch.dict(ops._state, {"path": self.main, "mtime": None,
                                          "omtime": None, "tools": {}, "problems": []})
        patcher.start()
        self.addCleanup(patcher.stop)
        # 假装所有命令本机都有，这样 available_tools 的差异只来自启停，断言才精确。
        which = patch.object(ops.shutil, "which", return_value="/usr/bin/true")
        which.start()
        self.addCleanup(which.stop)

    def overrides_file(self):
        return Path(self.tmp.name) / "ops_tools.overrides.yaml"

    def write_overrides(self, mapping):
        import yaml
        self.overrides_file().write_text(
            yaml.safe_dump({"overrides": mapping}, allow_unicode=True), encoding="utf-8")
        ops.refresh(force=True)

    # --- 开关与说明 ---------------------------------------------------------

    def test_disabling_hides_the_tool_and_refuses_execution(self):
        self.assertIn("one", ops.available_tools())
        ops.set_override("one", enabled=False)
        self.assertNotIn("one", ops.available_tools())
        self.assertIn("未知工具", ops.run_tool("one", {})["error"])
        self.assertIn("one", ops.describe_tools())  # 界面上仍然看得到

    def test_description_can_be_reworded_without_touching_the_command(self):
        ops.set_override("one", desc="新说明")
        spec = ops.all_tools()["one"]
        self.assertEqual(spec["desc"], "新说明")
        self.assertEqual(spec["argv"], ["free", "-m"])
        self.assertEqual(ops.available_tools()["one"]["desc"], "新说明")

    def test_overrides_cannot_change_the_command(self):
        """整个设计的根基：覆盖层写了 argv/binary 也必须被忽略。"""
        self.write_overrides({"one": {"desc": "伪装成人畜无害",
                                      "argv": ["cat", "/etc/shadow"], "binary": "cat",
                                      "params": {"x": {"type": "str"}}}})
        spec = ops.all_tools()["one"]
        self.assertEqual(spec["argv"], ["free", "-m"])
        self.assertEqual(spec["binary"], "free")
        self.assertEqual(spec["params"], {})
        self.assertEqual(spec["desc"], "伪装成人畜无害")

    def test_written_overrides_contain_only_the_two_allowed_fields(self):
        import yaml
        ops.set_override("one", enabled=False, desc="短说明")
        saved = yaml.safe_load(self.overrides_file().read_text(encoding="utf-8"))
        self.assertEqual(sorted(saved["overrides"]["one"]), ["desc", "enabled"])

    def test_reset_falls_back_to_the_handwritten_definition(self):
        ops.set_override("one", enabled=False, desc="临时说明")
        ops.reset_override("one")
        spec = ops.all_tools()["one"]
        self.assertEqual(spec["desc"], "原说明")
        self.assertTrue(spec["enabled"])

    def test_override_of_an_unknown_tool_is_refused(self):
        with self.assertRaises(ops.ConfigError):
            ops.set_override("nope", enabled=False)

    def test_description_length_is_capped(self):
        with self.assertRaises(ops.ConfigError):
            ops.set_override("one", desc="x" * (ops.MAX_DESC + 1))

    def test_tool_names_stay_english_but_display_names_can_be_chinese(self):
        """工具名是发给模型的函数名，按协议只能用英文；中文放 label。"""
        with self.assertRaises(ops.ConfigError) as caught:
            ops.propose_tool({"name": "看时间", "desc": "几点了",
                              "binary": "date", "argv": ["date"], "params": {}})
        self.assertIn("label", str(caught.exception))

        ops.set_override("one", label="内存概览")
        self.assertEqual(ops.describe_tools()["one"]["label"], "内存概览")
        self.assertEqual(ops.all_tools()["one"]["argv"], ["free", "-m"])

    def test_display_name_never_reaches_the_model(self):
        ops.set_override("one", label="内存概览")
        advertised = ops.available_tools()["one"]
        self.assertEqual(sorted(advertised), ["desc", "params"])

    def test_a_broken_overrides_file_does_not_lose_the_tools(self):
        self.overrides_file().write_text("overrides: [not a mapping]\n", encoding="utf-8")
        ops.refresh(force=True)
        self.assertEqual(sorted(ops.all_tools()), ["one", "two"])

    # --- 申请与批准 ---------------------------------------------------------

    GOOD = {"name": "three", "desc": "看登录用户", "binary": "who",
            "argv": ["who"], "params": {}}

    def test_a_proposal_is_inert_until_approved(self):
        """提交只是排队。没批准之前，模型绝不该看见它。"""
        item = ops.propose_tool(self.GOOD)
        self.assertNotIn("three", ops.all_tools())
        self.assertNotIn("three", ops.available_tools())
        self.assertIn("未知工具", ops.run_tool("three", {})["error"])
        self.assertEqual(len(ops.list_pending()), 1)
        self.assertEqual(item["tool"]["name"], "three")

    def test_the_pending_file_is_never_loaded_as_tools(self):
        ops.propose_tool(self.GOOD)
        ops.refresh(force=True)
        self.assertEqual(sorted(ops.all_tools()), ["one", "two"])

    def test_proposals_face_the_same_validation(self):
        for bad, expected in [
            ({"name": "x", "binary": "docker", "argv": ["bash", "-c", "id"], "params": {}},
             "第一项"),
            ({"name": "x", "binary": "docker", "argv": ["docker", "rm", "a"], "params": {}},
             "写操作"),
            ({"name": "x", "binary": "cat", "argv": ["cat", "{p}"], "params": {}},
             "未声明的参数"),
        ]:
            with self.subTest(bad=bad), self.assertRaises(ops.ConfigError) as caught:
                ops.propose_tool(bad)
            self.assertIn(expected, str(caught.exception))

    def test_duplicate_names_are_refused(self):
        with self.assertRaises(ops.ConfigError):
            ops.propose_tool({**self.GOOD, "name": "one"})
        ops.propose_tool(self.GOOD)
        with self.assertRaises(ops.ConfigError):
            ops.propose_tool(self.GOOD)

    def test_a_missing_command_is_refused_with_a_suggestion(self):
        """命令写错时当场说清原因并给替代，而不是批准后才发现跑不了。"""
        with patch.object(ops.shutil, "which", return_value=None), \
             patch.object(ops, "suggest_binaries", return_value=["date", "dateutils"]):
            with self.assertRaises(ops.ConfigError) as caught:
                ops.propose_tool({"name": "clock", "desc": "看时间",
                                  "binary": "datetime", "argv": ["datetime"],
                                  "params": {}})
        message = str(caught.exception)
        self.assertIn("datetime", message)
        self.assertIn("date", message)
        self.assertEqual(ops.list_pending(), [])  # 没写错的东西不进队列

    def test_suggestions_catch_the_usual_typos(self):
        with patch.dict(ops.os.environ, {"PATH": "/fake"}), \
             patch.object(ops.os, "listdir",
                          return_value=["date", "df", "who", "uptime", "ss"]):
            self.assertEqual(ops.suggest_binaries("datetime")[0], "date")
            self.assertIn("date", ops.suggest_binaries("dat"))
            self.assertIn("uptime", ops.suggest_binaries("uptim"))
            self.assertEqual(ops.suggest_binaries("zzzzzzzz"), [])

    def test_approval_writes_it_into_the_main_file_and_takes_effect(self):
        item = ops.propose_tool(self.GOOD)
        spec = ops.approve_pending(item["id"])
        self.assertEqual(spec["argv"], ["who"])
        self.assertIn("three", ops.all_tools())
        self.assertEqual(ops.list_pending(), [])
        self.assertIn("three", self.main.read_text(encoding="utf-8"))

    def test_rejection_drops_it_and_leaves_the_main_file_alone(self):
        before = self.main.read_text(encoding="utf-8")
        item = ops.propose_tool(self.GOOD)
        ops.drop_pending(item["id"])
        self.assertEqual(ops.list_pending(), [])
        self.assertEqual(self.main.read_text(encoding="utf-8"), before)

    def test_approval_can_use_the_tool_name_too(self):
        ops.propose_tool(self.GOOD)
        ops.approve_pending("three")
        self.assertIn("three", ops.all_tools())


if __name__ == "__main__":
    unittest.main()
