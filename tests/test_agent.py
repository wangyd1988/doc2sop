"""只读运维接口与 Agent 工具层的测试。

重点是安全边界：Agent 永远拿不到 shell，一切参数都要过白名单。
"""
import importlib.util
import sys
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
                     "a|b", "a>b", "../../etc/passwd", "kb app", ""]:
            with self.subTest(evil=evil):
                result = ops.run_tool("container_logs", {"name": evil})
                self.assertFalse(result["ok"])
                self.assertIn("参数不合法", result["error"])

    def test_unknown_tool_is_rejected(self):
        for name in ["docker_exec", "shell", "container_rm", ""]:
            result = ops.run_tool(name, {})
            self.assertFalse(result["ok"])
            self.assertIn("未知工具", result["error"])

    def test_write_verbs_are_not_reachable(self):
        """白名单里不存在任何写动词。"""
        for name, (_desc, _binary, build) in ops.TOOLS.items():
            try:
                argv = build({"name": "safe", "resource": "pod", "namespace": "default"})
            except ValueError:
                continue
            with self.subTest(tool=name):
                self.assertFalse(set(argv[1:]) & ops.FORBIDDEN,
                                 f"{name} 的命令模板包含写操作：{argv}")

    def test_line_count_is_clamped(self):
        for value, expected in [(5, 5), (-1, 1), (99999, 500), ("abc", 100), (None, 100)]:
            self.assertEqual(ops._lines(value), expected)

    def test_kubernetes_names_follow_dns_rules(self):
        self.assertEqual(ops._name("my-pod-1", ops.K8S_NAME), "my-pod-1")
        for bad in ["MyPod", "pod;ls", "pod/../x", "-leading"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ops._name(bad, ops.K8S_NAME)

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
            result = ops.run_tool("kube_get", {"resource": "pod"})
        self.assertFalse(result["ok"])
        self.assertIn("没有 kubectl", result["error"])

    def test_only_runnable_tools_are_advertised(self):
        with patch.object(ops.shutil, "which", lambda binary: "/usr/bin/docker"
                          if binary == "docker" else None):
            advertised = ops.available_tools()
        self.assertIn("container_logs", advertised)
        self.assertNotIn("kube_get", advertised)


class ToolLayerTests(unittest.TestCase):
    def test_no_tools_when_endpoint_not_configured(self):
        with patch.object(ops_client, "OPS_URL", ""), patch.object(ops_client, "OPS_TOKEN", ""):
            self.assertFalse(ops_client.enabled())
            self.assertEqual(ops_client.available_tools(), {})

    def test_tools_are_built_from_host_capabilities(self):
        with patch.object(agent_tools.ops_client, "available_tools",
                          return_value={"container_logs": "看日志", "host_resources": "看内存"}):
            built = agent_tools.build_tools()
        self.assertEqual(sorted(t.name for t in built), ["container_logs", "host_resources"])

    def test_tool_failure_is_returned_as_text_not_raised(self):
        """工具失败不能中断对话，要让模型看到失败原因。"""
        with patch.object(agent_tools.ops_client, "available_tools",
                          return_value={"container_logs": "看日志"}), \
             patch.object(agent_tools.ops_client, "execute",
                          return_value={"ok": False, "error": "容器不存在"}):
            tool = agent_tools.build_tools()[0]
            self.assertIn("容器不存在", tool.invoke({"name": "ghost", "lines": 10}))

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


if __name__ == "__main__":
    unittest.main()
