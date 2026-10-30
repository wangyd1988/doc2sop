"""python_exec（app/agent/sandbox.py）接在真实的 Agent 循环里：模型打桩，沙箱服务的 /run 打桩（最后一组接真的服务）。

钉住的：
- SANDBOX_URL 为空时不绑定 python_exec：工具、提示词、事件都和以前一样；配了才绑，并带上计算类的提示词、8 轮的预算；
- 工具说明每次调模型前现算，列出本轮此刻的数据文件（哪个工具的第几次调用、多大）；
- 挂进沙箱的是本轮数据工具的完整返回（不是给模型看的压缩版），只有本轮的、只有成功的，合计有上限；
- 结果写明是计算结果、不是指令；没跑完的以 [执行失败] 开头；
- 出网规则：沙箱输出里的 payroll-db 之后再搜会被拒；代码本身不算污点，计算类也不算「调过数据类工具」；
- 图谱照记代码和输出；不算观察到系统、不进 SOP、不触发沉淀；不对外开放；统计事件带上计算类的调用次数。
"""
import contextlib
import json
import unittest
import uuid
from unittest.mock import patch

from tests.support import clear_graph

from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage, ToolMessage

from app import graph, playbooks
from app.agent import egress, grow, ops_client, registry, sandbox, web_search
from app.agent import loop as agent_loop
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app as web_app

LOGS = {"container_logs": {"desc": "看容器日志", "params": {
    "name": {"type": "str", "pattern": "name", "required": True, "desc": "容器名"}}}}
FOUND = [{"title": "官方文档", "url": "https://docs.example.com/oom", "snippet": "OOMKilled 的含义"}]
TOKEN = "s" * 32


class FakeTool:
    """数据类工具的替身：outputs 是列表时按调用次序依次返回。"""

    def __init__(self, name, output):
        self.name, self.calls = name, []
        self.outputs = list(output) if isinstance(output, list) else None
        self.output = output

    def invoke(self, args):
        self.calls.append(args)
        return self.outputs.pop(0) if self.outputs is not None else self.output


class FakeSandbox:
    """沙箱服务 /run 的替身：记下每次请求，回一个固定的结果。"""

    def __init__(self, stdout="42\n", status="ok", exit_code=0, stderr=""):
        self.requests = []
        self.reply = {"ok": True, "status": status, "exit_code": exit_code, "stdout": stdout,
                      "stdout_truncated": False, "stderr": stderr, "stderr_truncated": False, "duration_ms": 1234}

    def __call__(self, code, files, caller=""):
        self.requests.append({"code": code, "files": files, "caller": caller})
        return dict(self.reply)


def scripted(script, seen):
    """按剧本回复的模型；记下每次绑定的工具、每次调用时 python_exec 的说明和看到的消息。"""
    rounds = iter(script)

    class Bound:
        def __init__(self, tools):
            self.tools = tools

        def invoke(self, messages):
            exec_tool = next((t for t in self.tools if t.name == sandbox.NAME), None)
            seen.setdefault("calls", []).append({"tools": [t.name for t in self.tools], "messages": list(messages),
                                                 "exec": exec_tool.description if exec_tool else None})
            calls, content = next(rounds)
            return AIMessage(content=content, tool_calls=calls)

    class Model:
        def bind_tools(self, tools, **kwargs):
            seen.setdefault("binds", []).append([t.name for t in tools])
            return Bound(list(tools))

    return Model()


def call(tool, cid, **args):
    return [{"name": tool, "args": args, "id": cid}]


@contextlib.contextmanager
def configured():
    """配上沙箱服务（地址不会真的连：要么 post 打桩，要么指向测试里起的服务）。"""
    with patch.object(sandbox, "SANDBOX_URL", "http://127.0.0.1:9"), patch.object(sandbox, "SANDBOX_TOKEN", TOKEN):
        yield


def run_agent(script, *, output="", question="问题", on=True, fake=None, allow_web=False, execution_id=None,
              thread_id=None):
    seen, fake = {}, fake or FakeSandbox()
    tool = FakeTool("container_logs", output)
    search = patch.object(web_search, "search", side_effect=lambda q: (q, FOUND))
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(agent_loop, "build_tools", return_value=[tool]))
        stack.enter_context(patch.object(ops_client, "available_tools", return_value=LOGS))
        stack.enter_context(patch.object(agent_loop, "chat_model", return_value=scripted(script, seen)))
        stack.enter_context(patch.object(sandbox, "post", side_effect=fake))
        stack.enter_context(patch.object(web_search, "enabled", return_value=allow_web))
        seen["search"] = stack.enter_context(search)
        if on:
            stack.enter_context(configured())
        events = list(agent_loop.run(question, "片段", [], allow_web=allow_web, execution_id=execution_id,
                                     thread_id=thread_id))
    return events, seen, fake, tool


def results(events, tool=None):
    return [p["preview"] for k, p in events if k == "tool_result" and (tool is None or p["tool"] == tool)]


# --- 开关 ---------------------------------------------------------------------------------

class SwitchTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def test_nothing_changes_without_sandbox_url(self):
        self.assertFalse(sandbox.enabled())
        with patch.object(sandbox, "SANDBOX_URL", "http://127.0.0.1:9"):
            self.assertFalse(sandbox.enabled())       # 没有令牌也不算配好
        self.assertNotIn(sandbox.NAME, [t.name for t in registry.app_tools(registry.TurnOptions())])
        self.assertFalse(registry.has_tools())
        events, seen, fake, _ = run_agent([([], "答")], on=False)
        self.assertEqual(seen["binds"], [["container_logs"]])
        self.assertEqual(seen["calls"][0]["messages"][0].content, agent_loop.AGENT_PROMPT + agent_loop.NO_WEB_RULES)
        self.assertEqual(events, [("delta", "答")])           # 没有 stats 事件
        self.assertEqual(fake.requests, [])

    def test_configured_it_is_bound_with_its_rules_and_more_rounds(self):
        with configured():
            self.assertTrue(registry.has_tools())             # 只配了沙箱也走 Agent 分支
            tool = next(t for t in registry.app_tools(registry.TurnOptions()) if t.name == sandbox.NAME)
        self.assertEqual(registry.meta_of(tool.contract),
                         {"category": "compute", "provider": "sandbox", "export": False, "group": "计算"})
        self.assertEqual(registry.category_of(sandbox.NAME), "compute")
        self.assertEqual(tool.contract["inputSchema"]["required"], ["code"])
        events, seen, _, _ = run_agent([([], "答")])
        self.assertEqual(seen["binds"], [["container_logs", sandbox.NAME]])
        self.assertEqual(seen["calls"][0]["messages"][0].content,
                         agent_loop.AGENT_PROMPT + agent_loop.EXEC_RULES + agent_loop.NO_WEB_RULES)
        self.assertEqual(events[-1][0], "stats")
        forever = [(call(sandbox.NAME, f"c{i}", code="print(1)"), "") for i in range(30)]
        events, _, fake, _ = run_agent(forever)
        self.assertEqual(len([k for k, _ in events if k == "tool_call"]), agent_loop.MAX_ROUNDS)
        self.assertEqual(len(fake.requests), 3)              # 每轮最多算 3 次
        self.assertTrue(all(r.startswith("[未执行] 本轮已运行 3 次计算，不能再算") for r in results(events)[3:]))

    def test_it_is_never_offered_to_external_agents(self):
        with configured():
            self.assertNotIn(sandbox.NAME, [t.name for t in registry.exported_app_tools()])
        self.assertFalse(registry.exportable(sandbox.TOOL))
        self.assertFalse(registry.POLICIES["compute"].export)


# --- 说明与挂载的数据 -----------------------------------------------------------------------

class FilesTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def test_the_description_lists_this_turns_files_before_each_model_call(self):
        script = [(call("container_logs", "1", name="kb-app"), ""), (call(sandbox.NAME, "2", code="print(1)"), ""),
                  ([], "答")]
        events, seen, fake, _ = run_agent(script, output="a\nbb\nccc")
        described = [c["exec"] for c in seen["calls"]]
        self.assertIn("本轮还没有数据文件", described[0])
        self.assertIn("- /data/01-container_logs.txt：第 1 次数据调用 container_logs（name=kb-app），8 字、3 行",
                      described[1])
        self.assertIn("前几轮的数据不在这里", described[1])
        self.assertEqual(described[2], described[1])
        self.assertEqual(len(seen["binds"]), 2)               # 一开始绑一次；查到数据后现算说明、再绑一次
        self.assertEqual(fake.requests[0]["files"], [{"name": "01-container_logs.txt", "content": "a\nbb\nccc"}])
        self.assertTrue(fake.requests[0]["caller"].startswith("agent conversation="))

    def test_the_sandbox_gets_the_full_return_not_what_the_model_saw(self):
        output = "\n".join(f"{i:04d} request ok" for i in range(500))
        script = [(call("container_logs", "1", name="kb-app"), ""), (call(sandbox.NAME, "2", code="print(1)"), ""),
                  ([], "答")]
        _, seen, fake, _ = run_agent(script, output=output)
        shown = next(m for m in seen["calls"][1]["messages"] if isinstance(m, ToolMessage)).content
        self.assertIn("中间省略", shown)
        self.assertNotIn("0250 request ok", shown)
        self.assertEqual(fake.requests[0]["files"][0]["content"], output)

    def test_only_this_turns_data_is_mounted(self):
        thread, fake = uuid.uuid4().hex, FakeSandbox()
        for turn in ("turn-one-data", "turn-two-data"):
            run_agent([(call("container_logs", f"{turn}-1", name="kb-app"), ""),
                       (call(sandbox.NAME, f"{turn}-2", code="print(1)"), ""), ([], "答")],
                      output=turn, fake=fake, thread_id=thread)
        run_agent([(call(sandbox.NAME, "third", code="print(1)"), ""), ([], "答")], fake=fake, thread_id=thread)
        self.assertEqual([[(f["name"], f["content"]) for f in r["files"]] for r in fake.requests],
                         [[("01-container_logs.txt", "turn-one-data")], [("01-container_logs.txt", "turn-two-data")], []])
        agent_loop.forget(thread)

    def test_failed_data_calls_are_not_mounted(self):
        script = [(call("container_logs", "1", name="kb-app"), ""), (call(sandbox.NAME, "2", code="print(1)"), ""),
                  ([], "答")]
        _, seen, fake, _ = run_agent(script, output="[执行失败] 容器不存在")
        self.assertEqual(fake.requests[0]["files"], [])
        self.assertIn("本轮还没有数据文件", seen["calls"][1]["exec"])

    def test_files_that_do_not_fit_are_listed_but_not_mounted(self):
        script = [(call("container_logs", "1", name="kb-app") + call("container_logs", "2", name="web01"), ""),
                  (call(sandbox.NAME, "3", code="print(1)"), ""), ([], "答")]
        for limit in ({"INPUT_MAX": 10}, {"FILES_MAX": 1}):
            with self.subTest(limit=limit), patch.multiple(sandbox, **limit):
                events, seen, fake, _ = run_agent(script, output=["123456", "abcdef"])
                self.assertIn("- /data/02-container_logs.txt：第 2 次数据调用 container_logs（name=web01），6 字、1 行"
                              "——超过挂载上限", seen["calls"][1]["exec"])
                self.assertEqual([f["name"] for f in fake.requests[0]["files"]], ["01-container_logs.txt"])
                self.assertIn("挂载了 1 个数据文件，另有 1 个超过挂载上限没有挂载", results(events, sandbox.NAME)[0])
        self.assertEqual((sandbox.FILES_MAX, sandbox.INPUT_MAX), (64, 4 * 1024 * 1024))   # 和沙箱服务的上限一致

    def test_file_names_only_use_safe_characters(self):
        self.assertEqual(sandbox.file_name(3, "holiday__holiday_calendar"), "03-holiday__holiday_calendar.txt")
        self.assertEqual(sandbox.file_name(12, "查询/../x y"), "12-x_y.txt")
        self.assertEqual(sandbox.file_name(1, "中文"), "01-tool.txt")


# --- 结果 ---------------------------------------------------------------------------------

class ResultTests(unittest.TestCase):
    def test_results_say_they_are_computation_not_instructions(self):
        text = sandbox.render({"status": "ok", "exit_code": 0, "stdout": "42\n", "duration_ms": 1500}, 2, 0)
        self.assertEqual(text.splitlines()[0], sandbox.HEADER)
        self.assertIn("退出状态 0，耗时 1.5 秒；挂载了 2 个数据文件。", text)
        self.assertIn("stdout（共 2 字）：\n42", text)
        self.assertIn("stdout：（空。结果要用 print 输出）", sandbox.render({"status": "ok", "exit_code": 0}, 0, 0))
        cut = sandbox.render({"status": "ok", "exit_code": 0, "stdout": "x", "stdout_truncated": True}, 0, 0)
        self.assertIn("stdout（共 1 字，超过 32KB 的部分已截断）：\nx", cut)

    def test_unfinished_runs_are_failures_that_say_why(self):
        for status, words in (("timeout", "代码运行超过 20 秒上限，已被终止"), ("oom", "代码用的内存超过 256MB 上限"),
                              ("killed", "代码被强制终止"), ("output_limit", "输出超过 32KB 上限"),
                              ("error", "代码出错退出（退出码 1）")):
            with self.subTest(status=status):
                text = sandbox.render({"status": status, "exit_code": 1, "stdout": "partial",
                                       "stderr": "Traceback (most recent call last):\nValueError: x"}, 0, 0)
                self.assertTrue(text.startswith(f"[执行失败] {words}"))
                self.assertIn(sandbox.HEADER, text)
                self.assertIn("stderr（末尾）：\nTraceback (most recent call last):\nValueError: x", text)
                self.assertIn("partial", text)

    def test_a_long_print_does_not_push_the_traceback_out_of_view(self):
        """给模型的结果会截到 STORE_TOOL_CHARS 字：先打印一大堆再报错，堆栈也要留在模型看得到的那一段里。"""
        text = sandbox.render({"status": "error", "exit_code": 1, "stdout": "row\n" * 5000,
                               "stderr": "Traceback (most recent call last):\nKeyError: 'payroll-db'"}, 1, 0)
        shown = agent_loop._clip(text, agent_loop.STORE_TOOL_CHARS)
        self.assertIn("KeyError: 'payroll-db'", shown)
        self.assertIn("stdout（共 19999 字）", shown)
        self.assertTrue(shown.endswith("…（已截断）"))

    def test_code_is_checked_before_anything_is_sent(self):
        with configured(), patch.object(sandbox, "post") as post:
            for args in ({"code": "  "}, {}, {"code": 1}):
                self.assertTrue(sandbox.run_tool(args, registry.Turn()).startswith("[执行失败] code 不能为空"))
            self.assertTrue(sandbox.run_tool({"code": "x" * (sandbox.CODE_MAX + 1)}, registry.Turn())
                            .startswith("[执行失败] 代码太长"))
        post.assert_not_called()

    def test_an_unavailable_sandbox_is_a_failed_call(self):
        busy = sandbox.Unavailable("沙箱正忙：同时最多运行 1 个，请稍后再试")
        with configured(), patch.object(sandbox, "post", side_effect=busy):
            text = sandbox.run_tool({"code": "print(1)"}, registry.Turn())
        self.assertEqual(text, "[执行失败] 计算沙箱不可用：沙箱正忙：同时最多运行 1 个，请稍后再试")
        self.assertEqual(sandbox.run_tool({"code": "print(1)"}, registry.Turn()),
                         "[执行失败] 计算沙箱不可用：未配置沙箱服务（SANDBOX_URL / SANDBOX_TOKEN）")


# --- 出网规则 -------------------------------------------------------------------------------

class EgressTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def test_sandbox_output_taints_later_searches(self):
        script = [(call(sandbox.NAME, "1", code="print(name)"), ""),
                  (call("web_search", "2", query="payroll-db OOMKilled"), ""), ([], "完")]
        events, seen, _, _ = run_agent(script, fake=FakeSandbox(stdout="payroll-db 出现了 3 次\n"), allow_web=True)
        self.assertTrue(results(events, "web_search")[0].startswith(
            "[未搜索] 搜索词里含有本轮数据里出现过的标识符「payroll-db」"))
        seen["search"].assert_not_called()

    def test_what_only_the_sandbox_printed_is_caught_too(self):
        """长日志压缩后模型看不到中间那行；用沙箱把它找出来、打印出来之后，它也算污点。"""
        output = "\n".join([f"{i:04d} request ok" for i in range(250)] + ["0250 upstream payroll-db slow"]
                           + [f"{i:04d} request ok" for i in range(251, 500)])
        search_first = [(call("container_logs", "1", name="kb-app"), ""),
                        (call("web_search", "2", query="payroll-db slow upstream"), ""), ([], "完")]
        _, seen, _, _ = run_agent(search_first, output=output, allow_web=True)
        self.assertEqual(seen["search"].call_count, 1)        # 模型看到的压缩版里没有它：不算污点
        compute_first = [(call("container_logs", "1", name="kb-app"), ""),
                         (call(sandbox.NAME, "2", code="print(slow lines)"), ""),
                         (call("web_search", "3", query="payroll-db slow upstream"), ""), ([], "完")]
        events, seen, fake, _ = run_agent(compute_first, output=output, allow_web=True,
                                          fake=FakeSandbox(stdout="0250 upstream payroll-db slow\n"))
        self.assertIn("0250 upstream payroll-db slow", fake.requests[0]["files"][0]["content"])
        seen["search"].assert_not_called()
        self.assertIn("「payroll-db」", results(events, "web_search")[0])

    def test_code_is_not_taint_and_computing_is_not_querying_data(self):
        script = [(call(sandbox.NAME, "1", code="# zz-top99\nprint(6 * 7)"), ""),
                  (call("web_search", "2", query="zz-top99 release notes"), ""), ([], "完")]
        _, seen, _, _ = run_agent(script, allow_web=True)
        self.assertEqual(seen["search"].call_count, 1)
        with patch.object(egress, "WEB_AFTER_DATA", "deny"):
            _, seen, _, _ = run_agent(script, allow_web=True)
            self.assertEqual(seen["search"].call_count, 1)    # 只算不查，严格模式下照样能搜
            with_data = [(call("container_logs", "0", name="kb-app"), "")] + script
            events, seen, _, _ = run_agent(with_data, output="ok", allow_web=True)
            seen["search"].assert_not_called()
            self.assertIn("WEB_AFTER_DATA=deny", results(events, "web_search")[0])


# --- 图谱、SOP、沉淀、统计 ---------------------------------------------------------------------

class RecordTests(unittest.TestCase):
    def setUp(self):
        clear_graph()
        self.client = TestClient(web_app)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def test_graph_keeps_code_and_output_but_computing_does_not_observe_the_system(self):
        run = graph.start_execution("conv", "算一下")
        run_agent([(call(sandbox.NAME, "1", code="print(6 * 7)"), ""), ([], "答：42")], execution_id=run)
        calls = graph.execution(run)["tool_calls"]
        self.assertEqual([(c["tool"], c["args"], c["ok"]) for c in calls], [(sandbox.NAME, {"code": "print(6 * 7)"}, True)])
        self.assertTrue(calls[0]["output"].startswith(sandbox.HEADER))
        self.assertIn("stdout（共 2 字）：\n42", calls[0]["output"])
        self.assertEqual(graph.finish_execution(run, "答：42"), "unknown")
        self.assertEqual(grow.data_calls(graph.execution(run)), [])
        with graph.lock:
            seeded = graph.db.execute("SELECT kind, name FROM entities WHERE kind != 'execution'").fetchall()
        self.assertEqual([tuple(row) for row in seeded], [("tool", sandbox.NAME)])
        failed = graph.start_execution("conv", "算一下")
        run_agent([(call(sandbox.NAME, "1", code="while True: pass"), ""), ([], "答")], execution_id=failed,
                  fake=FakeSandbox(status="timeout", exit_code=137, stdout=""))
        self.assertFalse(graph.execution(failed)["tool_calls"][0]["ok"])

    def test_python_exec_never_goes_into_a_sop(self):
        self.assertFalse(registry.POLICIES["compute"].sop)
        self.assertFalse(registry.observes_system(sandbox.NAME))
        with configured(), patch.object(ops_client, "available_tools", return_value=LOGS):
            known = set(registry.sop_tools())
            specs = registry.sop_specs()
        self.assertEqual((known, set(specs)), ({"container_logs"}, {"container_logs"}))
        with self.assertRaises(playbooks.InvalidPlaybook):
            playbooks.validate("统计错误", "日志里错误多", [{"tool": sandbox.NAME, "args": {"code": "print(1)"}}], known)

    def test_compute_only_turns_do_not_trigger_sop_growth(self):
        hits = [{"index": 1, "location": "手册.pdf", "text": "x", "score": 0.6}]

        def compute_only(question, context, history, **kwargs):
            yield "tool_call", {"tool": sandbox.NAME, "args": {"code": "print(1)"}, "category": "compute"}
            yield "tool_result", {"tool": sandbox.NAME, "preview": "1", "lines": 1, "chars": 1}
            yield "delta", "答案"

        with configured(), \
                patch("app.main.retrieve", return_value=hits), \
                patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
                patch("app.main.AGENT_MODE", "auto"), \
                patch("app.main.agent_loop.run", side_effect=compute_only) as run, \
                patch("app.main.grow.schedule") as schedule:
            response = self.client.post("/api/ask", json={"question": "算一下"}, auth=self.auth)
        run.assert_called_once()                              # 只配了沙箱也走 Agent 分支
        schedule.assert_not_called()
        events = [json.loads(line) for line in response.text.splitlines() if line]
        replay = self.client.get(f"/api/conversations/{events[0]['conversation']['id']}", auth=self.auth).json()
        self.assertEqual(replay["messages"][-1]["tools"], [{"tool": sandbox.NAME, "args": {"code": "print(1)"},
                                                             "category": "compute", "preview": "1", "lines": 1}])

    def test_stats_count_compute_calls(self):
        script = [(call("container_logs", "1", name="kb-app") + call(sandbox.NAME, "2", code="print(1)"), ""),
                  ([], "答")]
        events, _, _, _ = run_agent(script, output="ok")
        kind, stats = events[-1]
        self.assertEqual((kind, stats["calls"], stats["tool_rounds"]), ("stats", {"data": 1, "compute": 1}, 1))
        self.assertEqual({p["category"] for k, p in events if k == "tool_call"}, {"data", "compute"})


# --- 接真的沙箱服务（起容器那一层打桩）---------------------------------------------------------

class ServiceProtocolTests(unittest.TestCase):
    def test_the_app_talks_to_the_real_service(self):
        from tests.test_sandbox_service import TOKEN as SERVICE_TOKEN, Service, svc
        service = Service()
        self.addCleanup(service.close)
        turn = registry.Turn(caller="agent conversation=abc execution=def", outputs=[
            {"seq": 1, "tool": "container_logs", "args": {"name": "kb-app"}, "output": "第一行\nERROR x\n"}])
        with patch.object(svc, "log") as logged, patch.object(sandbox, "SANDBOX_URL", service.url), \
                patch.object(sandbox, "SANDBOX_TOKEN", SERVICE_TOKEN):
            text = sandbox.run_tool({"code": "print(6 * 7)"}, turn)
        self.assertTrue(text.startswith(sandbox.HEADER))
        self.assertIn("挂载了 1 个数据文件", text)
        self.assertIn("42", text)
        self.assertEqual(next(iter(service.docker.mounted.values())),
                         {"01-container_logs.txt": "第一行\nERROR x\n".encode("utf-8")})
        self.assertIn("caller=agent conversation=abc execution=def status=ok", logged.call_args.args[0])
        with patch.object(svc, "log"), patch.object(sandbox, "SANDBOX_URL", service.url), \
                patch.object(sandbox, "SANDBOX_TOKEN", "wrong-token-0123456789"):
            self.assertEqual(sandbox.run_tool({"code": "print(1)"}, registry.Turn()),
                             "[执行失败] 计算沙箱不可用：令牌无效")


if __name__ == "__main__":
    unittest.main()
