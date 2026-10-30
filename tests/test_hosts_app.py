"""远程主机（M4）的应用侧：target 的实参播种成主机实体（@组 记成主机组）、成为出网污点、经对外 MCP 可用；
页面申请命令工具能带适用分组，工具面板拿得到主机清单。

工具清单用真的工具服务（deploy/ops_readonly.py）在主机模式下生成，应用侧看到的就是线上会看到的样子。
"""
import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph

from langchain_core.messages import AIMessage

from app import access, graph, mcp_server
from app.agent import egress, ops_client, registry, web_fetch, web_search
from app.agent import loop as agent_loop
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

CONFIG = textwrap.dedent("""\
    tools:
      - {name: host_disk, label: 磁盘用量, desc: 看磁盘, export: true, impl: {type: command, argv: [df, -h], os: linux}}
    hosts:
      defaults: {user: opsread, key: "${ssh_key}", os: linux}
      list:
        - {name: gw-01, address: 10.0.0.2, groups: [prod]}
        - {name: db-02, address: 10.0.0.3, groups: [prod]}
    """)


def hosts_payload():
    """主机模式下工具服务的 /tools，原样过一遍 JSON（和走 HTTP 一样）。"""
    with tempfile.TemporaryDirectory() as tmp:
        main = Path(tmp) / "ops_tools.yaml"
        main.write_text(CONFIG, encoding="utf-8")
        with patch.dict(ops._state, {"path": main, "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
                                     "mmtime": None, "includes": [], "tools": {}, "problems": [], "mcp_servers": {},
                                     "connections": {}, "hosts": None}), \
                patch.object(ops, "HOST_OS", "linux"), \
                patch.object(ops.shutil, "which", lambda name: f"/usr/bin/{name}"), \
                patch.dict(ops._host_status, {}, clear=True), \
                patch.object(ops._monitor, "wake", lambda: None):
            ops.refresh(force=True)
            return json.loads(json.dumps(ops.available_tools(), ensure_ascii=False))


PAYLOAD = hosts_payload()


class ContractTests(unittest.TestCase):
    def test_the_app_keeps_the_target_contract(self):
        with patch.object(ops_client, "available_tools", return_value=PAYLOAD):
            entry = registry.data_tools()["host_disk"]
        prop = entry["inputSchema"]["properties"]["target"]
        self.assertEqual((prop["x-entity"], prop["x-default"]), ("host", "local"))
        self.assertNotIn("default", prop)
        self.assertEqual(prop["enum"], ["local", "gw-01", "db-02", "@prod", "@all"])
        public = registry.public_contract(registry.as_contract("host_disk", entry))
        self.assertNotIn("x-entity", public["inputSchema"]["properties"]["target"])
        self.assertNotIn("x-default", public["inputSchema"]["properties"]["target"])
        self.assertEqual(public["inputSchema"]["properties"]["target"]["enum"], prop["enum"])


class GraphTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def test_target_values_seed_hosts_and_groups(self):
        schema = PAYLOAD["host_disk"]["inputSchema"]
        run = graph.start_execution("c", "看磁盘")
        graph.record_tool_call(run, "host_disk", {"target": "gw-01"}, "/dev/vda1 41%", True, 3, schema=schema)
        graph.record_tool_call(run, "host_disk", {"target": "@prod"}, "== gw-01（成功）==", True, 3, schema=schema)
        graph.record_tool_call(run, "host_disk", {"target": "db-02"}, "连不上", False, 3, schema=schema)
        self.assertIsNotNone(graph.entity("host", "gw-01"))
        self.assertIsNotNone(graph.entity("host_group", "prod"))
        self.assertIsNone(graph.entity("host", "@prod"))
        self.assertIsNone(graph.entity("host", "db-02"))   # 失败的调用不播种
        self.assertEqual(graph.entity("host", "gw-01")["attrs"], {"param": "target"})
        self.assertEqual([f["object"] for f in graph.facts_of("host", "gw-01", "checked_by")], [("tool", "host_disk")])
        self.assertEqual([f["object"] for f in graph.facts_of("host_group", "prod", "checked_by")],
                         [("tool", "host_disk")])


def call(tool, cid, **args):
    return [{"name": tool, "args": args, "id": cid}]


class EgressTests(unittest.TestCase):
    """target 的实参是内部对象：本轮不能再随搜索词发出去（M3b 按 x-entity 收污点，这里钉住它覆盖了 target）。"""

    def setUp(self):
        clear_graph()

    def test_a_queried_host_never_reaches_the_search_engine(self):
        sent = []

        def execute(name, args):
            sent.append((name, args))
            return {"ok": True, "output": "/dev/vda1  40G  37G  3G  93% /"}

        rounds = iter([(call("host_disk", "1", target="gw-01"), ""),
                       (call("web_search", "2", query="gw-01 磁盘满了怎么清理"), ""),
                       (call("web_search", "3", query="linux 磁盘满了怎么清理"), ""),
                       ([], "完")])

        class Bound:
            def invoke(self, messages):
                calls, content = next(rounds)
                return AIMessage(content=content, tool_calls=calls)

        class Model:
            def bind_tools(self, tools):
                return Bound()

        with patch.object(ops_client, "available_tools", return_value=PAYLOAD), \
                patch.object(ops_client, "enabled", return_value=True), \
                patch.object(ops_client, "execute", side_effect=execute), \
                patch.object(agent_loop, "chat_model", return_value=Model()), \
                patch.object(web_search, "enabled", return_value=True), \
                patch.object(web_fetch, "enabled", return_value=False), \
                patch.object(web_search, "search", side_effect=lambda q: (q, [])) as search:
            events = list(agent_loop.run("磁盘快满了吗", "片段", [], allow_web=True))
        results = [p["preview"] for k, p in events if k == "tool_result"]
        self.assertEqual(sent, [("host_disk", {"target": "gw-01"})])
        self.assertTrue(results[1].startswith("[未搜索] 搜索词里含有本轮查过的内部对象「gw-01」"), results[1])
        self.assertEqual([c.args[0] for c in search.call_args_list], ["linux 磁盘满了怎么清理"])

    def test_the_rule_is_the_x_entity_declaration(self):
        turn = registry.Turn()
        turn.usage[egress.STATE] = egress.start("")
        egress.observe(turn, PAYLOAD["host_disk"]["inputSchema"], {"target": "db-02"}, "（没有输出）")
        with self.assertRaises(egress.Refused):
            egress.check_query(turn, "db-02 慢")

    def test_the_implicit_default_host_is_not_taint(self):
        """不填 target 时应用发的是 null：本机的名字 local 这种常见词不会每轮都被记成污点、拦掉正常的搜索。"""
        sent = []

        def execute(name, args):
            sent.append((name, args))
            return {"ok": True, "output": "/dev/vda1 41%"}

        rounds = iter([(call("host_disk", "1"), ""), (call("web_search", "2", query="local DNS 解析失败怎么办"), ""),
                       ([], "完")])

        class Bound:
            def invoke(self, messages):
                calls, content = next(rounds)
                return AIMessage(content=content, tool_calls=calls)

        class Model:
            def bind_tools(self, tools):
                return Bound()

        with patch.object(ops_client, "available_tools", return_value=PAYLOAD), \
                patch.object(ops_client, "enabled", return_value=True), \
                patch.object(ops_client, "execute", side_effect=execute), \
                patch.object(agent_loop, "chat_model", return_value=Model()), \
                patch.object(web_search, "enabled", return_value=True), \
                patch.object(web_fetch, "enabled", return_value=False), \
                patch.object(web_search, "search", side_effect=lambda q: (q, [])) as search:
            list(agent_loop.run("磁盘快满了吗", "片段", [], allow_web=True))
        self.assertEqual(sent, [("host_disk", {"target": None})])
        self.assertEqual([c.args[0] for c in search.call_args_list], ["local DNS 解析失败怎么办"])


class McpExportTests(unittest.TestCase):
    """带 target 的数据工具标了 export，经 /mcp 照样能用：target 在 schema 里（剥掉 x-entity），实参原样转给 /exec。"""

    def setUp(self):
        clear_graph()
        with access.lock:
            access.db.execute("DELETE FROM mcp_tokens")
            access.db.execute("DELETE FROM mcp_calls")
            access.db.commit()
        for p in (patch.object(ops_client, "available_tools", return_value=PAYLOAD),
                  patch.object(ops_client, "enabled", return_value=True)):
            p.start()
            self.addCleanup(p.stop)
        self.client = access.Client(id=uuid.uuid4().hex[:12], name="外部", scopes=frozenset({"data"}),
                                    categories=None, rate_per_minute=60, max_result_chars=20000)

    def test_listed_and_callable_with_a_target(self):
        listed = {tool["name"]: tool for tool in mcp_server.list_tools(self.client)}
        prop = listed["host_disk"]["inputSchema"]["properties"]["target"]
        self.assertEqual(prop["enum"], ["local", "gw-01", "db-02", "@prod", "@all"])
        self.assertNotIn("x-entity", prop)
        self.assertEqual(len(mcp_server.tool_models([listed["host_disk"]])), 1)
        sent = []

        def request(path, payload=None, timeout=30, headers=None):
            sent.append(payload)
            return {"ok": True, "output": "== gw-01（成功）==\n/dev/vda1 41%"}

        with patch.object(ops_client, "_request", side_effect=request):
            text, ok = mcp_server.call_tool(self.client, "host_disk", {"target": "@prod"})
            default, _ = mcp_server.call_tool(self.client, "host_disk", {})
            bad, bad_ok = mcp_server.call_tool(self.client, "host_disk", {"target": "evil;id"})
        self.assertTrue(ok)
        self.assertIn("gw-01", text)
        # 不填 target 时应用不替模型填：发 null，由工具服务按默认规则补上本机
        self.assertEqual(sent, [{"tool": "host_disk", "args": {"target": "@prod"}},
                                {"tool": "host_disk", "args": {"target": None}}])
        self.assertFalse(bad_ok)
        self.assertTrue(bad.startswith("[执行失败]"))


class PageApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def test_command_proposals_carry_their_host_groups(self):
        with patch.object(ops_client, "propose", return_value={"pending": {"id": "abc"}}) as propose:
            def sent(body):
                response = self.client.post("/api/tools/propose", json=body, auth=self.auth)
                self.assertEqual(response.status_code, 200, response.text)
                return propose.call_args[0][0]

            command = sent({"name": "nginx_status", "desc": "看 nginx", "binary": "nginx", "argv": ["nginx", "-T"],
                            "os": ["linux"], "groups": ["web", "prod"], "params": {}})
            self.assertEqual(command["groups"], ["web", "prod"])
            plain = sent({"name": "who_is_on", "desc": "看登录用户", "binary": "who", "argv": ["who"], "params": {}})
            self.assertNotIn("groups", plain)
            http = sent({"name": "prom_metric", "desc": "查指标", "groups": ["web"], "params": {},
                         "http": {"url": "/api/v1/query", "conn": "prom"}})
            self.assertNotIn("groups", http)

    def test_the_overview_carries_the_host_list(self):
        hosts = {"configured": True, "default": "local", "local": "local", "enum_max": 30, "groups": {},
                 "list": {"b": {"via": "ssh", "mode": "direct", "address": "10.0.0.2", "port": 22, "user": "u",
                                "os": "linux", "groups": [], "tools": None, "readonly": "账号权限", "status": None}}}
        with patch.object(ops_client, "describe_tools", return_value={"tools": {}, "hosts": hosts}):
            got = self.client.get("/api/tools", auth=self.auth).json()
        self.assertEqual(got["hosts"], hosts)
        with patch.object(ops_client, "describe_tools", return_value={"tools": {}}):
            self.assertEqual(self.client.get("/api/tools", auth=self.auth).json()["hosts"], {"configured": False})

    def test_the_page_knows_how_to_show_hosts(self):
        page = (REPO / "app" / "web" / "index.html").read_text(encoding="utf-8")
        for needle in ("function tlHostLine", "function hostsHtml", "只读靠账号权限", "tlNewGroups", "适用分组"):
            self.assertIn(needle, page)
