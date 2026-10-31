"""统一工具契约：工具服务按 MCP 的 Tool 格式下发契约字段，应用内注册表按类别定策略。

新旧对照钉在这里：deploy/ops_tools.yaml 和 packs/*/tools.yaml 的每个工具，改走契约之后——
工具清单、模型看到的签名、发给 /exec 的参数、图谱播种的实体类型与属性、SOP 校验结果——都和改造前一样。
改造前的做法（tools.py 的老签名生成、graph.py 的 _entity_kind、main.py 的 usable_tools）原样抄在下面当参照。
"""
import importlib.util
import json
import sys
import unittest
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, TypedDict
from unittest.mock import patch

from fastapi.testclient import TestClient

from tests.support import clear_graph

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field, ValidationError, create_model

from app import graph, playbooks
from app.agent import grow, ops_client, registry, web_search
from app.agent import loop as agent_loop
from app.agent import tools as agent_tools
from app.config import WEB_PASSWORD, WEB_USER
from app.main import app as web_app

REPO = Path(__file__).resolve().parent.parent
CONFIGS = [REPO / "deploy" / "ops_tools.yaml"] + sorted(REPO.glob("packs/*/tools.yaml"))
CONTRACT_FIELDS = ["_meta", "annotations", "inputSchema", "title"]

if "ops_readonly" in sys.modules:
    ops = sys.modules["ops_readonly"]
else:
    _SPEC = importlib.util.spec_from_file_location("ops_readonly", REPO / "deploy" / "ops_readonly.py")
    ops = importlib.util.module_from_spec(_SPEC)
    sys.modules["ops_readonly"] = ops
    _SPEC.loader.exec_module(ops)


def advertised(config):
    """工具服务对这份配置下发的 /tools（假装命令本机都有、本机就是目标平台 Linux），按 HTTP 往返一遍。"""
    state = {"path": Path(config), "mtime": None, "omtime": None, "tmtime": None, "imtime": None,
             "mmtime": None, "includes": [], "tools": {}, "problems": [], "mcp_servers": {}}
    with patch.dict(ops._state, state), patch.object(ops.shutil, "which", return_value="/usr/bin/true"), \
            patch.object(ops, "HOST_OS", "linux"):
        ops.refresh(force=True)
        return json.loads(json.dumps(ops.available_tools(), ensure_ascii=False)), dict(ops._state["tools"])


def legacy(payload):
    """老工具服务的 /tools：只有 desc、params（MCP 工具多一份 input_schema）。"""
    return {name: {k: v for k, v in meta.items() if k in ("desc", "params", "input_schema")}
            for name, meta in payload.items()}


SAMPLE = {"name": "kb-app", "k8s_name": "web-0", "resource": "pod", "date": "2026-10-01"}


def sample_args(params, everything):
    args = {}
    for key, spec in params.items():
        if not (everything or spec.get("required")):
            continue
        if spec.get("type") == "int":
            args[key] = {"year": 2026, "lines": 50}.get(key, spec.get("min", 1))
        else:
            args[key] = SAMPLE.get(spec.get("pattern"), "kb-app")
    return args


# --- 改造前的做法（原样抄来，当参照）---------------------------------------------------

_SCALAR = (str, int, float, bool)


def legacy_field(spec):
    """改造前 app/agent/tools.py 的 _field。"""
    description = str(spec.get("desc") or "")
    kind = spec.get("type")
    required = bool(spec.get("required"))
    if kind == "int":
        if required and "default" not in spec:
            return int, Field(description=description)
        return int, Field(default=int(spec.get("default", 100)), description=description)
    if kind in ("float", "bool", "json", "enum"):
        annotation = {"float": float, "bool": bool, "json": Any}.get(kind, str)
        values = tuple(v for v in (spec.get("enum") or []) if isinstance(v, _SCALAR))
        if kind == "enum" and values:
            annotation = Literal[values]
        if required:
            return annotation, Field(description=description)
        default = spec.get("default") if isinstance(spec.get("default"), _SCALAR) else None
        return Optional[annotation], Field(default=default, description=description)
    if required:
        return str, Field(description=description)
    return str, Field(default=str(spec.get("default", "")), description=description)


def legacy_tool(name, meta, sent):
    """改造前按 params 生成的工具（_args_schema + _make），执行时把参数记进 sent。"""
    params = meta.get("params") or {}
    schema = create_model(f"{name}_args", **{k: legacy_field(s) for k, s in params.items()}) \
        if params else agent_tools.Empty
    return StructuredTool.from_function(func=lambda **kwargs: sent.append(kwargs) or "ok", name=name,
                                        description=meta.get("desc", ""), args_schema=schema)


def legacy_entity_kind(key, pattern, args):
    """改造前 app/graph.py 的 _entity_kind。"""
    if pattern not in ("name", "k8s_name"):
        return None
    if key == "namespace":
        return "namespace"
    if pattern == "k8s_name":
        return "k8s_object"
    return "container" if key == "name" else key


def legacy_seeds(args, params):
    """改造前 record_tool_call 播下的对象实体：{(kind, name, attrs)}。"""
    out = set()
    for key, value in args.items():
        spec = (params or {}).get(key)
        pattern = spec.get("pattern") if isinstance(spec, dict) else None
        kind = legacy_entity_kind(key, pattern, args)
        if not kind or not isinstance(value, str) or not value.strip():
            continue
        attrs = {"param": key, "pattern": pattern}
        if kind == "k8s_object" and args.get("resource"):
            attrs["resources"] = [str(args["resource"])]
        out.add((kind, value.strip(), json.dumps(attrs, sort_keys=True)))
    return out


class LegacyWebQuery(BaseModel):
    """改造前 loop.py 里 web_search 的签名。"""
    query: str = Field(description="搜索关键词。只写公开、通用的词，不要包含内部项目名、IP、账号、密钥。")


def seeded():
    with graph.lock:
        rows = graph.db.execute("SELECT kind, name, attrs FROM entities"
                                " WHERE kind NOT IN ('tool', 'execution')").fetchall()
    return {(r[0], r[1], json.dumps(json.loads(r[2]), sort_keys=True)) for r in rows}


# --- 工具服务一侧：/tools 只增不改 ----------------------------------------------------

class ToolServiceContractTests(unittest.TestCase):
    def test_tools_endpoint_only_adds_contract_fields(self):
        for config in CONFIGS:
            payload, specs = advertised(config)
            self.assertTrue(payload, config)
            for name, meta in payload.items():
                with self.subTest(config=config.parent.name, tool=name):
                    self.assertEqual(sorted(set(meta) - {"desc", "params", "input_schema"}), CONTRACT_FIELDS)
                    # 老字段原样：desc、params 和改造前一样取自工具定义
                    self.assertEqual((meta["desc"], meta["params"]), (specs[name]["desc"], specs[name]["params"]))
                    # 外部工具（实参会发到组织外面：字面公网主机的 holiday_calendar）多一个 external 标记、openWorldHint；
                    # 内部工具的契约字段和以前一个字节都不差
                    external = specs[name].get("external") is True
                    if name == "holiday_calendar":
                        self.assertTrue(external)
                    doc2sop = {"category": "data", "provider": "ops", "export": False, "group": specs[name]["group"]}
                    self.assertEqual(meta["_meta"], {"doc2sop": {**doc2sop, **({"external": True} if external else {})}})
                    self.assertEqual(meta["annotations"], {"readOnlyHint": True, "destructiveHint": False,
                                                           "openWorldHint": external})
                    self.assertEqual(meta["title"], specs[name]["label"] or name)
                    self.assertEqual(meta["inputSchema"]["type"], "object")

    def test_legacy_params_become_json_schema(self):
        payload, _ = advertised(REPO / "deploy" / "ops_tools.yaml")
        logs = payload["container_logs"]["inputSchema"]
        self.assertEqual(logs["required"], ["name"])
        self.assertEqual(logs["properties"]["name"],
                         {"type": "string", "description": "容器名，例如 kb-app", "pattern": ops.NAME.pattern,
                          "x-pattern": "name", "x-entity": "container"})
        self.assertEqual(logs["properties"]["lines"],
                         {"type": "integer", "description": "查看最近多少行，默认 100，最多 500",
                          "minimum": 1, "maximum": 500, "default": 100})
        kube = payload["kube_yaml"]["inputSchema"]["properties"]
        self.assertEqual((kube["name"]["x-entity"], kube["namespace"]["x-entity"]), ("k8s_object", "namespace"))
        self.assertEqual(kube["namespace"]["default"], "default")
        self.assertNotIn("x-entity", kube["resource"])        # 资源类型、日期不是对象名
        self.assertEqual(kube["resource"]["x-pattern"], "resource")
        year = payload["holiday_calendar"]["inputSchema"]
        self.assertEqual(year["required"], ["year"])
        self.assertEqual(year["properties"]["year"],
                         {"type": "integer", "description": year["properties"]["year"]["description"],
                          "minimum": 2007, "maximum": 2035})
        day = payload["date_info"]["inputSchema"]["properties"]["day"]
        self.assertEqual((day["pattern"], day["x-pattern"]), (ops.DATE.pattern, "date"))
        self.assertNotIn("x-entity", day)
        self.assertEqual(payload["host_disk"]["inputSchema"], {"type": "object", "properties": {}})

    def test_regex_is_filled_in_from_the_preset_name(self):
        """配置里仍然只能写预置正则的名字；正则本身由工具服务填进 inputSchema。"""
        for config in CONFIGS:
            payload, _ = advertised(config)
            for name, meta in payload.items():
                for key, prop in meta["inputSchema"]["properties"].items():
                    if prop["type"] != "string":
                        continue
                    with self.subTest(tool=name, param=key):
                        self.assertEqual(prop["x-pattern"], meta["params"][key]["pattern"])
                        self.assertEqual(prop["pattern"], ops.PATTERNS[prop["x-pattern"]].pattern)

    def test_int_with_default_is_optional_like_the_old_signature(self):
        """带默认值的 int 即使写了 required，老签名也是「非必填 + 默认值」；契约照这个来，/exec 参数才不变。"""
        spec = {"type": "int", "desc": "年", "required": True, "default": 2026, "min": 2007, "max": 2035}
        prop, needed = ops._param_schema("year", spec)
        self.assertFalse(needed)
        self.assertEqual(prop["default"], 2026)
        self.assertEqual(registry._param_schema("year", spec), (
            {"description": "年", "type": "integer", "minimum": 2007, "maximum": 2035, "default": 2026}, False))

    def test_mcp_tools_keep_the_server_schema_and_mark_restricted_names(self):
        schema = {"type": "object", "required": ["name"],
                  "properties": {"name": {"type": "string"}, "ns": {"type": "string"}, "n": {"type": "integer"}}}
        spec = {"name": "k8s__pod", "type": "mcp", "label": "", "group": "k8s", "desc": "看 Pod",
                "mcp": {"server": "k8s", "tool": "pod"}, "input_schema": schema,
                "restrict": {"name": {"pattern": "k8s_name"}, "ns": {"pattern": "date"}, "n": {"max": 3}}}
        contract = ops._contract("k8s__pod", spec)
        props = contract["inputSchema"]["properties"]
        self.assertEqual(props["name"], {"type": "string", "x-pattern": "k8s_name", "x-entity": "k8s_object"})
        self.assertEqual(props["ns"], {"type": "string", "x-pattern": "date"})
        self.assertEqual(props["n"], {"type": "integer"})    # 收紧项照旧只在 /exec 执行，不写进 schema
        self.assertNotIn("x-pattern", schema["properties"]["name"])   # server 那份不被改动
        self.assertEqual((contract["title"], contract["_meta"]["doc2sop"]["group"]), ("k8s__pod", "k8s"))

    def test_entity_rule_is_the_same_on_both_sides(self):
        """工具服务和应用侧兜底各有一份 x-entity 规则，必须一致。"""
        for key in ("name", "namespace", "pod", "service", "lines", "day"):
            for pattern in (None, "name", "k8s_name", "resource", "date"):
                with self.subTest(key=key, pattern=pattern):
                    self.assertEqual(ops._entity_of(key, pattern), registry.entity_of(key, pattern))
                    self.assertEqual(registry.entity_of(key, pattern), legacy_entity_kind(key, pattern, {}))


# --- 新旧对照：清单、签名、/exec 参数、图谱播种、SOP 校验 ------------------------------------

class LegacyEquivalenceTests(unittest.TestCase):
    """新应用 × 新工具服务、新应用 × 老工具服务，结果都和改造前（老应用 × 老工具服务）一样。"""

    def setUp(self):
        clear_graph()

    def each_tool(self):
        for config in CONFIGS:
            payload, _ = advertised(config)
            old = legacy(payload)
            with patch.object(ops_client, "available_tools", return_value=old):
                completed = registry.data_tools()
            for name in sorted(payload):
                yield config.parent.name, name, payload[name], old[name], completed[name]

    def test_signatures_shown_to_the_model_are_unchanged(self):
        for where, name, new, old, completed in self.each_tool():
            expected = convert_to_openai_tool(legacy_tool(name, old, []))
            for label, meta in (("新工具服务", new), ("老工具服务", completed), ("老工具服务原样", old)):
                with self.subTest(config=where, tool=name, source=label):
                    built = agent_tools.build_tools({name: meta})
                    self.assertEqual(convert_to_openai_tool(built[0]), expected)

    def test_arguments_sent_to_exec_are_unchanged(self):
        """老签名给可选参数填具体默认值；JSON Schema 这条路也不能把 null 发给工具服务。"""
        for where, name, new, old, _ in self.each_tool():
            for everything in (False, True):
                args = sample_args(old["params"], everything)
                expected = []
                legacy_tool(name, old, expected).invoke(args)
                with self.subTest(config=where, tool=name, args=args), \
                        patch.object(ops_client, "execute", return_value={"ok": True, "output": "ok"}) as execute:
                    agent_tools.build_tools({name: new})[0].invoke(args)
                    self.assertEqual(execute.call_args[0], (name, expected[0]))
                    self.assertNotIn(None, execute.call_args[0][1].values())

    def test_graph_seeding_is_unchanged(self):
        for where, name, new, old, completed in self.each_tool():
            args = sample_args(old["params"], True)
            if "resource" in old["params"]:
                args["resource"] = "pod"
            for label, schema in (("新工具服务", new["inputSchema"]), ("老工具服务", completed["inputSchema"])):
                with self.subTest(config=where, tool=name, source=label):
                    clear_graph()
                    run = graph.start_execution("conv", "q")
                    graph.record_tool_call(run, name, args, "ok", True, 1, schema=schema)
                    self.assertEqual(seeded(), legacy_seeds(args, old["params"]))

    def test_tool_list_and_sop_validation_are_unchanged(self):
        payload, _ = advertised(REPO / "deploy" / "ops_tools.yaml")
        for source in (payload, legacy(payload)):
            with patch.object(ops_client, "available_tools", return_value=source):
                usable, specs = registry.sop_tools(), registry.sop_specs()
            # 改造前 main.usable_tools / tool_specs 的结果
            self.assertEqual(usable, {n: m.get("desc", "") for n, m in payload.items()})
            self.assertEqual(specs, {n: {"desc": m.get("desc", ""), "params": m.get("params") or {}}
                                     for n, m in payload.items()})
            for path in sorted(REPO.glob("packs/*/sops.json")):
                for sop in json.loads(path.read_text(encoding="utf-8")):
                    with self.subTest(sop=sop["name"]):
                        _, _, steps = playbooks.validate(sop["name"], sop["trigger"], sop["steps"], set(usable))
                        self.assertEqual([s["tool"] for s in steps], [s["tool"] for s in sop["steps"]])


# --- 注册表：类别、兼容、对外格式 ------------------------------------------------------

class RegistryTests(unittest.TestCase):
    def test_policies_follow_the_categories(self):
        self.assertEqual(set(registry.POLICIES), set(registry.CATEGORIES))
        data = registry.POLICIES["data"]
        self.assertTrue(data.observes and data.sop and data.selectable)
        for category in ("knowledge", "web", "compute", "internal"):
            policy = registry.POLICIES[category]
            with self.subTest(category=category):
                self.assertFalse(policy.observes or policy.sop or policy.selectable)
        self.assertEqual(registry.POLICIES["web"].limit, agent_loop.MAX_WEB_SEARCHES)
        self.assertEqual(agent_loop.MAX_WEB_SEARCHES, 2)
        self.assertFalse(registry.POLICIES["web"].export)

    def test_category_is_known_from_the_name(self):
        self.assertEqual(registry.category_of("web_search"), "web")
        for name in ("container_logs", "holiday__holiday_calendar", "not_a_tool"):
            self.assertEqual(registry.category_of(name), "data")
        self.assertFalse(registry.observes_system("web_search"))
        self.assertTrue(registry.observes_system("container_logs"))

    def test_old_tool_service_entries_are_completed(self):
        old = {"container_logs": {"desc": "日志", "params": {
                   "name": {"type": "str", "pattern": "name", "required": True, "desc": "容器名"},
                   "lines": {"type": "int", "default": 100, "min": 1, "max": 500}}},
               "holiday__date_info": {"desc": "星期几", "params": {"day": {"type": "str", "pattern": "date",
                                                                         "required": True}},
                                      "input_schema": {"type": "object", "required": ["day"],
                                                       "properties": {"day": {"type": "string"}}}},
               "k8s__pod": {"desc": "Pod", "params": {"name": {"type": "str", "pattern": "k8s_name"}},
                            "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}}},
               "host_resources": "看内存"}
        with patch.object(ops_client, "available_tools", return_value=old):
            tools = registry.data_tools()
        logs = tools["container_logs"]
        self.assertEqual(logs["params"], old["container_logs"]["params"])      # 老字段原样保留
        self.assertEqual(logs["inputSchema"]["properties"]["name"]["x-entity"], "container")
        self.assertEqual(logs["inputSchema"]["required"], ["name"])
        self.assertEqual((logs["title"], logs["annotations"]), ("container_logs", registry.DATA_ANNOTATIONS))
        self.assertEqual(logs["_meta"], {"doc2sop": {"category": "data", "provider": "ops", "export": False,
                                                     "group": ""}})
        # MCP 工具：用它的 input_schema，管理员收紧项里的预置正则照样标出来
        self.assertEqual(tools["holiday__date_info"]["inputSchema"]["properties"]["day"],
                         {"type": "string", "x-pattern": "date"})
        self.assertEqual(tools["k8s__pod"]["inputSchema"]["properties"]["name"]["x-entity"], "k8s_object")
        self.assertNotIn("x-pattern", old["k8s__pod"]["input_schema"]["properties"]["name"])
        self.assertEqual(tools["host_resources"]["desc"], "看内存")
        self.assertEqual(tools["host_resources"]["inputSchema"], {"type": "object", "properties": {}})

    def test_tool_service_cannot_reclassify_or_shadow_app_tools(self):
        sent = {"x": {"desc": "x", "params": {}, "_meta": {"doc2sop": {"category": "knowledge",
                                                                      "provider": "app", "export": True}}},
                "web_search": {"desc": "工具服务里同名的工具", "params": {}}}
        with patch.object(ops_client, "available_tools", return_value=sent), \
                self.assertLogs("kb", level="WARNING") as logged:
            tools, usable = registry.data_tools(), registry.sop_tools()
        self.assertEqual(sorted(tools), ["x"])
        self.assertEqual(usable, {"x": "x"})
        self.assertEqual(registry.meta_of(tools["x"])["category"], "data")
        self.assertEqual(registry.meta_of(tools["x"])["provider"], "ops")
        self.assertTrue(registry.meta_of(tools["x"])["export"])               # export 照工具服务标的
        self.assertIn("web_search", "\n".join(logged.output))

    def test_contracts_are_mcp_tools(self):
        payload, _ = advertised(REPO / "deploy" / "ops_tools.yaml")
        with patch.object(ops_client, "available_tools", return_value=payload), \
                patch.object(web_search, "enabled", return_value=True):
            listed = registry.contracts(registry.TurnOptions(allow_web=True))
            without_web = registry.contracts()
        for tool in listed:
            with self.subTest(tool=tool["name"]):
                self.assertEqual(sorted(tool), ["_meta", "annotations", "description", "inputSchema", "name",
                                                "title"])
                self.assertIn(registry.meta_of(tool)["category"], registry.CATEGORIES)
        by_name = {t["name"]: t for t in listed}
        self.assertEqual(registry.meta_of(by_name["web_search"]),
                         {"category": "web", "provider": "app", "export": False, "group": "联网"})
        self.assertEqual(by_name["container_logs"]["title"], "容器日志")
        self.assertNotIn("web_search", {t["name"] for t in without_web})

    def test_agent_branch_needs_something_to_bind(self):
        with patch.object(ops_client, "enabled", return_value=False):
            self.assertFalse(registry.has_tools(allow_web=False))
            with patch.object(web_search, "enabled", return_value=True):
                self.assertTrue(registry.has_tools(allow_web=True))
            with patch.object(web_search, "enabled", return_value=False):
                self.assertFalse(registry.has_tools(allow_web=True))
        with patch.object(ops_client, "enabled", return_value=True):
            self.assertTrue(registry.has_tools(allow_web=False))


class SchemaModelTests(unittest.TestCase):
    """JSON Schema → 签名：有默认值又不接受 null 的参数，签名就是它本来的类型带默认值。"""

    def model(self, schema):
        return agent_tools._schema_model("t_args", schema)

    def test_defaults_without_null(self):
        fields = self.model({"type": "object", "properties": {
            "lines": {"type": "integer", "default": 100},
            "ns": {"type": "string", "default": ""},
            "ratio": {"type": ["number", "null"], "default": 0.5},
            "opt": {"type": "string"}}}).model_fields
        self.assertIs(fields["lines"].annotation, int)
        self.assertEqual(fields["lines"].default, 100)
        self.assertIs(fields["ns"].annotation, str)
        self.assertEqual(fields["ns"].default, "")
        self.assertEqual(fields["ratio"].annotation, Optional[float])    # 声明了可为 null 的照旧
        self.assertEqual(fields["opt"].annotation, Optional[str])        # 没默认值的照旧可空
        self.assertIsNone(fields["opt"].default)

    def test_null_is_refused_where_the_schema_does_not_allow_it(self):
        tool = agent_tools.schema_tool({"name": "t", "description": "d", "inputSchema": {
            "type": "object", "properties": {"lines": {"type": "integer", "default": 100}}}})
        with self.assertRaises(ValidationError):
            tool.args_schema.model_validate({"lines": None})


# --- loop：web_search 走注册表，不再有工具名特判 ------------------------------------------

class FakeTool:
    def __init__(self, name, output="现场输出"):
        self.name, self.output, self.calls = name, output, []

    def invoke(self, args):
        self.calls.append(args)
        return self.output


def scripted(script, seen):
    rounds = iter(script)

    class Bound:
        def invoke(self, messages):
            calls, content = next(rounds)
            return AIMessage(content=content, tool_calls=calls)

    class Model:
        def bind_tools(self, tools):
            seen["tools"] = list(tools)
            return Bound()

        def invoke(self, messages):
            return Bound().invoke(messages)

    return Model()


def web_call(query, cid):
    return [{"name": "web_search", "args": {"query": query}, "id": cid}]


class LoopTests(unittest.TestCase):
    def setUp(self):
        clear_graph()

    def run_agent(self, script, tools=(), **kwargs):
        seen = {}
        with patch.object(agent_loop, "build_tools", return_value=list(tools)), \
                patch.object(agent_loop, "chat_model", return_value=scripted(script, seen)):
            events = list(agent_loop.run("问题", "片段", [], **kwargs))
        return events, seen

    def test_web_search_numbering_and_cap_are_unchanged(self):
        found = [{"title": "甲", "url": "https://a.example", "snippet": "一"},
                 {"title": "乙", "url": "https://b.example", "snippet": "二"}]
        script = [(web_call("a", "1"), ""), (web_call("b", "2"), ""), (web_call("c", "3"), ""), ([], "完")]
        with patch.object(web_search, "enabled", return_value=True), \
                patch.object(web_search, "search", side_effect=lambda q: (q, found)) as search:
            events, seen = self.run_agent(script, allow_web=True)
        self.assertEqual(search.call_count, 2)
        self.assertEqual([s["index"] for k, p in events if k == "web_sources" for s in p], ["W1", "W2", "W3", "W4"])
        results = [p["preview"] for k, p in events if k == "tool_result"]
        self.assertIn("[W3] 甲", results[1])
        self.assertTrue(results[2].startswith("[未搜索] 本轮已搜索 2 次"))
        self.assertEqual({p["category"] for k, p in events if k == "tool_call"}, {"web"})
        # 模型看到的 web_search 签名和改造前一样
        legacy_web = StructuredTool.from_function(
            func=lambda query: "", name="web_search", args_schema=LegacyWebQuery,
            description="上网搜索公开资料。仅当知识库片段无法回答、且问题不涉及公司内部信息时使用。")
        self.assertEqual([convert_to_openai_tool(t) for t in seen["tools"]], [convert_to_openai_tool(legacy_web)])

    def test_tool_call_events_carry_the_category(self):
        events, _ = self.run_agent([([{"name": "host_disk", "args": {}, "id": "1"},
                                      {"name": "web_search", "args": {"query": "q"}, "id": "2"}], ""),
                                    ([], "完")], tools=[FakeTool("host_disk")])
        calls = [p for k, p in events if k == "tool_call"]
        self.assertEqual([(c["tool"], c["category"]) for c in calls], [("host_disk", "data"), ("web_search", "web")])
        # 联网没开时 web_search 不在这一轮的工具里，和以前一样报未知工具
        self.assertIn("未知工具 web_search", [p for k, p in events if k == "tool_result"][1]["preview"])

    def test_a_new_app_tool_needs_no_change_to_the_loop(self):
        """M1 起的知识类、流程类工具就这样加：登记一个 AppTool，loop 照样限次、执行、推事件、记图谱。"""
        def lookup(args, turn):
            first = turn.number("kb_count", 1)
            turn.emit(("kb_sources", [{"index": first, "q": args.get("query")}]))
            return f"片段 [{first}]"

        kb = registry.AppTool({"name": "kb_lookup", "title": "查知识库", "description": "查知识库",
                               "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                                               "required": ["query"]},
                               "annotations": {"readOnlyHint": True},
                               "_meta": {"doc2sop": {"category": "knowledge", "provider": "app",
                                                     "export": True, "group": "知识库"}}},
                              lookup)
        many = {f"t{i:02d}": {"desc": f"工具 {i}", "params": {}} for i in range(agent_loop.TOOL_LIMIT + 5)}
        calls = [{"name": "kb_lookup", "args": {"query": str(i)}, "id": f"k{i}"} for i in range(4)]
        run = graph.start_execution("conv", "问题")
        with patch.object(registry, "APP_TOOLS", registry.APP_TOOLS + (kb,)), \
                patch.dict(registry._APP, {"kb_lookup": kb}), \
                patch.object(ops_client, "available_tools", return_value=many), \
                patch.object(agent_loop, "select_tools", wraps=agent_loop.select_tools) as select:
            events, seen = self.run_agent([(calls, ""), ([], "完")], tools=[FakeTool("t00")], execution_id=run)
            outcome = graph.finish_execution(run, "答完了")
            self.assertEqual(registry.category_of("kb_lookup"), "knowledge")
            self.assertNotIn("kb_lookup", registry.sop_tools())
        # 按问题筛选只看数据类：TOOL_LIMIT 只数它们，知识类固定绑定
        self.assertEqual(sorted(select.call_args[0][0]), sorted(many))
        self.assertEqual([t.name for t in seen["tools"]], ["t00", "kb_lookup"])
        self.assertEqual([p for k, p in events if k == "kb_sources"],
                         [[{"index": i, "q": str(i - 1)}] for i in (1, 2, 3)])
        previews = [p["preview"] for k, p in events if k == "tool_result"]
        self.assertTrue(previews[3].startswith("[未执行]"))                      # 知识类每轮 3 次
        self.assertEqual({p["category"] for k, p in events if k == "tool_call"}, {"knowledge"})
        recorded = graph.execution(run)["tool_calls"]
        self.assertEqual([c["ok"] for c in recorded], [True, True, True, False])
        self.assertEqual(outcome, "unknown")                                    # 查知识库不算观察到系统

    def test_old_checkpoints_still_load(self):
        """记忆里还是改造前的状态形状（web_count、web_searches）也能接着聊。"""
        class OldState(TypedDict):
            messages: Annotated[list, add_messages]
            rounds: int
            web_count: int
            web_searches: int

        thread = uuid.uuid4().hex
        self.addCleanup(agent_loop.forget, thread)
        old = StateGraph(OldState)
        old.add_node("agent", lambda state: {"messages": [AIMessage(content="以前的回答")]})
        old.add_edge(START, "agent")
        old.add_edge("agent", END)
        old.compile(checkpointer=agent_loop.memory()).invoke(
            {"messages": [HumanMessage(content="以前的问题")], "rounds": 0, "web_count": 3, "web_searches": 2},
            {"configurable": {"thread_id": thread}})
        seen_messages = []

        class Model:
            def bind_tools(self, tools):
                return self

            def invoke(self, messages):
                seen_messages.extend(messages)
                return AIMessage(content="接着答")

        with patch.object(agent_loop, "build_tools", return_value=[]), \
                patch.object(agent_loop, "chat_model", return_value=Model()):
            events = list(agent_loop.run("追问", "片段", [], thread_id=thread))
        self.assertEqual(events, [("delta", "接着答")])
        self.assertIn("以前的回答", [m.content for m in seen_messages])


# --- 各处的类别判断：结论质量、沉淀、触发沉淀 ---------------------------------------------

class CategoryRuleTests(unittest.TestCase):
    def setUp(self):
        clear_graph()
        self.client = TestClient(web_app)
        self.auth = (WEB_USER, WEB_PASSWORD)

    def test_only_data_calls_count_for_growth(self):
        run = graph.start_execution("conv", "q")
        for tool in ("container_inspect", "web_search", "container_logs"):
            graph.record_tool_call(run, tool, {}, "ok", True, 1)
        self.assertEqual([c["tool"] for c in grow.data_calls(graph.execution(run))],
                         ["container_inspect", "container_logs"])

    def test_web_only_turn_does_not_schedule_growth_and_keeps_categories(self):
        hits = [{"index": 1, "location": "手册.pdf", "text": "x", "score": 0.6}]

        def web_only(question, context, history, **kwargs):
            yield "tool_call", {"tool": "web_search", "args": {"query": "q"}, "category": "web"}
            yield "tool_result", {"tool": "web_search", "preview": "网上说", "lines": 1, "chars": 3}
            yield "delta", "答案"

        with patch("app.main.retrieve", return_value=hits), \
                patch("app.main.rewrite_question", side_effect=lambda q, h: q), \
                patch("app.main.AGENT_MODE", "auto"), \
                patch("app.main.ops_client.enabled", return_value=True), \
                patch("app.main.agent_loop.run", side_effect=web_only), \
                patch("app.main.grow.schedule") as schedule:
            response = self.client.post("/api/ask", json={"question": "搜一下"}, auth=self.auth)
        schedule.assert_not_called()
        events = [json.loads(line) for line in response.text.splitlines() if line]
        conversation_id = events[0]["conversation"]["id"]
        replay = self.client.get(f"/api/conversations/{conversation_id}", auth=self.auth).json()
        self.assertEqual(replay["messages"][-1]["tools"],
                         [{"tool": "web_search", "args": {"query": "q"}, "category": "web",
                           "preview": "网上说", "lines": 1}])


if __name__ == "__main__":
    unittest.main()
