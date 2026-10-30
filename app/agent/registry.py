"""工具注册表：各提供方的工具合成一张表，统一按 MCP 的 Tool 格式描述（统一工具契约）。

契约（docs/工具.md「工具契约」）：

    name / title / description / inputSchema / annotations    MCP 的 Tool 定义
    _meta.doc2sop = {category, provider, export, group}        项目扩展，对外下发时剥掉
    inputSchema 参数上的 x-entity                               这个参数的值是哪类对象的名字（图谱据此播种）

提供方：
    ops      工具服务（deploy/ops_readonly.py）下发的工具，全是数据类。新工具服务直接带契约字段；
             老工具服务只有 desc / params（MCP 工具多一份 input_schema），这里按同一规则补齐。
    app      应用内的工具：现在只有 web_search。
    sandbox  计算沙箱（还没有）。

权限与统计看类别，不看工具名：

    类别        算「观察到系统」  可进 SOP  对外        绑定给模型
    data        是                是        看 export   超过 TOOL_LIMIT 时按问题筛选
    knowledge   否                否        是          固定绑定
    web         否                否        否          固定绑定（跟随联网开关）
    compute     否                否        否          固定绑定
    internal    否                否        否          固定绑定

加一个应用内工具：写好契约（_meta.doc2sop 里给 category、provider）和执行函数 run(args, turn)，
在 APP_TOOLS 里登记一个 AppTool，wanted 决定这一轮绑不绑。loop、graph、grow、main、页面都不用改。

AGENT_MODE=off 时什么工具都不绑：由入口把关（main 的 use_agent、usable_tools），这里不重复判断。
"""
import copy
from dataclasses import dataclass
from typing import Callable

from app.agent import ops_client, web_search
from app.config import log, why

CATEGORIES = ("data", "knowledge", "web", "compute", "internal")


@dataclass(frozen=True)
class Policy:
    observes: bool              # 算不算观察到系统：结论质量、沉淀门槛、触发沉淀只数这一类
    sop: bool                   # 能不能写进 SOP 步骤（SOP 校验的「已有工具」）
    export: bool | None         # 能不能出现在对外 MCP；None 表示看工具自己的 export
    selectable: bool            # 工具多时参与按问题筛选、计入 TOOL_LIMIT；否则固定绑定
    limit: int | None = None    # 每轮最多调用几次；到了不执行，返回 limit_note
    limit_note: str = "[未执行] 本轮这类工具已调用 {limit} 次，请基于已有结果作答"


# 每轮限次：知识 3、外网 2（和以前的联网限次一样）、计算 3。
POLICIES = {
    "data": Policy(observes=True, sop=True, export=None, selectable=True),
    "knowledge": Policy(observes=False, sop=False, export=True, selectable=False, limit=3),
    "web": Policy(observes=False, sop=False, export=False, selectable=False, limit=web_search.MAX_SEARCHES,
                  limit_note="[未搜索] 本轮已搜索 {limit} 次，请基于已有结果作答"),
    "compute": Policy(observes=False, sop=False, export=False, selectable=False, limit=3),
    "internal": Policy(observes=False, sop=False, export=False, selectable=False),
}


def meta_of(contract) -> dict:
    """契约里的项目扩展 _meta.doc2sop。"""
    meta = contract.get("_meta") if isinstance(contract, dict) else None
    doc = meta.get("doc2sop") if isinstance(meta, dict) else None
    return doc if isinstance(doc, dict) else {}


# --- 一轮对话里的工具状态 --------------------------------------------------------

@dataclass(frozen=True)
class TurnOptions:
    """这一轮的开关，决定应用内工具绑不绑。"""
    allow_web: bool = False


class Turn:
    """一轮对话里工具共享的状态：按类别的调用次数、跨调用续编的编号（[W1]、[W2]…），以及往页面推事件。

    usage 存在 LangGraph 的 TurnState 里、每轮清零：loop 的 tools 节点进来时建一个 Turn，出去时写回。
    """

    def __init__(self, emit=None, usage=None):
        self.emit = emit or (lambda event: None)
        self.usage = copy.deepcopy(usage or {})

    def admit(self, category) -> str | None:
        """按类别限次：没到上限就记一次、返回 None；到了返回给模型看的说明，这次不执行。"""
        policy = POLICIES.get(category)
        calls = self.usage.setdefault("calls", {})
        used = calls.get(category, 0)
        if policy is not None and policy.limit is not None and used >= policy.limit:
            return policy.limit_note.format(limit=policy.limit)
        calls[category] = used + 1
        return None

    def number(self, key, count) -> int:
        """续编号：返回这一批的第一个编号，并把 key 的计数往后推 count 个。"""
        first = int(self.usage.get(key, 0)) + 1
        self.usage[key] = first - 1 + count
        return first


@dataclass(frozen=True)
class Binding:
    """这一轮绑给模型的一个工具。loop 只认它：按类别限次、执行、记图谱，不再按工具名分支。"""
    name: str
    category: str
    schema: dict                              # inputSchema，图谱按里面的 x-entity 播种
    run: Callable[[dict, Turn], str]


# --- 应用内提供方 ----------------------------------------------------------------

@dataclass(frozen=True)
class AppTool:
    """应用内（或沙箱）提供的一个工具。"""
    contract: dict                                       # MCP 的 Tool 格式，_meta.doc2sop 里有 category、provider
    run: Callable[[dict, Turn], str]                     # 参数原样传入，返回给模型看的文字；可以 turn.emit 推事件
    wanted: Callable[[TurnOptions], bool] = lambda options: True   # 这一轮要不要绑
    describe: Callable[[], dict] | None = None           # 说明要每轮现算时用它（只改说明，参数和类别以 contract 为准）

    @property
    def name(self) -> str:
        return self.contract["name"]

    @property
    def category(self) -> str:
        return meta_of(self.contract)["category"]

    def current(self) -> dict:
        return self.describe() if self.describe else self.contract


APP_TOOLS = (
    AppTool(web_search.TOOL, web_search.run_tool,
            wanted=lambda options: options.allow_web and web_search.enabled()),
)
_APP = {tool.name: tool for tool in APP_TOOLS}


def app_tools(options: TurnOptions) -> list:
    """这一轮要绑的应用内工具。它们不参与按问题筛选。"""
    return [tool for tool in APP_TOOLS if tool.wanted(options)]


def has_tools(allow_web=False) -> bool:
    """有没有工具可绑（只看配置，不发请求）：有才走 Agent 分支，否则纯知识库问答。"""
    return ops_client.enabled() or bool(app_tools(TurnOptions(allow_web=allow_web)))


def category_of(name) -> str:
    """工具属于哪个类别。应用内工具的名字是保留的、类别固定；其余都来自工具服务，是数据类。

    只看名字就能判断，所以图谱里的历史调用不用存类别，判断时也不用连工具服务。
    """
    tool = _APP.get(name)
    return tool.category if tool else "data"


def observes_system(name) -> bool:
    """这次调用算不算观察到了系统。取代以前各处的「不是 web_search」。"""
    return POLICIES[category_of(name)].observes


def bind_data(tool, entry=None) -> Binding:
    """数据类工具：执行走 LangChain 工具的 invoke——先按签名校验、补默认值，再发 /exec。"""
    schema = (entry or {}).get("inputSchema") if isinstance(entry, dict) else None
    return Binding(tool.name, "data", schema if isinstance(schema, dict) else {},
                   lambda args, turn: tool.invoke(args))


def bind_app(tool: AppTool) -> Binding:
    return Binding(tool.name, tool.category, tool.contract.get("inputSchema") or {}, tool.run)


# --- 工具服务（数据类）-------------------------------------------------------------

DATA_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


def data_tools() -> dict:
    """工具服务此刻下发的工具：名字 -> /tools 条目，老字段原样保留、契约字段保证齐全。

    应用内工具的名字是保留的：工具服务下发同名工具时忽略它，免得一个名字两种类别。
    """
    out = {}
    for name, meta in ops_client.available_tools().items():
        if name in _APP:
            log.warning("工具服务下发的 %s 与应用内工具同名，已忽略", name)
            continue
        out[name] = _normalize(name, meta)
    return out


def _normalize(name, meta) -> dict:
    # 最老的接口只回一句说明：按无参数处理
    entry = dict(meta) if isinstance(meta, dict) else {"desc": str(meta), "params": {}}
    if not isinstance(entry.get("inputSchema"), dict):
        entry.pop("inputSchema", None)
        try:
            entry["inputSchema"] = compat_schema(entry)
        except Exception as exc:   # 参数声明坏了：留给 build_tools 跳过这个工具，和以前一样
            log.warning("tool %s: params unusable (%s)", name, why(exc))
    entry["title"] = str(entry.get("title") or name)
    if not isinstance(entry.get("annotations"), dict):
        entry["annotations"] = dict(DATA_ANNOTATIONS)
    declared = meta_of(entry)
    extra = entry.get("_meta") if isinstance(entry.get("_meta"), dict) else {}
    # 工具服务的工具一律是数据类，不由它自己说了算；export 照它标的（对外出口做好后才有意义）
    entry["_meta"] = {**extra, "doc2sop": {"category": "data", "provider": "ops",
                                           "export": declared.get("export") is True,
                                           "group": str(declared.get("group") or "")}}
    return entry


def as_contract(name, entry) -> dict:
    """数据类条目 → MCP 的 Tool 格式。"""
    return {"name": name, "title": entry.get("title") or name, "description": entry.get("desc", ""),
            "inputSchema": entry.get("inputSchema") or {"type": "object", "properties": {}},
            "annotations": entry.get("annotations") or dict(DATA_ANNOTATIONS),
            "_meta": entry.get("_meta") or {}}


def contracts(options: TurnOptions | None = None) -> list:
    """此刻注册表里的全部工具，MCP 的 Tool 格式：数据类 + 这一轮要绑的应用内工具。"""
    tools = [as_contract(name, entry) for name, entry in sorted(data_tools().items())]
    return tools + [tool.current() for tool in app_tools(options or TurnOptions())]


def sop_tools() -> dict:
    """能写进 SOP 的工具：名字 -> 说明。

    可进 SOP 的只有数据类，也就是今天工具服务下发的工具，所以 SOP 校验结果和以前一样。
    """
    return {name: entry.get("desc", "") for name, entry in data_tools().items()}


def sop_specs() -> dict:
    """名字 -> {desc, params}：SOP 抽取和沉淀要把参数名告诉模型，args 才填得对。"""
    return {name: {"desc": entry.get("desc", ""), "params": entry.get("params") or {}}
            for name, entry in data_tools().items()}


# --- 老工具服务兜底：按同一规则推出 inputSchema ------------------------------------

ENTITY_PATTERNS = ("name", "k8s_name")
_SCALAR = (str, int, float, bool)


def entity_of(key, pattern):
    """老写法参数的 x-entity。与工具服务 ops_readonly._entity_of 是同一条规则，改要两边一起改。"""
    if pattern not in ENTITY_PATTERNS:
        return None
    if key == "namespace":
        return "namespace"
    if pattern == "k8s_name":
        return "k8s_object"
    return "container" if key == "name" else key


def _mark_pattern(prop, key, pattern):
    prop["x-pattern"] = pattern
    entity = entity_of(key, pattern)
    if entity:
        prop["x-entity"] = entity


def compat_schema(meta) -> dict:
    """老工具服务没有 inputSchema：MCP 工具用它的 input_schema，其余按 params 推一份。

    params 里的预置正则名（MCP 工具来自管理员的收紧项）照样标成 x-pattern / x-entity，图谱播种不变。
    这边不知道预置正则本身，所以不填 pattern——参数校验始终在工具服务那边。
    """
    params = meta.get("params") if isinstance(meta.get("params"), dict) else {}
    raw = meta.get("input_schema")
    if not isinstance(raw, dict):
        return schema_from_params(params)
    schema = copy.deepcopy(raw)
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    for key, spec in params.items():
        if isinstance(spec, dict) and spec.get("pattern") and isinstance(properties.get(key), dict):
            _mark_pattern(properties[key], key, spec["pattern"])
    return schema


def schema_from_params(params) -> dict:
    """老写法的 params → JSON Schema。默认值和必填照应用侧老签名的规则，发给 /exec 的参数才不变。"""
    properties, required = {}, []
    for key, spec in (params or {}).items():
        key = str(key)
        properties[key], needed = _param_schema(key, spec)
        if needed:
            required.append(key)
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _param_schema(key, spec):
    if not isinstance(spec, dict):
        raise ValueError(f"参数 {key} 的声明不是映射")
    kind, required = spec.get("type"), bool(spec.get("required"))
    prop = {"description": str(spec.get("desc") or "")}
    if spec.get("pattern"):
        _mark_pattern(prop, key, spec["pattern"])
    if kind == "int":
        prop["type"] = "integer"
        for bound, word in (("min", "minimum"), ("max", "maximum")):
            if isinstance(spec.get(bound), int) and not isinstance(spec.get(bound), bool):
                prop[word] = spec[bound]
        if required and "default" not in spec:
            return prop, True
        # 老签名：非必填（或带了默认值）的 int，默认值缺省是 100
        prop["default"] = int(spec.get("default", 100))
        return prop, False
    if kind in ("float", "bool", "json", "enum"):
        # 这几种只出现在 MCP 工具的 params 里（input_schema 坏了才会用到）
        values = [v for v in (spec.get("enum") or []) if isinstance(v, _SCALAR)]
        if kind == "enum" and values:
            prop["enum"] = values
        elif kind != "json":
            prop["type"] = {"float": "number", "bool": "boolean"}.get(kind, "string")
        if required:
            return prop, True
        if isinstance(spec.get("default"), _SCALAR):
            prop["default"] = spec["default"]
        return prop, False
    prop["type"] = "string"
    if required:
        return prop, True
    prop["default"] = str(spec.get("default", ""))
    return prop, False
