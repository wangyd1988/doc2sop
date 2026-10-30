"""Tool schemas exposed to the model.

签名统一按 JSON Schema 生成：工具服务下发的工具用契约里的 inputSchema（见 registry.py），
应用内工具（web_search……）用它们自己的契约。嵌套对象、数组、枚举、必填都保得住。
老工具服务没有 inputSchema 时，按它的 input_schema（MCP 工具）或 params 推一份，再走同一条路——
params 只作兼容。所以加工具仍然只改宿主机的定义文件，这边不留第二份清单，也不用重建镜像。
"""
import re
import warnings
from typing import Any, Literal, Optional, Union

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model

from app.agent import ops_client, registry
from app.config import log, why


class Empty(BaseModel):
    pass


_SCALAR = (str, int, float, bool)


def _nullable(schema) -> bool:
    kind = schema.get("type") if isinstance(schema, dict) else None
    return isinstance(kind, list) and "null" in kind


def _annotation(schema, name: str):
    """JSON Schema 片段 → Python 类型注解。认不出来的一律 Any，不让一个冷门关键字拖垮整个工具。"""
    if not isinstance(schema, dict):
        return Any
    values = tuple(v for v in (schema.get("enum") or []) if isinstance(v, _SCALAR))
    if values:
        return Literal[values]
    kind = schema.get("type")
    nullable = False
    if isinstance(kind, list):
        kinds = [k for k in kind if k != "null"]
        nullable = len(kinds) < len(kind)
        kind = kinds[0] if len(kinds) == 1 else None
    if kind == "string":
        base = str
    elif kind == "integer":
        base = int
    elif kind == "number":
        base = float
    elif kind == "boolean":
        base = bool
    elif kind == "array":
        items = schema.get("items")
        base = list[_annotation(items, name + "_item")] if isinstance(items, dict) else list
    elif kind == "object":
        base = _schema_model(name, schema) if isinstance(schema.get("properties"), dict) \
            and schema["properties"] else dict
    else:
        options = schema.get("anyOf") or schema.get("oneOf")
        if isinstance(options, list) and options:
            base = Union[tuple(_annotation(o, f"{name}_{i}") for i, o in enumerate(options))]
        else:
            base = Any
    return Optional[base] if nullable else base


def _schema_model(name: str, schema: dict):
    required = {str(r) for r in (schema.get("required") or [])}
    fields = {}
    for key, prop in (schema.get("properties") or {}).items():
        key = str(key)
        if not key.isidentifier() or key.startswith("_"):
            continue
        description = str(prop.get("description") or prop.get("title") or "") \
            if isinstance(prop, dict) else ""
        annotation = _annotation(prop, f"{name}_{key}")
        if key in required:
            fields[key] = (annotation, Field(description=description))
            continue
        default = prop.get("default") if isinstance(prop, dict) and \
            isinstance(prop.get("default"), _SCALAR) else None
        if default is not None and not _nullable(prop):
            # 有默认值、又不接受 null：签名就是这个类型带默认值（缺参时把默认值发出去），不放进 null
            fields[key] = (annotation, Field(default=default, description=description))
        else:
            fields[key] = (Optional[annotation], Field(default=default, description=description))
    if not fields:
        return Empty
    with warnings.catch_warnings():
        # server 的参数名撞上 BaseModel 的方法名（schema、json、copy）只是警告，照用
        warnings.simplefilter("ignore")
        return create_model(name, **fields)


def _plain(value):
    """嵌套参数到了这里可能还是 pydantic 实例，发给宿主机前要变回普通 JSON。"""
    if isinstance(value, BaseModel):
        return _plain(value.model_dump(exclude_none=True))
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _make(name: str, description: str, schema):
    def call(**kwargs):
        result = ops_client.execute(name, _plain(kwargs))
        output = result.get("output", "")
        if not result.get("ok"):
            return f"[执行失败] {result.get('error') or output or '未知错误'}"
        return output or "（命令执行成功，但没有输出）"

    return StructuredTool.from_function(
        func=call, name=name, description=description, args_schema=schema)


def _schema_for(name: str, meta: dict):
    """签名的来源：契约里的 inputSchema；老工具服务没有它，就按 input_schema / params 推一份。"""
    schema = meta.get("inputSchema")
    if not isinstance(schema, dict):
        schema = registry.compat_schema(meta)
    try:
        return _schema_model(f"{name}_args", schema)
    except Exception as exc:
        log.warning("tool %s: input schema unusable (%s), falling back to params", name, why(exc))
    return _schema_model(f"{name}_args", registry.schema_from_params(meta.get("params") or {}))


def build_tools(available: dict | None = None):
    """Build the tool list from whatever the ops host currently advertises (or a chosen subset)."""
    tools = []
    source = ops_client.available_tools() if available is None else available
    for name, meta in sorted(source.items()):
        # 老版本接口只回描述字符串；按无参数处理，别让整轮对话挂掉。
        if not isinstance(meta, dict):
            meta = {"desc": str(meta), "params": {}}
        try:
            tools.append(_make(name, meta.get("desc", ""), _schema_for(name, meta)))
        except Exception as exc:
            log.warning("tool %s skipped: %s", name, why(exc))
    log.info("ops tools enabled: %s", ", ".join(t.name for t in tools) or "none")
    return tools


def schema_tool(contract: dict):
    """应用内工具绑给模型的签名：只描述参数；执行由注册表做，loop 不会调这个 func。"""
    name = contract["name"]
    return StructuredTool.from_function(
        func=lambda **kwargs: "", name=name, description=contract.get("description", ""),
        args_schema=_schema_model(f"{name}_args", contract.get("inputSchema") or {}))


# 工具一多就不能全绑给模型：几百个 schema 会把上下文撑爆，模型也挑不准。
# 超过这个数时按问题相关性筛选，SOP 引用到的工具无条件保留。只数、只筛数据类（工具服务下发的）；
# 应用内的工具（web_search 等）固定绑定，不占这个名额。
TOOL_LIMIT = 40
_TOKEN = re.compile(r"[a-z0-9_]+|[\u4e00-\u9fff]")


def _tokens(text) -> set:
    text = str(text or "").lower()
    out = set(_TOKEN.findall(text))
    # 中文再加二元组，单字太容易误中
    cjk = "".join(c for c in text if "\u4e00" <= c <= "\u9fff")
    out |= {cjk[i:i + 2] for i in range(len(cjk) - 1)}
    return out


def select_tools(available: dict, question: str, must_have=(), limit: int = TOOL_LIMIT) -> dict:
    """Pick the tools worth showing the model for this question.

    Scoring is plain token overlap between the question and the tool's name /
    label / description / group. It does not need to be clever: the goal is to
    drop the 900 tools that obviously have nothing to do with the question, not
    to rank the remaining 40 perfectly — the model does that.
    """
    if len(available) <= limit:
        return dict(available)
    want = _tokens(question)
    scored = []
    for name, meta in available.items():
        meta = meta if isinstance(meta, dict) else {"desc": str(meta)}
        have = _tokens(" ".join([name, name.replace("_", " "), str(meta.get("label", "")),
                                 str(meta.get("desc", "")), str(meta.get("group", ""))]))
        scored.append((len(want & have), name))
    scored.sort(key=lambda s: (-s[0], s[1]))
    chosen = {n for n in must_have if n in available}
    for score, name in scored:
        if len(chosen) >= limit:
            break
        chosen.add(name)
    log.info("tool selection: %d of %d (sop-pinned %d)", len(chosen), len(available),
             len([n for n in must_have if n in available]))
    return {n: available[n] for n in sorted(chosen)}
