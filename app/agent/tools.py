"""Tool schemas exposed to the model.

The ops host is the single source of truth. It reports each tool's description
and parameter spec, and we turn that into the function signature the model sees.
Adding a tool is therefore an edit to the host's definition file — no schema to
keep in sync here, and no rebuild of this image.
"""
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field, create_model

from app.agent import ops_client
from app.config import log, why


class Empty(BaseModel):
    pass


def _field(spec: dict):
    """One declared parameter as a (type, Field) pair for create_model."""
    description = str(spec.get("desc") or "")
    if spec.get("type") == "int":
        return int, Field(default=int(spec.get("default", 100)),
                          description=description)
    if spec.get("required"):
        return str, Field(description=description)
    return str, Field(default=str(spec.get("default", "")), description=description)


def _args_schema(name: str, params: dict):
    if not params:
        return Empty
    return create_model(f"{name}_args",
                        **{key: _field(spec) for key, spec in params.items()})


def _make(name: str, description: str, schema):
    def call(**kwargs):
        result = ops_client.execute(name, kwargs)
        output = result.get("output", "")
        if not result.get("ok"):
            return f"[执行失败] {result.get('error') or output or '未知错误'}"
        return output or "（命令执行成功，但没有输出）"

    return StructuredTool.from_function(
        func=call, name=name, description=description, args_schema=schema)


def build_tools():
    """Build the tool list from whatever the ops host currently advertises."""
    tools = []
    for name, meta in sorted(ops_client.available_tools().items()):
        # 老版本接口只回描述字符串；按无参数处理，别让整轮对话挂掉。
        if not isinstance(meta, dict):
            meta = {"desc": str(meta), "params": {}}
        try:
            tools.append(_make(name, meta.get("desc", ""),
                               _args_schema(name, meta.get("params") or {})))
        except Exception as exc:
            log.warning("tool %s skipped: %s", name, why(exc))
    log.info("ops tools enabled: %s", ", ".join(t.name for t in tools) or "none")
    return tools
