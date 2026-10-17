"""Tool schemas exposed to the model.

The ops host is the single source of truth. It reports each tool's description
and parameter spec, and we turn that into the function signature the model sees.
Adding a tool is therefore an edit to the host's definition file — no schema to
keep in sync here, and no rebuild of this image.
"""
import re

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


def build_tools(available: dict | None = None):
    """Build the tool list from whatever the ops host currently advertises (or a chosen subset)."""
    tools = []
    source = ops_client.available_tools() if available is None else available
    for name, meta in sorted(source.items()):
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


# 工具一多就不能全绑给模型：几百个 schema 会把上下文撑爆，模型也挑不准。
# 超过这个数时按问题相关性筛选，SOP 引用到的工具无条件保留。
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
