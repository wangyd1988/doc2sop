"""排障 Agent：知识库给方法，工具查现场，两者对照出结论。

和单纯的 RAG 不同，这里的流程是：

    检索知识库 → 模型判断还缺什么现场信息 → 调只读工具取数 → 对照后给结论

`run` 是一个生成器，边执行边把事件吐出来，前端可以实时看到它查了什么、
看到了什么，而不是等一个黑盒答案。
"""
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app.agent.tools import build_tools
from app.clients import chat_model
from app.config import BOT_NAME, HISTORY_CHARS, log, why

MAX_ROUNDS = 4  # 最多几轮工具调用，防止模型来回绕

AGENT_PROMPT = f"""你是「{BOT_NAME}」，一位容器网络与云平台排障助手，用“您”称呼用户。

你有两个信息来源，必须配合使用：
1. **知识库片段**——团队沉淀的排障经验与配置说明，告诉你“应该查什么、正常值是什么”。
2. **只读运维工具**——可以查看当前环境的真实状态，告诉你“现在实际是什么”。

工作方法：
- 先看知识库片段提示了哪些排查点，再用工具去现场核对这些点，不要凭空猜测现状。
- 需要具体配置字段、日志、资源占用时，直接调用工具获取，不要让用户手动去查。
- 一次可以调用多个工具；拿到结果后如果还缺关键信息，可以继续调用。
- 工具都是只读的，你无法修改环境。需要变更时，把具体命令写给用户，由用户自己执行。

回答要求：
- 明确区分【知识库依据】和【现场实测】，用 [编号] 标注引用的知识库片段并注明来源文档。
- 先给结论，再给依据，最后给建议动作。
- 现场数据与知识库描述不一致时，要指出来，这往往就是问题所在。
- 知识库和工具都没有足够信息时，直说没有，并指出还需要哪些信息，不要编造。
- 打招呼、闲聊自然回应即可，不需要调用工具。"""


def _preview(output: str):
    text = (output or "").strip()
    return {"preview": text[:400] + ("…" if len(text) > 400 else ""),
            "lines": len(text.splitlines())}


def run(question: str, context: str, history):
    """跑一轮排障对话，边跑边产出事件。

    产出 (kind, payload)：
      ("tool_call",   {"tool": ..., "args": {...}})
      ("tool_result", {"tool": ..., "preview": ..., "lines": n})
      ("delta",       "答案文本片段")
      ("error",       "错误说明")
    """
    tools = build_tools()
    if not tools:
        log.info("no ops tools available, agent answers from knowledge base only")
    model = chat_model(timeout=120, max_retries=1)
    bound = model.bind_tools(tools) if tools else model
    by_name = {tool.name: tool for tool in tools}

    messages = [SystemMessage(content=AGENT_PROMPT)]
    for role, content in history:
        messages.append(HumanMessage(content=content[:HISTORY_CHARS]) if role == "user"
                        else AIMessage(content=content[:HISTORY_CHARS]))
    messages.append(HumanMessage(
        content=f"知识库片段：\n{context}\n\n用户的问题：{question}"))

    for _ in range(MAX_ROUNDS):
        try:
            reply = bound.invoke(messages)
        except Exception as exc:
            log.warning("agent invoke failed", exc_info=True)
            yield "error", f"模型调用失败：{why(exc)}"
            return

        calls = getattr(reply, "tool_calls", None) or []
        if not calls:
            # 没有工具调用，这一轮就是最终答案。
            if reply.content:
                yield "delta", reply.content
            return

        messages.append(reply)
        for call in calls:
            name, args = call["name"], call.get("args") or {}
            yield "tool_call", {"tool": name, "args": args}
            tool = by_name.get(name)
            if tool is None:
                output = f"[执行失败] 未知工具 {name}"
            else:
                try:
                    output = tool.invoke(args)
                except Exception as exc:
                    output = f"[执行失败] {why(exc)}"
            yield "tool_result", {"tool": name, **_preview(str(output))}
            messages.append(ToolMessage(content=str(output), tool_call_id=call["id"]))

    # 达到轮次上限，让模型基于已有结果收口。
    messages.append(HumanMessage(
        content="已达到工具调用次数上限，请基于目前拿到的信息给出结论和建议。"))
    try:
        final = bound.invoke(messages)
    except Exception as exc:
        yield "error", f"模型调用失败：{why(exc)}"
        return
    if final.content:
        yield "delta", final.content
