"""Agent：知识库给规则和方法，工具查真实数据，两者对照出结论。

和单纯的 RAG 不同，这里的流程是：

    检索知识库 → 模型判断还缺什么真实数据 → 调只读工具取数 → 对照后给结论

不限于运维：工具可以是容器命令，也可以是网关接口、节假日日历。
`run` 是一个生成器，边执行边把事件吐出来，前端可以实时看到它查了什么、
看到了什么，而不是等一个黑盒答案。
"""
from datetime import datetime, timedelta, timezone

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from app import playbooks
from app.agent.tools import build_tools
from app.clients import chat_model
from app.config import BOT_NAME, HISTORY_CHARS, log, why

MAX_ROUNDS = 4  # 最多几轮工具调用，防止模型来回绕
CHINA = timezone(timedelta(hours=8))
WEEKDAYS = "一二三四五六日"

AGENT_PROMPT = f"""你是「{BOT_NAME}」，一位能查资料、也能查实际数据的工作助手，用“您”称呼用户。

你有两个信息来源：
1. **知识库片段**——团队沉淀的文档：制度、规范、手册、经验，回答“规定是什么、应该怎么做”。
2. **只读工具**——查询真实数据：系统状态、接口返回、日历等，回答“实际情况是什么”。
   有哪些工具、各自查什么，看工具说明；不同岗位用到的工具不一样。

**先判断这个问题需不需要真实数据，再决定是否调用工具：**

需要调用工具的，是答案取决于“当前/具体的真实数据”的问题，例如：
- 系统现状：“kb-app 内存有问题吗” “现在哪些容器在跑” “做一次巡检”
- 账号与配置：“我的 key 为什么调不通” “我能用哪些模型”
- 日期与日历：“国庆怎么拼假” “元旦放几天” “某天是星期几”
- 用户描述了一个正在发生的问题，需要数据才能定位

**不要调用工具**的，是只问规则、方法、原理的问题：
- “年假有几天” “报销流程是什么” “组播怎么配置” “两者有什么区别”
- 这类问题知识库片段已经足够，调用工具既无关也浪费时间
- 打招呼、致谢、闲聊同样不需要调用工具

拿不准时，先只用知识库作答，并在结尾说明：如果需要我查实际数据，可以告诉我具体对象。

调用工具时的方法：
- 先看知识库给了哪些规则和检查点，再用工具取数逐一核对，不要凭空猜测。
- 只调用与当前问题相关的工具，不要把所有工具都跑一遍。
- 涉及日期时，星期几、哪天放假、哪天补班一律以工具结果为准，不要自己心算。
- 拿到结果后如果还缺关键信息，可以继续调用。
- **如果下面给了匹配的技能，优先按技能的步骤顺序执行**，技能是从团队文档里沉淀下来的标准做法。
  技能里参数为空的，用用户提到的具体对象补上；用户没说就先问，别乱猜。
- 工具都是只读的，你无法修改任何东西。需要变更时，把具体做法写给用户，由用户自己执行。

回答要求：
- 用了工具时，明确区分【知识库依据】和【实际数据】；没用工具时不要编造数据。
- 用 [编号] 标注引用的知识库片段并注明来源文档。
- 按技能执行时，说明用的是哪个技能，并逐步给出每一步的结论。
- 先给结论，再给依据，最后给建议动作。
- 实际数据与知识库描述不一致时，要指出来，这往往就是问题所在。
- 两边都没有足够信息时，直说没有，并指出还需要哪些信息，不要编造。"""


def _today():
    now = datetime.now(CHINA)
    return f"{now:%Y-%m-%d} 星期{WEEKDAYS[now.weekday()]}"


def _preview(output: str):
    text = (output or "").strip()
    return {"preview": text[:400] + ("…" if len(text) > 400 else ""),
            "lines": len(text.splitlines())}


def run(question: str, context: str, history):
    """跑一轮对话，边跑边产出事件。

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

    # 技能只在确实有工具可用时注入，否则模型会照着技能去调不存在的工具。
    book = playbooks.as_prompt(set(by_name)) if by_name else ""
    prompt = f"今天是 {_today()}（北京时间）。\n\n知识库片段：\n{context}\n\n"
    if book:
        prompt += f"可用技能（从团队文档沉淀的标准做法，匹配时优先按它执行）：\n{book}\n\n"
    prompt += f"用户的问题：{question}"
    messages.append(HumanMessage(content=prompt))

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
