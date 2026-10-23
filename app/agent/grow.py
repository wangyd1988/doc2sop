"""从一次自由排查里长出 SOP。

文档抽取（extract.py）是「人写过的做法 → SOP」；这里是「Agent 刚做过的事 → SOP」：
用户问了一个没有 SOP 的问题，Agent 自己选了几个工具、查到数据、给出了结论——这条路径
本身就是一份经验，不记下来下次还得重新摸。

整个流程跑在回答结束后的后台线程里，不拖慢流式回答：

    该不该提（should_propose）→ 把本轮轨迹喂给模型长出候选（generate）
    → 过 playbooks.validate（安全线不变：只能引用已有工具）→ 入 proposals 等人批准

节制与去重：
  - 候选的工具序列与某个已有 SOP 相似度 ≥ 70% → 改提「补充到《X》」，只带 X 没有的步骤
  - 人点过「忽略」的轨迹签名，30 天内不再提；同签名已有待确认提议时也不重复提
  - 每天最多提 N 条（SOP_PROPOSALS_PER_DAY）；AUTO_SOP_PROPOSALS=false 整体关闭
"""
import difflib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from langsmith import traceable

from app import config, graph, playbooks
from app.agent.extract import _clean_args, _listing, _parse, _spec
from app.agent.loop import _clip, _condense
from app.agent.web_search import TOOL_NAME as WEB_TOOL
from app.clients import chat_model
from app.config import log, why

SOURCE = "从实践沉淀"
IGNORE_DAYS = 30
SIMILAR = 0.7
MIN_TOOLS = 2
MIN_ANSWER_CHARS = 40
MAX_STEPS = 6
CALL_CHARS = 1200          # 每次调用的返回喂给模型的上限
ANSWER_CHARS = 2000
TRAJECTORY_CHARS = 6000
MAX_OUTPUT_TOKENS = 8000
# 回答开头出现这些话，说明这一轮没有得出结论（没查到 / 反问用户），不值得沉淀
NO_CONCLUSION = ("没有找到", "没查到", "知识库里没有", "知识库中没有", "无法判断", "无法确定",
                 "请提供", "请告诉我", "需要您提供")
EVIDENCE = re.compile(r"第\s*(\d+)\s*次调用\s*([A-Za-z0-9_]+)")

GROW_PROMPT = """你要把 Agent 刚完成的一次排查整理成可复用的「SOP」（标准作业流程）。

下面给出这一轮的完整轨迹：用户的问题、Agent 依次调用了哪些工具（参数与返回摘要）、最后得出的结论。
SOP = 下次遇到同类问题时，按顺序调用哪些工具、每一步看什么、怎么判断。

**你只能使用下面列出的工具，不能发明新工具、不能写命令行。**
每个工具后面括号里列出了它接受的参数名，args 的键只能从中选，不要自己起名。

可用工具：
{tools}

输出 JSON 数组，最多一个元素，形如：
[{{
  "name": "SOP 名称，不超过 20 字，说清是排查什么的，例如：容器 OOM 排查",
  "trigger": "什么时候用它：一句话概括这类问题，不要写本次的具体对象名",
  "steps": [
    {{"tool": "工具名（必须是上面列出的）",
      "args": {{"参数名": "固定值；本次的具体对象（容器名、Pod 名、命名空间、日期、key 名）要泛化成空字符串，使用时再填"}},
      "checkpoint": "这一步看什么、怎么判断——写本次实际用到的判断依据，例如：退出码 137 且内存上限远低于文档值 → OOM",
      "evidence": "支撑这一步的依据，写成「第 n 次调用 工具名 的返回：关键内容」，n 是轨迹里的调用序号"}}
  ]
}}]

要求：
- 只保留对得出结论真正起作用的调用；重复的、没用上结果的调用不要
- 步骤顺序按本次的调用顺序，除非明显应该先后对调
- 具体对象一律泛化成空字符串；只有像 default 这样的通用默认值可以保留
- checkpoint 必须具体到数字或状态，不要写「检查是否正常」这种空话
- evidence 的序号和工具名必须与轨迹对得上，不要编
- 这次排查如果没有得出结论，或只是一次简单的单项查询，输出空数组 []
- 只输出 JSON，不要解释、不要代码块标记"""


def enabled():
    return bool(config.AUTO_SOP_PROPOSALS)


def ops_calls(execution):
    """本轮的运维工具调用（去掉联网搜索——SOP 不能引用它，也不算观察系统）。"""
    return [c for c in execution.get("tool_calls", []) if c["tool"] != WEB_TOOL]


def signature(tools):
    """工具序列签名：按顺序的工具名、连续重复合并，如 "container_inspect>container_logs"。"""
    seq = []
    for tool in tools:
        if not seq or seq[-1] != tool:
            seq.append(tool)
    return ">".join(seq)


def similarity(a, b):
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a.split(">"), b.split(">")).ratio()


def _followed(seq, steps):
    """SOP 的步骤序列是否按顺序出现在本轮调用里（允许中间穿插别的调用）。"""
    it = iter(seq)
    return bool(steps) and all(tool in it for tool in steps)


def has_conclusion(answer):
    text = (answer or "").strip()
    return len(text) >= MIN_ANSWER_CHARS and not any(p in text[:120] for p in NO_CONCLUSION)


def should_propose(execution, answer, enabled_playbooks):
    """返回 (要不要提, 不提的原因)。原因只进日志，方便回答「为什么没提」。"""
    if not enabled():
        return False, "自动提议已关闭"
    if execution.get("playbook_id"):
        return False, "本轮是按 SOP 执行的"
    if execution.get("outcome") not in ("ok", "anomaly"):
        return False, f"outcome 是 {execution.get('outcome')}"
    calls = ops_calls(execution)
    if len({c["tool"] for c in calls}) < MIN_TOOLS:
        return False, f"不同工具少于 {MIN_TOOLS} 个"
    if not has_conclusion(answer):
        return False, "回答没有结论"
    if "按 SOP《" in (answer or ""):
        return False, "回答声明是按 SOP 执行的"
    seq = [c["tool"] for c in calls]
    for playbook in enabled_playbooks:
        if _followed(seq, [s["tool"] for s in playbook["steps"]]):
            return False, f"套用了 SOP《{playbook['name']}》"
    sig = signature(seq)
    if graph.recently_rejected(sig, IGNORE_DAYS):
        return False, f"同样的轨迹 {IGNORE_DAYS} 天内被忽略过"
    if any(p["signature"] == sig for p in graph.list_proposals(status="pending")):
        return False, "同样的轨迹已有待确认的提议"
    day_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if graph.count_proposals_since(day_start.isoformat(timespec="seconds")) >= config.SOP_PROPOSALS_PER_DAY:
        return False, "今天的提议数已到上限"
    return True, ""


def trajectory(execution, answer):
    """喂给模型的本轮轨迹。每次调用的返回先按 loop 的方式压缩，再按总预算分摊。"""
    calls = ops_calls(execution)
    question = str(execution.get("question") or "")[:500]
    conclusion = (answer or "").strip()[:ANSWER_CHARS]
    budget = TRAJECTORY_CHARS - len(question) - len(conclusion) - 200
    per_call = max(300, min(CALL_CHARS, budget // max(1, len(calls))))
    lines = [f"用户的问题：{question}", ""]
    for index, call in enumerate(calls, 1):
        args = "，".join(f"{k}={v}" for k, v in call["args"].items() if v not in ("", None))
        head = f"第 {index} 次调用 {call['tool']}" + (f"（{args}）的返回：" if args else " 的返回：")
        body = _clip(_condense(call["output"]), per_call) if call["ok"] else f"[失败] {call['output'][:300]}"
        lines += [head, body, ""]
    lines += ["最终结论：", conclusion]
    return "\n".join(lines)


def _check_evidence(step_tool, quote, calls):
    """evidence 必须指向轨迹里真实存在的调用：序号在范围内、工具名与那次调用和本步都对得上。

    对不上的不丢，加 ⚠ 前缀留给人看——和文档抽取里「未在文档中找到」是同一个做法。
    """
    quote = str(quote or "").strip()
    if not quote:
        return "⚠ 未给出依据"
    match = EVIDENCE.search(quote)
    if match:
        index, tool = int(match.group(1)), match.group(2)
        if 1 <= index <= len(calls) and calls[index - 1]["tool"] == tool == step_tool:
            return quote
    return f"⚠ 对不上的依据：{quote}"


@traceable(name="SOP 沉淀", run_type="chain")
def generate(execution, answer, known_tools):
    """从轨迹长出一个候选 SOP：{"name", "trigger", "steps"}；没有或不合格返回 None，绝不抛异常。

    known_tools：工具名 -> {"desc", "params"}（或只是说明文字），和文档抽取用同一份。
    """
    if not known_tools:
        return None
    calls = ops_calls(execution)
    model = chat_model(timeout=150, max_retries=0, max_tokens=MAX_OUTPUT_TOKENS)
    messages = [("system", GROW_PROMPT.format(tools=_listing(known_tools))),
                ("human", trajectory(execution, answer))]
    content = ""
    for attempt in (1, 2):
        try:
            content = (model.invoke(messages).content or "").strip()
        except Exception as exc:
            log.info("SOP growth failed for %s: %s", execution["id"], why(exc))
            return None
        if content:
            break
        log.info("empty SOP growth response for %s (attempt %d)", execution["id"], attempt)
    parsed = _parse(content)
    if not parsed or not isinstance(parsed[0], dict):
        return None
    item = parsed[0]
    steps = item.get("steps")
    if not isinstance(steps, list):
        return None

    kept, dropped = [], set()
    for step in steps[:MAX_STEPS]:
        if not isinstance(step, dict):
            continue
        tool = step.get("tool")
        if tool not in known_tools:
            if tool:
                dropped.add(str(tool))
            continue
        _, params = _spec(known_tools[tool])
        args, _ = _clean_args(step.get("args"), params)
        kept.append({"tool": tool, "args": args,
                     "checkpoint": str(step.get("checkpoint") or "").strip()[:300],
                     "evidence": _check_evidence(tool, step.get("evidence"), calls)[:300]})
    if dropped:
        log.info("SOP growth for %s dropped unknown tools: %s", execution["id"], sorted(dropped))
    if not kept:
        return None
    try:
        name, trigger, steps = playbooks.validate(
            str(item.get("name") or execution.get("question") or "")[:playbooks.NAME_MAX],
            str(item.get("trigger") or "")[:playbooks.TRIGGER_MAX], kept, set(known_tools))
    except playbooks.InvalidPlaybook as exc:
        log.info("grown SOP for %s rejected: %s", execution["id"], exc)
        return None
    return {"name": name, "trigger": trigger, "steps": steps}


def _closest(step_tools, candidates):
    """候选步骤序列最像哪个已有 SOP（含停用的——停用的也不该再长一个重样的）。"""
    sig = signature(step_tools)
    best, score = None, 0.0
    for playbook in candidates:
        ratio = similarity(sig, signature(s["tool"] for s in playbook["steps"]))
        if ratio > score:
            best, score = playbook, ratio
    return best, score


def propose(execution_id, answer, known_tools):
    """判断 → 生成 → 入库，返回提议 id 或 None。schedule() 在后台线程里调它，测试里直接调。"""
    execution = graph.execution(execution_id)
    if not execution:
        return None
    wanted, reason = should_propose(execution, answer, playbooks.list_all(only_enabled=True))
    if not wanted:
        log.info("no SOP proposal for %s: %s", execution_id, reason)
        return None
    candidate = generate(execution, answer, known_tools)
    if not candidate:
        return None

    calls = ops_calls(execution)
    payload = {"name": candidate["name"], "trigger": candidate["trigger"],
               "steps": candidate["steps"], "source": SOURCE,
               "summary": {"tools": len({c["tool"] for c in calls}), "calls": len(calls)}}
    kind = "new_sop"
    target, score = _closest([s["tool"] for s in candidate["steps"]], playbooks.list_all())
    if target and score >= SIMILAR:
        have = {s["tool"] for s in target["steps"]}
        extra = [s for s in candidate["steps"] if s["tool"] not in have]
        if not extra:
            log.info("no SOP proposal for %s: already covered by SOP %s", execution_id, target["name"])
            return None
        kind = "extend_sop"
        payload.update(steps=extra, target={"id": target["id"], "name": target["name"]},
                       similarity=round(score, 2))
    return graph.add_proposal(kind, payload, [f"tool_call:{c['id']}" for c in calls],
                              execution_id=execution_id,
                              signature=signature(c["tool"] for c in calls))


# 单线程：模型调用串行化，排查高峰时也不会一下子压过去一堆沉淀请求
_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="grow")


def schedule(execution_id, answer, known_tools):
    """回答落库后调用：后台跑 propose，任何失败只记日志。

    known_tools 可以是现成的字典，也可以是取字典的函数——向宿主机要工具清单要走一次网络，
    放到后台线程里做，不耽误请求收尾。
    """
    if not enabled():
        return None

    def work():
        try:
            propose(execution_id, answer, known_tools() if callable(known_tools) else known_tools)
        except Exception:
            log.warning("SOP proposal failed for %s", execution_id, exc_info=True)

    return _pool.submit(work)
