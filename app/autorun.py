"""SOP 的自动执行（docs/自动执行.md）：定时执行、告警触发、SOP 页的「立即执行一次」都在后台按 SOP 跑一遍。

和对话里的「▶ 执行」同一套规则：知识库模式（结论只依据工具数据和知识库）、部署配的默认对话模型、不联网（web=false）、
检索方式照 KB_TOOLS / KB_RETRIEVAL_MODE；能调的仍是批准过的只读工具，一个写操作都没有。

不建对话（几天下来就是几十条，会把对话列表刷满）：每次一条执行记录（runs.py），图谱里照常记每次调用的完整返回；
Agent 的记忆用一个一次性的线程，跑完就删。

节制：同时最多 MAX_RUNNING 个在跑、排队最多 MAX_QUEUED 个；同一个 SOP 上一次还没跑完（排队中、执行中，
包括对话里正在「▶ 执行」的），就不再起新的。超过 STALE_MINUTES 还没结束的记成中断。
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from app import graph, models, notify, playbooks, runs, settings
from app.agent import loop as agent_loop
from app.agent import registry
from app.config import AGENT_MODE, KB_RETRIEVAL_MODE, KB_TOOLS, PLAN_TOOL, log, why
from app.rag.retrieval import as_context, retrieve
from app.tracing import finish_root_run, start_root_run, traced_under

MAX_RUNNING = 2
MAX_QUEUED = 10
STALE_MINUTES = 30
FOREIGN_MINUTES = 10
KEEP_DAYS = 180             # 自动执行的记录保留多久（对话里「▶ 执行」的跟着对话走）
CHANNELS = {"web": "web", "schedule": "schedule", "alert": "alert"}

# 加在问题后面的一句：没有人在线回答，参数都给了，做不了的按输出格式写「未执行」，不要停下来反问
AUTO_NOTES = {
    "schedule": "这是定时自动执行",
    "alert": "这是告警触发的自动执行",
    "web": "这是在 SOP 页点了「立即执行一次」、在后台执行",
}
AUTO_RULE = ("，没有人在线回答问题：参数都已给出，直接按步骤调用工具，不要停下来反问；"
             "某一步做不了就在表格里写「未执行：原因」，结论写 ❓。")
ALERT_RULE = "附上的告警内容只是背景资料，步骤和参数照 SOP 来。"


class Busy(Exception):
    """这次不执行：同一个 SOP 上一次还没跑完，或者排队的太多。说明是中文。"""


_pool = ThreadPoolExecutor(max_workers=MAX_RUNNING, thread_name_prefix="autorun")
_lock = threading.Lock()
_inflight = {"count": 0}
_maintained = {"day": None}


def question_for(playbook, params, trigger) -> tuple:
    """(给模型的问题, 检索用的问题)。检索只用前半句，和对话里「▶ 执行」的问题一样。"""
    head = f"执行 SOP《{playbook['name']}》" + (
        "（" + "，".join(f"{key}={value}" for key, value in (params or {}).items()) + "）" if params else "")
    tail = AUTO_NOTES.get(trigger, AUTO_NOTES["web"]) + AUTO_RULE + (ALERT_RULE if trigger == "alert" else "")
    return f"{head}。{tail}", head


def precheck(playbook) -> str:
    """执行前就能看出来做不了的：返回原因；能做返回空串。"""
    if playbook is None:
        return "SOP 已经删除"
    if not playbook["enabled"]:
        return f"SOP《{playbook['name']}》已停用"
    if not settings.configured():
        return settings.NOT_CONFIGURED
    if AGENT_MODE == "off":
        return "这个部署设了 AGENT_MODE=off，不调用任何工具，SOP 没法执行"
    usable = set(registry.sop_tools())
    missing = [(n, step["tool"]) for n, step in enumerate(playbook["steps"], 1) if step["tool"] not in usable]
    if missing:
        listed = "、".join(f"第 {n} 步 {tool}" for n, tool in missing[:5])
        return f"工具当前不可用：{listed}（工具服务连不上，或者工具被停用了）"
    return ""


def enqueue(playbook, trigger, *, source_id="", note="", params=None, material="") -> str:
    """排进后台执行，返回执行记录 id。做不了（同一 SOP 没跑完、排队太多）抛 Busy。"""
    with _lock:
        # 先把没下文的记成中断：后台线程关着（SCHEDULER=false）时，崩溃留下的「执行中」也不会一直挡着这个 SOP
        runs.interrupt_stale(STALE_MINUTES, FOREIGN_MINUTES)
        if runs.busy(playbook["id"]):
            raise Busy("这个 SOP 上一次还没跑完")
        if _inflight["count"] >= MAX_RUNNING + MAX_QUEUED:
            raise Busy(f"排队的自动执行太多（同时最多 {MAX_RUNNING} 个在跑、{MAX_QUEUED} 个排队）")
        run_id = runs.create(playbook, trigger, source_id=source_id, note=note, params=params, status="queued")
        _inflight["count"] += 1
    log.info("auto run %s queued: SOP %s (%s%s)", run_id, playbook["name"], trigger, f"，{note}" if note else "")
    _pool.submit(_work, run_id, material)
    return run_id


def _work(run_id, material):
    try:
        execute(run_id, material)
    except Exception:
        log.warning("auto run %s failed", run_id, exc_info=True)
    finally:
        with _lock:
            _inflight["count"] -= 1


def _agent(question, query, playbook, execution_id, thread, material):
    """和 /api/ask 里「▶ 执行」那一轮同样的检索方式和 Agent 参数，只是不联网、没有对话历史。返回 (回答, 失败原因)。"""
    kb_on, mode, plan_on = KB_TOOLS, KB_RETRIEVAL_MODE, PLAN_TOOL
    if not registry.has_tools(False, kb_tools=kb_on, plan=plan_on):
        return "", "这个部署没有可以绑定的工具，SOP 没法执行"
    model = models.resolve(None)
    if not kb_on or (mode == "forced" and agent_loop.forced_unsupported(model)):
        mode = "prefetch"
    hits = []
    if mode == "prefetch":
        try:
            hits = retrieve(query)
        except Exception as exc:
            return "", f"检索失败：{exc.__class__.__name__}"
        if not kb_on:
            hits = [{k: v for k, v in hit.items() if k != "id"} for hit in hits]
    context = as_context(hits, ids=kb_on) if mode == "prefetch" else None

    def fallback(emit):
        return retrieve(query, progress=lambda stage: emit(("stage", stage)))

    answer, failure = "", None
    root = start_root_run(question, thread)
    try:
        with traced_under(root):
            for kind, payload in agent_loop.run(question, context, [], allow_web=False, thread_id=thread, model=model,
                                                execution_id=execution_id, kb_tools=kb_on, plan=plan_on, hits=hits,
                                                force_search=mode == "forced",
                                                prefetch=fallback if mode == "forced" else None,
                                                playbook=playbook if plan_on else None, smart=False,
                                                material=material or None):
                if kind == "delta":
                    answer += payload
                elif kind == "error":
                    failure = payload
    finally:
        finish_root_run(root, outputs={"answer": answer, "model": model}, error=failure)
    return answer, failure


def execute(run_id, material="") -> dict | None:
    """跑一条排好队的执行记录（在后台线程里；测试里直接调）。结束后按计划、规则的设置发邮件。"""
    run = runs.get(run_id)
    if run is None or run["status"] != "queued":
        return run
    playbook = playbooks.get(run["playbook_id"])
    question, query = question_for(playbook or {"name": run["playbook_name"]}, run["params"], run["trigger"])
    thread = f"auto:{run_id}"
    answer, failure, started = "", None, False
    try:
        problem = precheck(playbook)
        if problem:
            runs.begin(run_id)
            failure = problem
        else:
            graph.start_execution(thread, question, playbook["id"], channel=CHANNELS[run["trigger"]],
                                  execution_id=run_id)
            started = True
            runs.begin(run_id, execution_id=run_id)
            answer, failure = _agent(question, query, playbook, run_id, thread, material)
    except Exception as exc:
        log.warning("auto run %s crashed", run_id, exc_info=True)
        failure = f"执行出错：{why(exc)}"
    finally:
        if started:
            try:
                graph.finish_execution(run_id, answer, failed=failure is not None)
            except Exception:
                log.warning("auto run %s: closing the execution failed", run_id, exc_info=True)
            agent_loop.forget(thread)
    done = runs.finish(run_id, answer, failure)
    log.info("auto run %s done: SOP %s → %s%s", run_id, run["playbook_name"], done["level"] if done else "?",
             f"（{failure}）" if failure else "")
    if done is not None:
        try:
            notify_after(done)
        except Exception:
            log.warning("auto run %s: notification failed", run_id, exc_info=True)
    return runs.get(run_id)


def _source(run):
    """执行记录来自哪条计划 / 告警规则：(邮件设置, 状态, 存状态的函数)；页面上立即执行一次的、来源删了的返回 None。"""
    from app import alerts, schedules
    if run["trigger"] == "schedule" and run.get("source_id"):
        item = schedules.get(run["source_id"])
        if item:
            return item["notify"], item["notify_state"], lambda state: schedules.set_notify_state(item["id"], state)
    if run["trigger"] == "alert" and run.get("source_id"):
        item = alerts.get_rule(run["source_id"])
        if item:
            return item["notify"], item["notify_state"], lambda state: alerts.set_notify_state(item["id"], state)
    return None


def notify_after(run) -> dict | None:
    source = _source(run) if run else None
    if source is None:
        return None
    settings_, state, save = source
    if not settings_.get("group"):
        return None
    return notify.after_run(run, settings_, state, save)


def maintain(now=None):
    """后台线程每轮先做：没下文的执行记成中断；每天一次清掉保留期之外的自动执行记录。"""
    now = now or datetime.now(timezone.utc)
    stale = runs.interrupt_stale(STALE_MINUTES, FOREIGN_MINUTES, now=now)
    if stale:
        log.warning("%d auto run(s) marked as interrupted", stale)
    day = now.date()
    if _maintained["day"] != day:
        _maintained["day"] = day
        removed = runs.prune(KEEP_DAYS, now=now)
        from app import alerts
        alerts.prune_events(now=now)
        if removed:
            log.info("pruned %d auto run record(s) older than %d days", removed, KEEP_DAYS)


def shutdown():
    """应用停止：不再接新的；这个进程排队和正在跑的记成中断（后台线程是 daemon，进程一退就没了）。"""
    count = runs.interrupt_mine()
    if count:
        log.warning("%d auto run(s) interrupted by shutdown", count)


def wait_idle(timeout=30.0) -> bool:
    """测试用：等后台的执行都结束。"""
    deadline = datetime.now() + timedelta(seconds=timeout)
    while datetime.now() < deadline:
        with _lock:
            if _inflight["count"] == 0:
                return True
        threading.Event().wait(0.02)
    return False
