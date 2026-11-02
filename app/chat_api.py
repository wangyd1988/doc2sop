"""云上协同的页面接口和挂载（docs/正式部署.md「云上协同」）。

都在网页的 Basic 认证后面（FastAPI 的全局依赖），写请求照常过防跨站中间件：不加任何不经登录的路由，转接程序也不需要网页密码
（是 kb-app 去长轮询它）。main 只在配了 CHAT_BRIDGE_URL 或 CHAT_BRIDGE_TOKEN 时导入这个模块、调 install。

    GET  /api/chat/status                转接程序连没连上、能不能发；开通了哪些群和人、哪里写得不对；最近 @ 过、还没开通的
    POST /api/chat/test-push             发一条测试消息：只能选转接程序里配好的目标名字；每个目标每分钟 1 条、每小时一共 10 条
    GET  /api/chat/notify                计划、告警规则推到哪（旁表 chat_notify）和能选的目标
    PUT  /api/chat/notify/{kind}/{id}    改一条：kind 是 schedule 或 rule；目标空着就是不推
"""
import json
import threading
import time
from collections import deque
from contextlib import asynccontextmanager

from fastapi import APIRouter, Body, HTTPException, Request

from app import alerts, chat_bridge, chat_channel, chat_config, chat_push, chat_store, notify, schedules
from app.agent import registry, web_search
from app.chat_bridge import BridgeError
from app.config import CHAT_BRIDGE_TOKEN, CHAT_BRIDGE_URL, WEB_USER, log

router = APIRouter()
TEST_GAP = 60               # 同一个目标的测试消息至少隔多少秒
TEST_PER_HOUR = 10
BRIDGE_KEYS = ("enabled", "state", "since", "started_at", "tls", "diagnose", "send", "robot", "conflict", "targets",
               "target_kinds", "problems", "queue", "kb_app_last_poll", "counters")
NOTIFY_KINDS = {"schedule": "计划", "rule": "告警规则"}
_state = {"channel": None, "problem": "", "smart": None}


def _body(data) -> dict:
    if not isinstance(data, dict):
        raise HTTPException(400, "请求体必须是 JSON 对象")
    return data


def _bridge_status():
    """(转接程序的状态, 连不上时的说明)。"""
    bridge = chat_bridge.current()
    if bridge is None:
        return {}, _state["problem"] or "没有配转接程序"
    try:
        return bridge.status(), ""
    except BridgeError as exc:
        return {}, str(exc)


def scope_problems(cfg) -> list:
    """配置本身写对了、但这个部署此刻做不到的：工具不可用、智能模式没打开、联网没配。"""
    out = []
    try:
        live = set(registry.data_tools())
    except Exception:
        live = None
    smart = _state["smart"]() if _state["smart"] else {"available": False}
    for scope in list(cfg.groups.values()) + list(cfg.people.values()):
        gone = [name for name in scope.tools if live is not None and name not in live]
        if gone:
            out.append(f"「{scope.name}」开的工具 {'、'.join(gone)} 现在不可用（没批准、改了名、下线了，或者工具服务连不上）")
        if scope.mode == "smart" and not smart.get("available"):
            out.append(f"「{scope.name}」写了 mode: smart，但这个部署的智能模式不能用，先按知识库模式答")
        if scope.web and not web_search.enabled():
            out.append(f"「{scope.name}」写了 web: true，但这个部署没有配联网搜索")
    return out


def paste_lines(item) -> dict:
    """没开通的会话：可以直接粘进 chat.yaml 和转接程序 targets.yaml 的那几行。"""
    ident = json.dumps(item["ident"], ensure_ascii=False)
    if item["chat_type"] == "single":
        name = item["sender_name"] or f"用户…{item['ident'][-4:]}"
        return {"chat_yaml": f"people:\n  {ident}: {{name: {json.dumps(name, ensure_ascii=False)}}}",
                "targets_yaml": f"targets:\n  {json.dumps(name, ensure_ascii=False)}: {{user_id: {ident}}}"}
    name = item["chat_name"] or f"群…{item['ident'][-4:]}"
    return {"chat_yaml": f"groups:\n  {ident}: {{name: {json.dumps(name, ensure_ascii=False)}}}",
            "targets_yaml": f"targets:\n  {json.dumps(name, ensure_ascii=False)}: {{chat_id: {ident}}}"}


@router.get("/api/chat/status")
def chat_status():
    cfg = chat_config.load()
    live, error = _bridge_status()
    channel = _state["channel"]
    return {"enabled": True, "problem": _state["problem"],
            "bridge": {"reachable": bool(live), "error": error, **{k: live[k] for k in BRIDGE_KEYS if k in live}},
            "channel": channel.status() if channel else None,
            "config": chat_config.public(cfg),
            "problems": list(cfg.problems) + ([cfg.loose] if cfg.loose else []) + scope_problems(cfg),
            "unknown": [{**item, "paste": paste_lines(item)} for item in chat_store.unknown_list()],
            "pushes": chat_store.push_recent(10)}


_tests = {"times": deque(), "by_target": {}}
_tests_lock = threading.Lock()


@router.post("/api/chat/test-push")
def chat_test_push(request: Request, data: dict = Body(...)):
    target = " ".join(str(_body(data).get("target") or "").split())
    if not target or len(target) > chat_config.NAME_MAX:
        raise HTTPException(400, "要选一个推送目标")
    now = time.monotonic()
    with _tests_lock:
        times = _tests["times"]
        while times and now - times[0] > 3600:
            times.popleft()
        if len(times) >= TEST_PER_HOUR:
            raise HTTPException(429, f"测试消息每小时最多 {TEST_PER_HOUR} 条，稍后再试")
        if now - _tests["by_target"].get(target, -TEST_GAP) < TEST_GAP:
            raise HTTPException(429, "同一个目标的测试消息每分钟最多一条")
        times.append(now)
        _tests["by_target"][target] = now
    log.info("chat test push requested (user=%s ip=%s)", WEB_USER, request.client.host if request.client else "-")
    try:
        reply = chat_push.test_push(target)
    except BridgeError as exc:
        if exc.status == 404:
            raise HTTPException(400, f"转接程序里没有推送目标「{target}」") from None
        raise HTTPException(502, f"没发出去：{exc}") from None
    return {"sent": not reply.get("held"), "held": bool(reply.get("held")), "target": target}


def _notify_view(item) -> dict:
    return {key: item[key] for key in ("kind", "id", "target", "when", "repeat", "updated_at")}


@router.get("/api/chat/notify")
def chat_notify():
    live, error = _bridge_status()
    return {"targets": live.get("targets") or [], "target_kinds": live.get("target_kinds") or {}, "error": error,
            "when": list(notify.WHEN), "repeat": list(notify.REPEAT),
            "items": [_notify_view(item) for item in chat_store.notify_all()]}


@router.put("/api/chat/notify/{kind}/{source_id}")
def set_chat_notify(kind: str, source_id: str, data: dict = Body(...)):
    if kind not in NOTIFY_KINDS:
        raise HTTPException(404, "只能给计划（schedule）或告警规则（rule）设推送")
    found = schedules.get(source_id) if kind == "schedule" else alerts.get_rule(source_id)
    if not found:
        raise HTTPException(404, f"{NOTIFY_KINDS[kind]}不存在")
    body = _body(data)
    target = " ".join(str(body.get("target") or "").split())
    if not target:
        chat_store.notify_delete(kind, source_id)
        log.info("chat push for %s %s turned off", kind, source_id)
        return {"kind": kind, "id": source_id, "target": ""}
    when, repeat = body.get("when") or "problems", body.get("repeat") or "daily"
    if when not in notify.WHEN or repeat not in notify.REPEAT:
        raise HTTPException(400, "什么时候推只能是 problems / always；重复提醒只能是 daily / always / never")
    live, error = _bridge_status()
    if not live:
        raise HTTPException(503, f"转接程序连不上，没法核对推送目标，稍后再保存（{error}）")
    if target not in (live.get("targets") or []):
        raise HTTPException(400, f"转接程序里没有推送目标「{target}」：目标在服务器的 targets.yaml 里配，页面上只能选")
    chat_store.notify_set(kind, source_id, target, when, repeat)
    log.info("chat push for %s %s set (%s, %s)", kind, source_id, when, repeat)
    return _notify_view(chat_store.notify_get(kind, source_id))


# --- main 用的：群聊的对话在网页上只读、对话列表按来源筛选 ---------------------------------------------

def readonly(conversation_id) -> bool:
    return chat_store.owns(conversation_id)


def conversation_list(source="") -> dict:
    source = source if source in ("web", "chat") else ""
    return {"conversations": chat_store.list_conversations(source), "chat": True, "source": source or "all"}


def conversation_source(conversation_id) -> dict:
    found = chat_store.source_of(conversation_id)
    return {"source": found, "readonly": True} if found else {}


def forget(conversation_id):
    chat_store.close_conversation(conversation_id)


# --- 挂到应用上 ---------------------------------------------------------------------------

def install(app, start_turn, turn_events, smart_status):
    """main 调用：建表、挂页面接口；地址和令牌都对时，聊天线程随应用启停。地址写错时不连，页面上写明哪里不对。"""
    chat_store.ensure()
    app.include_router(router)
    _state["smart"] = smart_status
    problem = chat_bridge.check_url(CHAT_BRIDGE_URL) or ("" if CHAT_BRIDGE_TOKEN else "没有配 CHAT_BRIDGE_TOKEN")
    if problem:
        _state["problem"] = problem
        log.warning("chat: not started: %s", problem)
        return
    bridge = chat_bridge.configure(CHAT_BRIDGE_URL, CHAT_BRIDGE_TOKEN)
    channel = chat_channel.Channel(bridge, start_turn, turn_events)
    _state["channel"] = channel
    previous = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app_):
        async with previous(app_) as state:
            channel.start()
            try:
                yield state
            finally:
                channel.stop()

    app.router.lifespan_context = lifespan
