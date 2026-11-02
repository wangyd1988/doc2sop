"""SOP 执行记录、自动执行（定时、告警）、邮件、知识库缺口看板的页面接口（docs/自动执行.md）。

都在网页的 Basic 认证后面（FastAPI 的全局依赖），写请求照常过防跨站中间件。唯一的例外是告警入口 /api/alerts/hook：
它挂在路由表上、不经 FastAPI（见 alerts.py），只认配置好的告警令牌，没配时回 404。
"""
import html
import json
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.routing import Route

from app import alerts, automation_config, automation_page, autorun, catalog, gaps, mailer, playbooks, runs, schedules
from app.config import BOT_NAME, SCHEDULER, WEB_USER, log

router = APIRouter()
TEST_MAIL_GAP = 60          # 同一个收件组的测试邮件至少隔多少秒
TEST_MAIL_PER_HOUR = 10
SETTINGS_BODY_MAX = 64 * 1024
SETTINGS_PER_MINUTE = 10    # 每个来源地址每分钟最多改几次设置：和「主机与数据源」的写操作同一档（main.CONFIG_LIMITS）
NO_STORE = {"Cache-Control": "no-store"}


def _groups() -> dict:
    return automation_config.load().groups


def _body(data) -> dict:
    if not isinstance(data, dict):
        raise HTTPException(400, "请求体必须是 JSON 对象")
    return data


# --- 执行记录 ---------------------------------------------------------------------------

@router.get("/api/runs")
def list_runs(playbook_id: str = "", trigger: str = "", level: str = "", offset: int = 0, limit: int = catalog.PAGE):
    offset, limit = catalog.clamp(offset, limit)
    items, total = runs.listing(playbook_id or None, trigger or None, level or None, offset, limit)
    return {"runs": items, "total": total, "offset": offset, "limit": limit}


@router.get("/api/runs/summary")
def runs_summary():
    """SOP 列表、SOP 详情上的小结：执行了几次、最近一次的结论、有几条计划和告警规则、下次什么时候。"""
    out = runs.summary_by_playbook()
    for item in schedules.overview():
        entry = out.setdefault(item["playbook_id"], {"runs": 0, "last": None})
        entry["schedules"] = entry.get("schedules", 0) + 1
        if item["next_at"] and (not entry.get("next_at") or item["next_at"] < entry["next_at"]):
            entry["next_at"] = item["next_at"]
    for rule in alerts.rules():
        entry = out.setdefault(rule["playbook_id"], {"runs": 0, "last": None})
        entry["rules"] = entry.get("rules", 0) + 1
    return {"playbooks": out}


@router.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    item = runs.detail(run_id)
    if item is None:
        raise HTTPException(404, "执行记录不存在")
    return item


@router.get("/api/runs/{run_id}/report.md")
def run_markdown(run_id: str):
    text = runs.markdown(run_id)
    if text is None:
        raise HTTPException(404, "执行记录不存在")
    run = runs.get(run_id)
    name = f"SOP执行报告-{run['playbook_name']}-{runs.local_time(run['started_at'])[:16].replace(':', '')}.md"
    return Response(text, media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f"attachment; filename=\"sop-run-{run_id[:8]}.md\"; filename*=UTF-8''{quote(name)}",
        "Cache-Control": "private, no-store"})


@router.delete("/api/runs/{run_id}")
def delete_run(run_id: str):
    run = runs.get(run_id)
    if run is None:
        raise HTTPException(404, "执行记录不存在")
    if run["status"] in ("queued", "running"):
        raise HTTPException(409, "还在执行，结束后再删")
    runs.delete(run_id)
    log.info("run record %s deleted (SOP %s)", run_id, run["playbook_name"])
    return {"deleted": run_id}


@router.post("/api/playbooks/{playbook_id}/run")
def run_playbook_now(playbook_id: str, data: dict = Body(default_factory=dict)):
    """SOP 页的「立即执行一次」：在后台按 SOP 跑一遍，不进对话，结果在执行记录里。留空的参数要在这里给。"""
    playbook = playbooks.get(playbook_id)
    if playbook is None:
        raise HTTPException(404, "SOP 不存在")
    problem = autorun.precheck(playbook)
    if problem:
        raise HTTPException(409, problem)
    try:
        params = schedules.clean_params(playbook, _body(data).get("params"))
    except schedules.InvalidSchedule as exc:
        raise HTTPException(400, str(exc)) from None
    try:
        run_id = autorun.enqueue(playbook, "web", note="立即执行一次", params=params)
    except autorun.Busy as exc:
        raise HTTPException(409, str(exc)) from None
    return {"run": runs.get(run_id)}


# --- 定时执行 ---------------------------------------------------------------------------

def _limits() -> dict:
    return {"min_every": schedules.MIN_EVERY, "max_every": schedules.MAX_EVERY, "max_schedules": schedules.MAX_SCHEDULES,
            "max_per_sop": schedules.MAX_PER_SOP, "grace_minutes": int(schedules.GRACE.total_seconds() // 60),
            "max_running": autorun.MAX_RUNNING, "max_queued": autorun.MAX_QUEUED, "per_hour": alerts.PER_HOUR,
            "dedup_default": alerts.DEDUP_DEFAULT, "dedup_range": list(alerts.DEDUP_RANGE),
            "stale_minutes": autorun.STALE_MINUTES, "keep_days": autorun.KEEP_DAYS}


@router.get("/api/schedules")
def list_schedules(playbook_id: str = ""):
    return {"schedules": schedules.overview(playbook_id or None), "limits": _limits(), "scheduler": SCHEDULER}


@router.post("/api/schedules")
def create_schedule(data: dict = Body(...)):
    try:
        item = schedules.create(_body(data), _groups())
    except schedules.InvalidSchedule as exc:
        raise HTTPException(400, str(exc)) from None
    return {"schedule": item}


def _schedule(schedule_id):
    item = schedules.get(schedule_id)
    if item is None:
        raise HTTPException(404, "计划不存在")
    return item


@router.put("/api/schedules/{schedule_id}")
def update_schedule(schedule_id: str, data: dict = Body(...)):
    _schedule(schedule_id)
    try:
        item = schedules.update(schedule_id, _body(data), _groups())
    except schedules.InvalidSchedule as exc:
        raise HTTPException(400, str(exc)) from None
    return {"schedule": item}


@router.post("/api/schedules/{schedule_id}/pause")
def pause_schedule(schedule_id: str):
    _schedule(schedule_id)
    return {"schedule": schedules.set_enabled(schedule_id, False)}


@router.post("/api/schedules/{schedule_id}/resume")
def resume_schedule(schedule_id: str):
    item = _schedule(schedule_id)
    playbook = playbooks.get(item["playbook_id"])
    if playbook is None or not playbook["enabled"]:
        raise HTTPException(409, "SOP 已删除或停用：先启用 SOP 再恢复计划")
    return {"schedule": schedules.set_enabled(schedule_id, True)}


@router.post("/api/schedules/{schedule_id}/run")
def run_schedule_now(schedule_id: str):
    """计划上的「立即执行一次」：用这条计划的参数和邮件设置，马上在后台跑一次（不占计划时刻）。"""
    item = _schedule(schedule_id)
    playbook = playbooks.get(item["playbook_id"])
    problem = autorun.precheck(playbook)
    if problem:
        raise HTTPException(409, problem)
    try:
        run_id = autorun.enqueue(playbook, "schedule", source_id=schedule_id,
                                 note=f"{item['describe']}的计划，立即执行一次", params=item["params"])
    except autorun.Busy as exc:
        raise HTTPException(409, str(exc)) from None
    return {"run": runs.get(run_id)}


@router.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    _schedule(schedule_id)
    schedules.delete(schedule_id)
    return {"deleted": schedule_id}


# --- 告警规则 ---------------------------------------------------------------------------

@router.get("/api/alert-rules")
def list_alert_rules(playbook_id: str = ""):
    return {"rules": alerts.overview(playbook_id or None), "limits": _limits()}


@router.post("/api/alert-rules")
def create_alert_rule(data: dict = Body(...)):
    try:
        rule = alerts.create_rule(_body(data), _groups())
    except alerts.InvalidRule as exc:
        raise HTTPException(400, str(exc)) from None
    return {"rule": rule}


def _rule(rule_id):
    rule = alerts.get_rule(rule_id)
    if rule is None:
        raise HTTPException(404, "告警规则不存在")
    return rule


@router.put("/api/alert-rules/{rule_id}")
def update_alert_rule(rule_id: str, data: dict = Body(...)):
    _rule(rule_id)
    try:
        rule = alerts.update_rule(rule_id, _body(data), _groups())
    except alerts.InvalidRule as exc:
        raise HTTPException(400, str(exc)) from None
    return {"rule": rule}


@router.post("/api/alert-rules/{rule_id}/pause")
def pause_alert_rule(rule_id: str):
    _rule(rule_id)
    return {"rule": alerts.set_rule_enabled(rule_id, False)}


@router.post("/api/alert-rules/{rule_id}/resume")
def resume_alert_rule(rule_id: str):
    rule = _rule(rule_id)
    playbook = playbooks.get(rule["playbook_id"])
    if playbook is None or not playbook["enabled"]:
        raise HTTPException(409, "SOP 已删除或停用：告警只能触发启用的 SOP")
    return {"rule": alerts.set_rule_enabled(rule_id, True)}


@router.delete("/api/alert-rules/{rule_id}")
def delete_alert_rule(rule_id: str):
    _rule(rule_id)
    alerts.delete_rule(rule_id)
    return {"deleted": rule_id}


@router.get("/api/alerts/events")
def alert_events(limit: int = 50):
    return {"events": alerts.recent_events(max(1, min(200, limit)))}


# --- 自动执行的设置（发件邮箱、收件组、告警入口）、测试邮件 ---------------------------------------------

@router.get("/api/automation")
def automation_status(response: Response):
    """自动执行的设置和状态。settings 是页面上看、改的那份（automation_page.view）：发件服务器、账号、收件组的地址都看得到
    （要改就得看得见），授权码、告警令牌永远只有状态（已设置的时间 / 未设置 / 要重新输入），没有值。
    其余是摘要（收件组只有名字和人数，计划、告警规则的表单用）、各种上限、告警入口的地址。"""
    response.headers.update(NO_STORE)
    return {**automation_config.public(), "settings": automation_page.view(), "hook_path": alerts.PATH,
            "scheduler": SCHEDULER, "limits": _limits(),
            "counts": {"schedules": len(schedules.listing()), "rules": len(alerts.rules())}}


_settings_hits: dict = {}
_settings_lock = threading.Lock()


def _settings_wait(address: str) -> int:
    """这个来源地址还要等几秒才能再改；0 表示现在就行（并记一次）。"""
    now = time.monotonic()
    with _settings_lock:
        for stale in [key for key, hits in _settings_hits.items() if not hits or now - hits[-1] >= 60]:
            del _settings_hits[stale]
        hits = [at for at in _settings_hits.get(address, []) if now - at < 60]
        if len(hits) >= SETTINGS_PER_MINUTE:
            _settings_hits[address] = hits
            return int(60 - (now - hits[0])) + 1
        _settings_hits[address] = hits + [now]
    return 0


async def _settings_body(request: Request) -> dict:
    body = await request.body()
    if len(body) > SETTINGS_BODY_MAX:
        raise HTTPException(413, "请求体太大")
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(400, "请求体不是合法 JSON") from None
    if not isinstance(data, dict):
        raise HTTPException(400, "请求体必须是 JSON 对象")
    return data


@router.post("/api/automation/settings")
async def save_settings(request: Request):
    """页面上改自动执行的设置：{version, change: {kind, …}, passphrase}。扩大能力的要审批口令（工具服务核对），缩小能力的不要。
    请求体手动解析：FastAPI 的 422 会把输入（口令、授权码）回显出来。口令、授权码不保存、不记日志，也不出现在回复和报错里；
    新生成的告警令牌只在这一次的回复里。每个来源地址每分钟最多 SETTINGS_PER_MINUTE 次。"""
    data = await _settings_body(request)
    address = request.client.host if request.client else "-"
    wait = _settings_wait(address)
    if wait:
        log.info("automation settings refused: too frequent (ip=%s)", address)
        raise HTTPException(429, f"操作太频繁了：{wait} 秒后再试")
    try:
        result = await run_in_threadpool(automation_page.apply, data, f"web user={WEB_USER} ip={address}", WEB_USER, address)
    except automation_page.Refused as exc:
        change = data.get("change")
        kind = change.get("kind") if isinstance(change, dict) else None
        known = kind if isinstance(kind, str) and kind in automation_page.PLANNERS else "?"   # 请求里写的原样不进日志：可能带换行
        log.info("automation settings %s refused: %s (ip=%s)", known, exc.status, address)
        return JSONResponse({"detail": str(exc), **exc.extra}, status_code=exc.status, headers=NO_STORE)
    return JSONResponse(result, headers=NO_STORE)


_test_mail = {"times": deque(), "by_group": {}}
_test_mail_lock = threading.Lock()


@router.post("/api/automation/test-mail")
def test_mail(request: Request, data: dict = Body(...)):
    """发一封测试邮件：只能发给配置好的收件组；同一个组每分钟一封、每小时一共最多 TEST_MAIL_PER_HOUR 封。"""
    group = " ".join(str(_body(data).get("group") or "").split())
    settings = automation_config.load()
    if settings.mail is None:
        raise HTTPException(409, f"发件设置用不了：{settings.mail_problem}" if settings.mail_problem else
                            "还没有配置发件邮箱（SMTP）：先在下面的「邮件」里设置")
    if group not in settings.groups:
        raise HTTPException(400, f"没有收件组「{group}」：可能刚被删掉，刷新后再选")
    now = time.monotonic()
    with _test_mail_lock:
        times = _test_mail["times"]
        while times and now - times[0] > 3600:
            times.popleft()
        if len(times) >= TEST_MAIL_PER_HOUR:
            raise HTTPException(429, f"测试邮件每小时最多 {TEST_MAIL_PER_HOUR} 封，稍后再试")
        if now - _test_mail["by_group"].get(group, -TEST_MAIL_GAP) < TEST_MAIL_GAP:
            raise HTTPException(429, "同一个收件组的测试邮件每分钟最多一封")
        times.append(now)
        _test_mail["by_group"][group] = now
    who = f"user={WEB_USER} ip={request.client.host if request.client else '-'}"
    log.info("test mail to group %s requested (%s)", group, who)
    subject = f"[{BOT_NAME}] 测试邮件：收件组「{group}」"
    text = (f"这是 {BOT_NAME} 的测试邮件，发给收件组「{group}」。\n收到它说明邮件设置能用："
            "SOP 自动执行有异常、没跑成、没法判断时会发到这个组（按计划和告警规则上的设置）。\n")
    html_body = "".join(f"<p>{html.escape(line)}</p>" for line in text.strip().split("\n"))
    try:
        result = mailer.send(group, subject, text, html_body, settings=settings, delays=())
    except mailer.MailError as exc:
        log.warning("test mail to group %s failed: %s", group, exc)
        raise HTTPException(502, f"没发出去：{exc}") from None
    log.info("test mail to group %s sent (%d recipients)", group, result["recipients"])
    return {"sent": True, "group": group, "recipients": result["recipients"]}


# --- 知识库缺口 ---------------------------------------------------------------------------

@router.get("/api/gaps")
def gap_board(limit: int = 0):
    return gaps.board(limit=max(0, min(200, limit)) or None)


@router.post("/api/gaps/ignore")
def ignore_gaps(data: dict = Body(...)):
    keys = _body(data).get("keys")
    if not isinstance(keys, list) or not keys:
        raise HTTPException(400, "要给出这一组问题的 keys")
    return {"ignored": gaps.ignore(keys)}


# --- 挂到应用上 ---------------------------------------------------------------------------

def install(app):
    """main 调用：页面接口、告警入口（不经 FastAPI 的 Basic 依赖）、定时执行的后台线程（SCHEDULER 打开时，随应用启停）。"""
    app.include_router(router)
    hook = alerts.Hook()
    app.router.routes.append(Route(alerts.PATH, endpoint=hook))
    app.router.routes.append(Route(alerts.PATH + "/", endpoint=hook))
    previous = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app_):
        async with previous(app_) as state:
            if SCHEDULER:
                schedules.start()
            try:
                yield state
            finally:
                schedules.stop()
                autorun.shutdown()

    app.router.lifespan_context = lifespan
