"""SOP 的定时执行（docs/自动执行.md「定时执行」）。

一个 SOP 可以有多条计划：每天几点、每周几几点、或者每隔 N 分钟（最少 MIN_EVERY 分钟）。时间按北京时间：中国不实行
夏令时，Asia/Shanghai 就是固定的 UTC+8，不依赖系统的时区数据。库里存 UTC。每隔 N 分钟的从北京时间当天 0 点起算，
N 能整除一天时就是整点、整半点这样的时刻。

不重复执行：每个计划时刻（计划 id + 时刻）在 sop_slots 里占一行，主键冲突的那个进程不执行。部署切换、重启时新旧两份
可能同时在跑一小会儿：两边算出来的时刻一样，只有一边占得到。

错过：应用没在运行（部署、重启、宕机）的那段时间里到点的执行。迟到 GRACE 以内的照常执行（部署通常一两分钟）；
更晚的记一条「错过」（错过多次也只记一条，写明次数和时间段），不补跑——过时的巡检结果容易误导人，下一次照常按时执行。
错过算「没跑成」，计划选了收件组的会收到邮件。

暂停的计划、SOP 停用或删了的计划不执行，也不算错过；恢复时从恢复的那一刻起算。
"""
import json
import threading
import uuid
from datetime import datetime, time, timedelta, timezone

from app import graph, notify, playbooks, runs
from app.agent import sop_tools
from app.config import log, why

CHINA = timezone(timedelta(hours=8))
KINDS = ("daily", "weekly", "interval")
MIN_EVERY, MAX_EVERY = 15, 7 * 24 * 60
MAX_SCHEDULES, MAX_PER_SOP = 50, 10
GRACE = timedelta(minutes=10)
SCAN_DAYS = 400                 # 错过太久的只往回数这么多天
SCAN_LIMIT = 50000
PARAM_MAX = 200
WEEKDAY_NAMES = "一二三四五六日"
TICK_SECONDS = 20


class InvalidSchedule(ValueError):
    """计划写得不对，附带可直接给页面看的原因。"""


def _utc(iso):
    if not iso:
        return None
    try:
        moment = datetime.fromisoformat(str(iso))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _hm(at):
    hour, minute = str(at).split(":")
    return int(hour), int(minute)


def _days(schedule):
    if schedule["kind"] == "daily":
        return set(range(1, 8))
    days = schedule.get("weekdays") or ""
    if isinstance(days, (list, tuple, set)):
        return {int(d) for d in days}
    return {int(d) for d in str(days).split(",") if d.strip().isdigit()}


def slots(schedule, after, until, limit=SCAN_LIMIT):
    """(after, until] 之间的计划时刻（UTC，从早到晚），最多 limit 个。"""
    if until <= after:
        return
    after = max(after, until - timedelta(days=SCAN_DAYS))
    count = 0
    if schedule["kind"] == "interval":
        every = timedelta(minutes=int(schedule["every"]))
        anchor = (_utc(schedule.get("anchor")) or after).astimezone(timezone.utc)
        steps = 0 if after < anchor else (after - anchor) // every + 1
        moment = anchor + steps * every
        while moment <= until and count < limit:
            yield moment
            count += 1
            moment += every
        return
    hour, minute = _hm(schedule["at"])
    days = _days(schedule)
    if not days:
        return
    day = after.astimezone(CHINA).date()
    while count < limit:
        moment = datetime.combine(day, time(hour, minute), tzinfo=CHINA).astimezone(timezone.utc)
        if moment > until:
            return
        if moment > after and day.isoweekday() in days:
            yield moment
            count += 1
        day += timedelta(days=1)


def next_slot(schedule, after):
    horizon = timedelta(minutes=int(schedule.get("every") or 0) + 1) if schedule["kind"] == "interval" else timedelta(days=8)
    return next(slots(schedule, after, after + horizon, limit=1), None)


def describe(schedule) -> str:
    if schedule["kind"] == "interval":
        every = int(schedule["every"])
        return f"每 {every // 60} 小时" if every % 60 == 0 and every >= 60 else f"每 {every} 分钟"
    if schedule["kind"] == "daily":
        return f"每天 {schedule['at']}"
    days = sorted(_days(schedule))
    if days == [1, 2, 3, 4, 5]:
        return f"工作日（周一到周五）{schedule['at']}"
    return "每周" + "、".join(WEEKDAY_NAMES[d - 1] for d in days) + f" {schedule['at']}"


def _local(moment) -> str:
    return moment.astimezone(CHINA).strftime("%m-%d %H:%M")


# --- 校验与存取 ---------------------------------------------------------------------

def blanks(playbook) -> list:
    return [key for key, _ in sop_tools.blanks(playbook)]


def clean_params(playbook, raw) -> dict:
    """计划、告警规则上的参数：SOP 里留空的参数必须都给默认值，填不全不能保存。别的键不收。"""
    raw = raw if isinstance(raw, dict) else {}
    out, missing = {}, []
    for key in blanks(playbook):
        value = " ".join(str(raw.get(key) if raw.get(key) is not None else "").split())
        if not value:
            missing.append(key)
        elif len(value) > PARAM_MAX:
            raise InvalidSchedule(f"参数 {key} 太长（最多 {PARAM_MAX} 个字）")
        else:
            out[key] = value
    if missing:
        raise InvalidSchedule(f"SOP《{playbook['name']}》有留空的参数：{'、'.join(missing)}。"
                              "自动执行时没有人能回答，必须在这里给默认值")
    return out


def validate(raw, playbook, groups) -> dict:
    if playbook is None:
        raise InvalidSchedule("SOP 不存在")
    if not playbook["enabled"]:
        raise InvalidSchedule(f"SOP《{playbook['name']}》已停用：先启用再设置计划")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise InvalidSchedule("计划只能是每天、每周或每隔 N 分钟")
    out = {"kind": kind, "at": "", "weekdays": "", "every": 0}
    if kind in ("daily", "weekly"):
        at = str(raw.get("at") or "").strip()
        try:
            hour, minute = _hm(at)
            valid = 0 <= hour <= 23 and 0 <= minute <= 59
        except ValueError:
            valid = False
        if not valid:
            raise InvalidSchedule("时间要写成 HH:MM（北京时间，如 09:00）")
        out["at"] = f"{hour:02d}:{minute:02d}"
    if kind == "weekly":
        days = raw.get("weekdays") or []
        if isinstance(days, str):
            days = [d for d in days.split(",") if d.strip()]
        try:
            days = sorted({int(d) for d in days})
        except (TypeError, ValueError):
            days = []
        if not days or any(d < 1 or d > 7 for d in days):
            raise InvalidSchedule("每周的计划至少选一天（1 是周一，7 是周日）")
        out["weekdays"] = ",".join(map(str, days))
    if kind == "interval":
        try:
            every = int(raw.get("every"))
        except (TypeError, ValueError):
            every = 0
        if not MIN_EVERY <= every <= MAX_EVERY:
            raise InvalidSchedule(f"间隔要在 {MIN_EVERY} 分钟到 {MAX_EVERY // 1440} 天之间：太频繁会挤占模型和工具")
        out["every"] = every
    out["params"] = clean_params(playbook, raw.get("params"))
    try:
        out["notify"] = notify.clean(raw.get("notify"), groups)
    except notify.InvalidNotify as exc:
        raise InvalidSchedule(str(exc)) from None
    out["enabled"] = raw.get("enabled", True) is not False
    return out


def _view(row, now=None) -> dict:
    out = dict(row)
    out["describe"] = describe(out)
    out["params"] = json.loads(out.get("params") or "{}")
    out["notify"] = {**notify.DEFAULTS, **json.loads(out.get("notify") or "{}")}
    out["notify_state"] = json.loads(out.get("notify_state") or "{}")
    out["enabled"] = bool(out["enabled"])
    out["weekdays"] = [int(d) for d in str(out.get("weekdays") or "").split(",") if d]
    return out


def get(schedule_id) -> dict | None:
    with graph.lock:
        row = graph.db.execute("SELECT * FROM sop_schedules WHERE id = ?", (schedule_id,)).fetchone()
    return _view(row) if row else None


def listing(playbook_id=None, enabled_only=False) -> list:
    where, args = [], []
    if playbook_id:
        where.append("playbook_id = ?")
        args.append(playbook_id)
    if enabled_only:
        where.append("enabled = 1")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with graph.lock:
        rows = graph.db.execute(f"SELECT * FROM sop_schedules{clause} ORDER BY created_at", args).fetchall()
    return [_view(row) for row in rows]


def _anchor(now):
    """每隔 N 分钟的起点：北京时间今天 0 点。"""
    local = now.astimezone(CHINA)
    return datetime.combine(local.date(), time(0, 0), tzinfo=CHINA)


def create(raw, groups, now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    playbook = playbooks.get(str(raw.get("playbook_id") or ""))
    data = validate(raw, playbook, groups)
    with graph.lock:
        total = graph.db.execute("SELECT COUNT(*) FROM sop_schedules").fetchone()[0]
        mine = graph.db.execute("SELECT COUNT(*) FROM sop_schedules WHERE playbook_id = ?",
                                (playbook["id"],)).fetchone()[0]
        if total >= MAX_SCHEDULES:
            raise InvalidSchedule(f"计划最多 {MAX_SCHEDULES} 条，先删掉不用的")
        if mine >= MAX_PER_SOP:
            raise InvalidSchedule(f"一个 SOP 最多 {MAX_PER_SOP} 条计划")
        schedule_id = uuid.uuid4().hex
        stamp = _iso(now)
        graph.db.execute(
            "INSERT INTO sop_schedules (id, playbook_id, kind, at, weekdays, every, anchor, params, notify, enabled,"
            " last_slot, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (schedule_id, playbook["id"], data["kind"], data["at"], data["weekdays"], data["every"], _iso(_anchor(now)),
             json.dumps(data["params"], ensure_ascii=False), json.dumps(data["notify"], ensure_ascii=False),
             1 if data["enabled"] else 0, stamp, stamp, stamp))
        graph.db.commit()
    log.info("schedule %s created for SOP %s: %s", schedule_id, playbook["id"], describe(data))
    return get(schedule_id)


def update(schedule_id, raw, groups, now=None) -> dict:
    """整体改一条计划。改了时间、或者从暂停恢复的，从现在起算：之前的时刻不算错过。"""
    now = now or datetime.now(timezone.utc)
    current = get(schedule_id)
    if current is None:
        raise LookupError(schedule_id)
    playbook = playbooks.get(current["playbook_id"])
    data = validate({**raw, "playbook_id": current["playbook_id"]}, playbook, groups)
    stamp = _iso(now)
    with graph.lock:
        graph.db.execute(
            "UPDATE sop_schedules SET kind = ?, at = ?, weekdays = ?, every = ?, anchor = ?, params = ?, notify = ?,"
            " enabled = ?, last_slot = ?, updated_at = ? WHERE id = ?",
            (data["kind"], data["at"], data["weekdays"], data["every"], _iso(_anchor(now)),
             json.dumps(data["params"], ensure_ascii=False), json.dumps(data["notify"], ensure_ascii=False),
             1 if data["enabled"] else 0, stamp, stamp, schedule_id))
        graph.db.commit()
    return get(schedule_id)


def set_enabled(schedule_id, enabled, now=None) -> dict | None:
    """暂停 / 恢复。恢复时从现在起算：暂停期间到点的不算错过。"""
    stamp = _iso(now or datetime.now(timezone.utc))
    with graph.lock:
        graph.db.execute("UPDATE sop_schedules SET enabled = ?, updated_at = ?, last_slot = CASE WHEN ? THEN ?"
                         " ELSE last_slot END WHERE id = ?",
                         (1 if enabled else 0, stamp, 1 if enabled else 0, stamp, schedule_id))
        graph.db.commit()
    return get(schedule_id)


def delete(schedule_id) -> bool:
    with graph.lock:
        cur = graph.db.execute("DELETE FROM sop_schedules WHERE id = ?", (schedule_id,))
        graph.db.execute("DELETE FROM sop_slots WHERE schedule_id = ?", (schedule_id,))
        graph.db.commit()
    return cur.rowcount > 0


def set_notify_state(schedule_id, state):
    with graph.lock:
        graph.db.execute("UPDATE sop_schedules SET notify_state = ? WHERE id = ?",
                         (json.dumps(state, ensure_ascii=False), schedule_id))
        graph.db.commit()


def claim(schedule_id, slot, status, run_id=None) -> bool:
    """占一个计划时刻：占到了返回 True。主键冲突（别的进程占了）返回 False。"""
    with graph.lock:
        cur = graph.db.execute("INSERT OR IGNORE INTO sop_slots (schedule_id, slot, status, run_id, claimed_at)"
                               " VALUES (?, ?, ?, ?, ?)", (schedule_id, _iso(slot), status, run_id, graph.now_iso()))
        graph.db.commit()
    return cur.rowcount == 1


def _settle(schedule_id, slot, status, run_id):
    with graph.lock:
        graph.db.execute("UPDATE sop_slots SET status = ?, run_id = ? WHERE schedule_id = ? AND slot = ?",
                         (status, run_id, schedule_id, _iso(slot)))
        graph.db.commit()


def _advance(schedule_id, slot):
    stamp = _iso(slot)
    with graph.lock:
        graph.db.execute("UPDATE sop_schedules SET last_slot = ? WHERE id = ? AND (last_slot IS NULL OR last_slot < ?)",
                         (stamp, schedule_id, stamp))
        graph.db.commit()


def last_runs(schedule_ids) -> dict:
    """计划 id -> 最近一次的执行记录（含错过、跳过）。"""
    ids = list(schedule_ids)
    if not ids:
        return {}
    with graph.lock:
        rows = graph.db.execute(
            f"SELECT {runs.LIST_FIELDS} FROM sop_runs r WHERE trigger = 'schedule' AND source_id IN"
            f" ({','.join('?' * len(ids))}) AND started_at = (SELECT MAX(started_at) FROM sop_runs x"
            " WHERE x.trigger = 'schedule' AND x.source_id = r.source_id)", ids).fetchall()
    return {row["source_id"]: runs._brief(row) for row in rows}


def overview(playbook_id=None, now=None) -> list:
    """页面上的计划列表：下次执行时间、上次的结果；SOP 停用、删了的写明。"""
    now = now or datetime.now(timezone.utc)
    items = listing(playbook_id)
    last = last_runs(item["id"] for item in items)
    names = {}
    for item in items:
        book = names.get(item["playbook_id"]) or playbooks.get(item["playbook_id"])
        names[item["playbook_id"]] = book
        state = "" if book and book["enabled"] else "SOP 已删除" if book is None else "SOP 已停用，计划不执行"
        after = max(now, _utc(item.get("last_slot")) or now)
        upcoming = next_slot(item, after) if item["enabled"] and not state else None
        item.update(playbook_name=book["name"] if book else "", blocked=state, last=last.get(item["id"]),
                    next_at=_iso(upcoming) if upcoming else None)
        item.pop("notify_state", None)
    return items


# --- 到点执行 -------------------------------------------------------------------------

def tick(now=None, enqueue=None) -> list:
    """看一遍启用的计划：到点的占时刻、交给 autorun 执行；迟到太久的记「错过」。返回做了什么（测试、日志用）。"""
    from app import autorun
    enqueue = enqueue or autorun.enqueue
    now = now or datetime.now(timezone.utc)
    done = []
    for schedule in listing(enabled_only=True):
        after = _utc(schedule.get("last_slot")) or _utc(schedule["created_at"]) or now
        due = list(slots(schedule, after, now))
        if not due:
            continue
        latest = due[-1]
        book = playbooks.get(schedule["playbook_id"])
        if book is None or not book["enabled"]:
            _advance(schedule["id"], latest)
            done.append((schedule["id"], "blocked", None))
            continue
        on_time = latest if now - latest <= GRACE else None
        missed = [slot for slot in due if slot != on_time]
        if missed and claim(schedule["id"], missed[-1], "missed"):
            span = _local(missed[0]) + (f" 到 {_local(missed[-1])}" if len(missed) > 1 else "")
            reason = (f"错过了 {len(missed)} 次（{span}，北京时间）：那时应用没在运行（部署、重启或宕机）。"
                      "错过的不补跑，下一次照常按时执行")
            run_id = runs.record_skip(book, "schedule", "missed", reason, source_id=schedule["id"],
                                      note=describe(schedule))
            _settle(schedule["id"], missed[-1], "missed", run_id)
            done.append((schedule["id"], "missed", run_id))
            log.warning("schedule %s (SOP %s): missed %d slot(s) %s", schedule["id"], book["name"], len(missed), span)
            try:
                autorun.notify_after(runs.get(run_id))
            except Exception:
                log.warning("schedule %s: notifying the missed run failed", schedule["id"], exc_info=True)
        if on_time and claim(schedule["id"], on_time, "run"):
            try:
                run_id = enqueue(book, "schedule", source_id=schedule["id"], note=describe(schedule),
                                 params=schedule["params"])
            except autorun.Busy as exc:
                run_id = runs.record_skip(book, "schedule", "skipped", f"跳过 {_local(on_time)} 这一次：{exc}",
                                          source_id=schedule["id"], note=describe(schedule))
                _settle(schedule["id"], on_time, "skipped", run_id)
                done.append((schedule["id"], "skipped", run_id))
                log.info("schedule %s skipped %s: %s", schedule["id"], _local(on_time), exc)
            else:
                _settle(schedule["id"], on_time, "run", run_id)
                done.append((schedule["id"], "run", run_id))
        _advance(schedule["id"], latest)
    return done


_stop = threading.Event()
_thread = None


def _loop():
    from app import autorun
    while not _stop.wait(TICK_SECONDS):
        try:
            autorun.maintain()
            tick()
        except Exception as exc:
            log.warning("scheduler tick failed: %s", why(exc), exc_info=True)


def start():
    """应用启动时（SCHEDULER 打开）起后台线程，每 TICK_SECONDS 秒看一次。"""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="scheduler", daemon=True)
    _thread.start()
    log.info("scheduler started (every %ds)", TICK_SECONDS)


def stop():
    _stop.set()
