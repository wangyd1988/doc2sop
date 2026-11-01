"""SOP 执行记录（docs/自动执行.md「执行记录」）。

每次按 SOP 执行都留一份：对话里的「▶ 执行」、SOP 页的「立即执行一次」、定时执行、告警触发。记录建在图谱上——
执行过的就是一条 executions（同一个 id），每一步调了什么工具、什么参数、完整返回都在 tool_calls 里。这里多存的是：

    谁触发的（页面 / 定时 / 告警）、用了什么参数、开始和结束时间、SOP 当时的步骤（之后改了 SOP，记录里仍是执行时的样子）
    结构化的结论：等级（正常 / 有异常 / 没跑成 / 没法判断）和异常项（哪一步、查看什么、看到的值、结论）

结论从回答里按 SOP 输出格式（sop_tools.SOP_FORMAT）的逐步表格解析，不改提示词：结论只能是 ✅ ⚠️ ❌ ❓。
解析不出来的一律记「没法判断」，不能当成正常；表格说正常、可那一步的工具根本没调成功，也是「没法判断」——没有依据。
"""
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from app import graph, playbooks
from app.agent import registry

TRIGGERS = ("web", "schedule", "alert")
TRIGGER_NAMES = {"web": "页面", "schedule": "定时", "alert": "告警"}
LEVELS = ("ok", "anomaly", "failed", "unknown")
LEVEL_NAMES = {"ok": "正常", "anomaly": "有异常", "failed": "没跑成", "unknown": "没法判断"}
LEVEL_ICONS = {"ok": "✅", "anomaly": "⚠️", "failed": "❌", "unknown": "❓"}
STATUS_NAMES = {"queued": "排队中", "running": "执行中", "done": "完成", "missed": "错过", "skipped": "跳过"}
MARK_ICONS = {"ok": "✅", "warn": "⚠️", "bad": "❌", "unknown": "❓"}
PROBLEM_MARKS = ("warn", "bad")
CHINA = timezone(timedelta(hours=8))
OUTPUT_MAX = 20000          # 详情里每次调用的返回最多给页面多少字（完整的在图谱里）
EXPORT_OUTPUT_MAX = 4000    # 导出的 Markdown 里每次调用的返回最多多少字
FOLLOWUPS_MAX = 20
CELL_MAX = 500
# 这个进程的标识：部署切换时新旧两份可能同时在跑一小会儿，执行记录上记着是谁在跑（interrupt_stale 用）
OWNER = uuid.uuid4().hex[:12]


# --- 解析 SOP 输出格式的逐步表格 ---------------------------------------------------------

_MARKS = (("✅", "ok"), ("⚠", "warn"), ("❌", "bad"), ("❓", "unknown"))
_SEPARATOR = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")
_STEP_NO = re.compile(r"^\D{0,3}?(\d{1,2})(?!\d)")
_EMPHASIS = re.compile(r"\*\*|__|`|~~")
_BREAK = re.compile(r"<br\s*/?>", re.IGNORECASE)
_NONE = re.compile(r"^[（(]?(无|暂无|没有|无需跟进|不需要|全部正常)[）)]?[。.！!]?$")
_LIST_ITEM = re.compile(r"^(?:[-*•·]|\d{1,2}[.、)）])\s*(.+)$")
COLUMN_KEYS = {"verdict": ("结论", "判断"), "step": ("步骤", "序号", "#"), "check": ("查看", "检查"),
               "value": ("实际数据", "实际", "数据")}


def _plain(text) -> str:
    """表格单元格 → 纯文字：去掉加粗、行内代码的标记，<br> 换成空格，压掉多余空白。"""
    text = _BREAK.sub(" ", str(text or ""))
    return " ".join(_EMPHASIS.sub("", text).split())[:CELL_MAX]


def _cells(line) -> list:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    return [part.replace("\\|", "|").strip() for part in re.split(r"(?<!\\)\|", text)]


def _tables(answer):
    """回答里的 Markdown 表格：[(表头, [行…])]。行一直取到空行或不含 | 的行为止。"""
    lines = str(answer or "").splitlines()
    i = 0
    while i < len(lines) - 1:
        if "|" in lines[i] and _SEPARATOR.match(lines[i + 1]) and "-" in lines[i + 1]:
            header, body, j = _cells(lines[i]), [], i + 2
            while j < len(lines) and lines[j].strip() and "|" in lines[j]:
                body.append(_cells(lines[j]))
                j += 1
            yield header, body
            i = j
        else:
            i += 1


def _columns(header):
    """表头 → 各列的位置。没有「结论」列的表不是 SOP 的汇报表格。"""
    names = [_plain(cell) for cell in header]

    def find(keys, taken=()):
        for key in keys:            # 先找写得一模一样的，再找包含的
            for index, name in enumerate(names):
                if index not in taken and name == key:
                    return index
        for key in keys:
            for index, name in enumerate(names):
                if index not in taken and key in name:
                    return index
        return None

    verdict = find(COLUMN_KEYS["verdict"])
    if verdict is None:
        return None
    step = find(COLUMN_KEYS["step"], {verdict})
    check = find(COLUMN_KEYS["check"], {verdict, step})
    value = find(COLUMN_KEYS["value"], {verdict, step, check})
    if check is None and value is None:
        return None
    return {"verdict": verdict, "step": step, "check": check, "value": value}


def _mark(text):
    """结论单元格 → (mark, 说明)。只认 ✅ ⚠️ ❌ ❓：没有这几个符号的算「无法判断」，不按文字猜（「不正常」里也有「正常」）。"""
    found = [(text.find(symbol), symbol, mark) for symbol, mark in _MARKS if symbol in text]
    if not found:
        return "unknown", text, False
    _, symbol, mark = min(found)
    note = text.replace(symbol, "", 1).replace("\ufe0f", "").strip(" ：:，,-—")
    return mark, note, True


def parse(answer) -> dict:
    """按 SOP 输出格式解析回答：逐步表格（rows）、需要跟进（followups）。只认带「结论」列的表格。"""
    rows = []
    for header, body in _tables(answer):
        columns = _columns(header)
        if columns is None:
            continue
        for cells in body:
            if not any(cell.strip() for cell in cells):
                continue

            def cell(key):
                index = columns[key]
                return _plain(cells[index]) if index is not None and index < len(cells) else ""

            verdict = cell("verdict")
            mark, note, marked = _mark(verdict)
            step = cell("step")
            found = _STEP_NO.match(step)
            rows.append({"step": step, "n": int(found.group(1)) if found else None, "check": cell("check"),
                         "value": cell("value"), "mark": mark, "note": note, "verdict": verdict, "marked": marked})
    return {"rows": rows, "followups": followups(answer)}


def followups(answer) -> list:
    """「需要跟进」一段里的条目；写「无」的是空列表。"""
    lines = str(answer or "").splitlines()
    for index, line in enumerate(lines):
        if "需要跟进" not in line or "|" in line:
            continue
        items = []
        rest = _plain(line.split("需要跟进", 1)[1]).strip(" ：:#*")
        if rest:
            items.append(rest)
        for following in lines[index + 1:]:
            text = following.strip()
            if not text:
                if items:
                    break
                continue
            if text.startswith(("#", "|")):
                break
            item = _LIST_ITEM.match(text)
            if item:
                items.append(_plain(item.group(1)))
            elif items:
                break
            else:
                items.append(_plain(text))
        return [item[:300] for item in items if item and not _NONE.match(item)][:FOLLOWUPS_MAX]
    return []


def row_label(row) -> str:
    step = f"第 {row['n']} 步" if row.get("n") else (row.get("step") or "")
    return " ".join(part for part in (step, row.get("check") or "") if part) or "（没写是哪一步）"


def _numbers(steps_count, rows):
    covered = {row["n"] for row in rows if row.get("n")}
    if covered:
        return [n for n in range(1, steps_count + 1) if n not in covered]
    return list(range(len(rows) + 1, steps_count + 1))


def judge(parsed, steps, calls, answer, failure=None):
    """(等级, 说明)。steps：执行时 SOP 的步骤；calls：本轮的数据类调用 [(工具, 成没成)]。

    没跑成：出错、没有回答、数据工具一个都没调成功、每一步都写着「未执行」。
    有异常：表格里有 ⚠️ 或 ❌（哪怕别的步骤没做完，异常也要先报出来）。
    没法判断：没有表格、有 ❓ 或没标符号的行、有的步骤不在表格里、表格说正常可那一步的工具没调成功过。
    """
    if failure:
        return "failed", str(failure)[:300]
    if not str(answer or "").strip():
        return "failed", "没有得到回答"
    if calls and not any(ok for _, ok in calls):
        return "failed", "数据工具都没有调用成功"
    rows = parsed["rows"]
    if not rows:
        return "unknown", "回答里没有 SOP 输出格式要求的逐步表格（步骤 | 查看 | 实际数据 | 结论），没法判断"
    if all(row["mark"] == "unknown" and row["value"].startswith("未执行") for row in rows):
        return "failed", "每一步都没有执行"
    if any(row["mark"] in PROBLEM_MARKS for row in rows):
        return "anomaly", ""
    unclear = [row for row in rows if row["mark"] == "unknown"]
    if unclear:
        unmarked = [row for row in unclear if not row.get("marked")]
        what = "没有用 ✅ ⚠️ ❌ ❓ 标出结论" if unmarked and len(unmarked) == len(unclear) else "无法判断"
        return "unknown", f"{len(unclear)} 项{what}：" + "、".join(row_label(row) for row in unclear[:3])
    missing = _numbers(len(steps), rows)
    if missing:
        return "unknown", f"第 {'、'.join(map(str, missing[:6]))} 步没有出现在表格里"
    succeeded = {tool for tool, ok in calls if ok}
    uncalled = [n for n, step in enumerate(steps, 1) if step.get("tool") not in succeeded]
    if uncalled:
        return "unknown", f"第 {'、'.join(map(str, uncalled[:6]))} 步的工具没有调用成功过，表格里的结论没有依据"
    return "ok", ""


def findings(rows) -> list:
    """异常项：结论是 ⚠️ 或 ❌ 的行。"""
    return [{"step": row_label(row), "n": row.get("n"), "check": row.get("check", ""), "value": row.get("value", ""),
             "mark": row["mark"], "note": row.get("note", "")} for row in rows if row["mark"] in PROBLEM_MARKS]


def summarize(level, reason, rows, steps) -> str:
    if level == "ok":
        return f"{len(steps) or len(rows)} 步都正常"
    if level == "anomaly":
        items = findings(rows)
        head = "；".join(f"{item['check'] or item['step']}（{item['value']}）" if item["value"] else
                        (item["check"] or item["step"]) for item in items[:2])
        return f"{len(items)} 项异常：{head}" + ("……" if len(items) > 2 else "")
    return reason or LEVEL_NAMES[level]


# --- 和上一次比 ---------------------------------------------------------------------

_NUM = re.compile(r"(-?\d+(?:\.\d+)?)\s*(%|[KMGTP]i?B?|ms|s|秒|分钟|小时|天|次|个|核)?")


def _key(row) -> str:
    return re.sub(r"\s+", "", str(row.get("check") or "")).lower()


def _match(current, previous):
    """这次的每一行对上上次的哪一行：先看步骤号 + 查看什么，再看只有一行的同一步骤号。"""
    used, pairs = set(), []
    for row in current:
        hit = next((i for i, old in enumerate(previous)
                    if i not in used and old.get("n") == row.get("n") and _key(old) == _key(row)), None)
        if hit is None and row.get("n"):
            same = [i for i, old in enumerate(previous) if old.get("n") == row["n"]]
            mine = [r for r in current if r.get("n") == row["n"]]
            if len(same) == 1 and len(mine) == 1 and same[0] not in used:
                hit = same[0]
        if hit is None and not row.get("n"):
            hit = next((i for i, old in enumerate(previous) if i not in used and _key(old) == _key(row) and _key(row)),
                       None)
        if hit is not None:
            used.add(hit)
        pairs.append((row, previous[hit] if hit is not None else None))
    left = [old for i, old in enumerate(previous) if i not in used]
    return pairs, left


def _fmt(number) -> str:
    return f"{number:+.2f}".rstrip("0").rstrip(".") if number != int(number) else f"{int(number):+d}"


def deltas(before, after) -> list:
    """两次「实际数据」里的数字一一对得上（个数、单位都一样）时，算出每个数的变化：["85% → 91%（+6）", …]。"""
    old, new = _NUM.findall(before or ""), _NUM.findall(after or "")
    if not old or len(old) != len(new) or len(new) > 4 or [u for _, u in old] != [u for _, u in new]:
        return []
    out = []
    for (a, unit), (b, _) in zip(old, new):
        if a != b:
            out.append(f"{a}{unit} → {b}{unit}（{_fmt(float(b) - float(a))}）")
    return out


def compare(run, previous) -> dict | None:
    """这次和上一次（同一个 SOP、同样的参数）比：新出现的异常、已经恢复的、仍未恢复的、数值的变化。"""
    if previous is None:
        return None
    out = {"previous": {key: previous.get(key) for key in ("id", "started_at", "level", "trigger", "summary")},
           "new": [], "recovered": [], "still": [], "changed": [], "gone": [], "note": ""}
    now_rows, old_rows = (run.get("report") or {}).get("rows") or [], (previous.get("report") or {}).get("rows") or []
    if not now_rows or not old_rows:
        out["note"] = ("上一次" if not old_rows else "这一次") + "没有逐步的结论（没跑成或没法判断），没法逐项比较"
        return out
    pairs, left = _match(now_rows, old_rows)
    for row, old in pairs:
        bad_now = row["mark"] in PROBLEM_MARKS
        bad_then = old is not None and old["mark"] in PROBLEM_MARKS
        item = {"step": row_label(row), "check": row.get("check", ""), "value": row.get("value", ""),
                "mark": row["mark"], "before": old.get("value", "") if old else "",
                "before_mark": old["mark"] if old else None}
        if bad_now and not bad_then:
            out["new"].append(item)
        elif bad_now:
            out["still"].append(item)
        elif bad_then and row["mark"] == "ok":
            out["recovered"].append(item)
        if old is not None and old.get("value") != row.get("value"):
            out["changed"].append({**item, "deltas": deltas(old.get("value"), row.get("value"))})
    out["gone"] = [{"step": row_label(old), "check": old.get("check", ""), "value": old.get("value", ""),
                    "mark": old["mark"]} for old in left if old["mark"] in PROBLEM_MARKS]
    return out


def signature(run) -> str:
    """这次的问题是什么：正常是空串；同样的问题连续出现时签名不变（数值变了也不变），邮件据此判断「仍未恢复」。"""
    level = run.get("level")
    if level == "ok":
        return ""
    if level != "anomaly":
        return level or "unknown"
    rows = (run.get("report") or {}).get("rows") or []
    keys = sorted({f"{row.get('n') or ''}:{_key(row)}:{row['mark']}" for row in rows if row["mark"] in PROBLEM_MARKS})
    return "anomaly|" + "|".join(keys)


# --- 存取 -----------------------------------------------------------------------------

def _now():
    return graph.now_iso()


def _canonical(params) -> str:
    return json.dumps({str(k): v for k, v in (params or {}).items() if v not in (None, "")},
                      ensure_ascii=False, sort_keys=True)


def _steps_snapshot(playbook) -> list:
    return [{"tool": s["tool"], "args": s.get("args") or {}, "checkpoint": s.get("checkpoint", "")}
            for s in playbook.get("steps") or []]


def _row(row) -> dict:
    out = dict(row)
    for key, empty in (("params", {}), ("report", {}), ("mail", {})):
        try:
            out[key] = json.loads(out.get(key) or "null") or empty
        except ValueError:
            out[key] = empty
    out["trigger_name"] = TRIGGER_NAMES.get(out["trigger"], out["trigger"])
    out["level_name"] = LEVEL_NAMES.get(out["level"], out["level"])
    out["status_name"] = STATUS_NAMES.get(out["status"], out["status"])
    return out


def params_from_question(playbook, question) -> dict:
    """对话里「▶ 执行」的问题是「执行 SOP《名字》（参数：值，…）」，人在括号里补上留空的参数。认得出就当参数记下，
    比较「和上一次」时只和参数一样的比；认不出就把括号里的原话记下。"""
    found = re.search(r"《[^》]*》\s*[（(](.*)[）)]\s*$", str(question or "").strip())
    if not found:
        return {}
    blanks = {key for step in playbook.get("steps") or [] for key, value in (step.get("args") or {}).items()
              if value in ("", None)}
    out = {}
    for part in re.split(r"[，,；;]", found.group(1)):
        if not part.strip():
            continue
        pair = re.split(r"\s*[:：=]\s*", part.strip(), maxsplit=1)
        if len(pair) == 2 and pair[0] in blanks and pair[1]:
            out[pair[0]] = pair[1][:200]
        else:
            return {"补充": found.group(1).strip()[:200]}
    return out


def create(playbook, trigger, *, run_id=None, source_id="", note="", params=None, status="queued",
           conversation_id=None, execution_id=None, owner=None) -> str:
    if trigger not in TRIGGERS:
        raise ValueError(f"trigger 只能是 {'、'.join(TRIGGERS)} 之一")
    run_id = run_id or uuid.uuid4().hex
    report = {"steps": _steps_snapshot(playbook)}
    with graph.lock:
        graph.db.execute(
            "INSERT INTO sop_runs (id, execution_id, playbook_id, playbook_name, trigger, source_id, note, params,"
            " status, report, conversation_id, owner, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, execution_id, playbook["id"], playbook.get("name", ""), trigger, source_id or "", (note or "")[:300],
             _canonical(params), status, json.dumps(report, ensure_ascii=False), conversation_id, owner or OWNER,
             _now()))
        graph.db.commit()
    return run_id


def record_skip(playbook, trigger, status, reason, source_id="", note="") -> str:
    """错过、跳过的也留一条：没有执行，结论是「没跑成」。note 是触发说明（如「每天 09:00」），reason 写为什么没执行。"""
    run_id = create(playbook, trigger, source_id=source_id, note=note, status=status)
    with graph.lock:
        graph.db.execute("UPDATE sop_runs SET level = 'failed', summary = ?, finished_at = started_at WHERE id = ?",
                         (reason[:300], run_id))
        graph.db.commit()
    return run_id


def begin(run_id, execution_id=None):
    with graph.lock:
        graph.db.execute("UPDATE sop_runs SET status = 'running', started_at = ?, execution_id = COALESCE(?, execution_id),"
                         " owner = ? WHERE id = ?", (_now(), execution_id, OWNER, run_id))
        graph.db.commit()


def finish(run_id, answer, failure=None) -> dict | None:
    """执行结束：解析回答、判等级、写回。返回整条记录（带 previous 和 compare，发邮件要用）。"""
    run = get(run_id)
    if run is None:
        return None
    steps = (run.get("report") or {}).get("steps") or []
    calls = []
    if run.get("execution_id"):
        execution = graph.execution(run["execution_id"]) or {}
        calls = [(c["tool"], bool(c["ok"])) for c in execution.get("tool_calls") or []
                 if registry.observes_system(c["tool"])]
    parsed = parse(answer)
    level, reason = judge(parsed, steps, calls, answer, failure)
    report = {"steps": steps, "rows": parsed["rows"], "findings": findings(parsed["rows"]),
              "followups": parsed["followups"], "reason": reason,
              "calls": {"total": len(calls), "ok": sum(1 for _, ok in calls if ok)}}
    with graph.lock:
        graph.db.execute("UPDATE sop_runs SET status = 'done', level = ?, summary = ?, report = ?, answer = ?, error = ?,"
                         " finished_at = ? WHERE id = ?",
                         (level, summarize(level, reason, parsed["rows"], steps),
                          json.dumps(report, ensure_ascii=False), str(answer or ""), str(failure or "")[:500],
                          _now(), run_id))
        graph.db.commit()
    return get(run_id)


def set_mail(run_id, mail: dict):
    with graph.lock:
        graph.db.execute("UPDATE sop_runs SET mail = ? WHERE id = ?", (json.dumps(mail, ensure_ascii=False), run_id))
        graph.db.commit()


def get(run_id) -> dict | None:
    with graph.lock:
        row = graph.db.execute("SELECT * FROM sop_runs WHERE id = ?", (run_id,)).fetchone()
    return _row(row) if row else None


LIST_FIELDS = ("id, execution_id, playbook_id, playbook_name, trigger, source_id, note, params, status, level, summary,"
               " mail, conversation_id, started_at, finished_at")


def _brief(row) -> dict:
    out = _row({**dict(row), "report": "{}"})
    out.pop("report", None)
    return out


def listing(playbook_id=None, trigger=None, level=None, offset=0, limit=30):
    where, args = [], []
    if playbook_id:
        where.append("playbook_id = ?")
        args.append(playbook_id)
    if trigger:
        where.append("trigger = ?")
        args.append(trigger)
    if level:
        where.append("level = ? AND status = 'done'")
        args.append(level)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    with graph.lock:
        total = graph.db.execute(f"SELECT COUNT(*) FROM sop_runs{clause}", args).fetchone()[0]
        rows = graph.db.execute(f"SELECT {LIST_FIELDS} FROM sop_runs{clause} ORDER BY started_at DESC, rowid DESC"
                                " LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
    return [_brief(row) for row in rows], total


def recent_auto(limit=6) -> list:
    """不在对话里的执行（定时、告警、SOP 页的「立即执行一次」）：工作台「最近」里和对话排在一起。"""
    with graph.lock:
        rows = graph.db.execute(f"SELECT {LIST_FIELDS} FROM sop_runs WHERE conversation_id IS NULL"
                                " ORDER BY started_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
    return [_brief(row) for row in rows]


def summary_by_playbook() -> dict:
    """SOP 列表上的小结：每个 SOP 的执行次数和最近一次（不算错过、跳过）。"""
    with graph.lock:
        counts = graph.db.execute("SELECT playbook_id, COUNT(*) FROM sop_runs GROUP BY playbook_id").fetchall()
        latest = graph.db.execute(
            f"SELECT {LIST_FIELDS} FROM sop_runs r WHERE status IN ('queued', 'running', 'done') AND started_at = ("
            " SELECT MAX(started_at) FROM sop_runs x WHERE x.playbook_id = r.playbook_id"
            " AND x.status IN ('queued', 'running', 'done'))").fetchall()
    out = {pid: {"runs": n, "last": None} for pid, n in counts}
    for row in latest:
        out.setdefault(row["playbook_id"], {"runs": 0, "last": None})["last"] = _brief(row)
    return out


def previous(run) -> dict | None:
    """同一个 SOP、同样参数的上一次完成的执行（错过、跳过的不算）。"""
    with graph.lock:
        row = graph.db.execute(
            "SELECT * FROM sop_runs WHERE playbook_id = ? AND params = ? AND status = 'done' AND id != ?"
            " AND execution_id IS NOT NULL AND (started_at < ? OR (started_at = ? AND rowid < ("
            "   SELECT rowid FROM sop_runs WHERE id = ?)))"
            " ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (run["playbook_id"], _canonical(run.get("params")), run["id"], run["started_at"], run["started_at"],
             run["id"])).fetchone()
    return _row(row) if row else None


def busy(playbook_id) -> bool:
    """这个 SOP 是不是还有一次没跑完（排队中或执行中，不管是谁触发的）。"""
    with graph.lock:
        row = graph.db.execute("SELECT 1 FROM sop_runs WHERE playbook_id = ? AND status IN ('queued', 'running')"
                               " LIMIT 1", (playbook_id,)).fetchone()
    return row is not None


def count_since(playbook_id, trigger, since_iso) -> int:
    with graph.lock:
        return graph.db.execute("SELECT COUNT(*) FROM sop_runs WHERE playbook_id = ? AND trigger = ? AND started_at >= ?"
                                " AND status IN ('queued', 'running', 'done')",
                                (playbook_id, trigger, since_iso)).fetchone()[0]


def interrupt_stale(stale_minutes=30, foreign_minutes=10, now=None, owner=None) -> int:
    """没跑完就没了下文的执行记成「没跑成：执行中断」：超过 stale_minutes 的一律算；别的进程（部署切换前的那一份）
    留下的，超过 foreign_minutes 就算——那个进程已经停了，它排队和正在跑的都不会再有结果。"""
    owner = owner or OWNER
    now = now or datetime.now(timezone.utc)
    stale = (now - timedelta(minutes=stale_minutes)).isoformat(timespec="seconds")
    foreign = (now - timedelta(minutes=foreign_minutes)).isoformat(timespec="seconds")
    note = "执行中断：应用重启或执行超时，没有结果"
    with graph.lock:
        cur = graph.db.execute(
            "UPDATE sop_runs SET status = 'done', level = 'failed', summary = ?, error = ?, finished_at = ?"
            " WHERE status IN ('queued', 'running') AND (started_at < ? OR (owner != ? AND started_at < ?))",
            (note, note, _now(), stale, owner, foreign))
        graph.db.commit()
    return cur.rowcount


def interrupt_mine(owner=None) -> int:
    """应用停止时：这个进程排队和正在跑的执行都不会有结果了，马上记成中断。"""
    owner = owner or OWNER
    note = "执行中断：应用停止（部署或重启），没有结果"
    with graph.lock:
        cur = graph.db.execute("UPDATE sop_runs SET status = 'done', level = 'failed', summary = ?, error = ?,"
                               " finished_at = ? WHERE status IN ('queued', 'running') AND owner = ?",
                               (note, note, _now(), owner))
        graph.db.commit()
    return cur.rowcount


def delete(run_id) -> bool:
    """删一条执行记录：连同它的图谱执行、工具调用、反馈（这些调用播下的事实撤回）。对话里的消息不动。"""
    run = get(run_id)
    if run is None:
        return False
    with graph.lock:
        graph.db.execute("DELETE FROM sop_runs WHERE id = ?", (run_id,))
        graph.db.commit()
    if run.get("execution_id"):
        graph.delete_execution(run["execution_id"])
    return True


def prune(days, now=None) -> int:
    """自动执行（定时、告警、立即执行一次）的记录保留 days 天；对话里「▶ 执行」的跟着对话走，不在这里删。"""
    if not days or days <= 0:
        return 0
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).isoformat(timespec="seconds")
    with graph.lock:
        ids = [r[0] for r in graph.db.execute("SELECT id FROM sop_runs WHERE conversation_id IS NULL AND started_at < ?"
                                              " AND status NOT IN ('queued', 'running')", (cutoff,)).fetchall()]
    for run_id in ids:
        delete(run_id)
    return len(ids)


# --- 详情 -----------------------------------------------------------------------------

def _assign(steps, calls):
    """把这次的工具调用分到 SOP 的各步：按工具名、按先后，第 n 次调某个工具算用到这个工具的第 n 个步骤；对不上的放「其他调用」。"""
    by_tool = {}
    for n, step in enumerate(steps, 1):
        by_tool.setdefault(step["tool"], []).append(n)
    assigned = {n: [] for n in range(1, len(steps) + 1)}
    used = {}
    extra = []
    for call in calls:
        slots = by_tool.get(call["tool"])
        if not slots:
            extra.append(call)
            continue
        index = used.get(call["tool"], 0)
        assigned[slots[min(index, len(slots) - 1)]].append(call)
        used[call["tool"]] = index + 1
    return assigned, extra


def detail(run_id) -> dict | None:
    run = get(run_id)
    if run is None:
        return None
    calls, question, feedback = [], "", []
    if run.get("execution_id"):
        execution = graph.execution(run["execution_id"]) or {}
        question = execution.get("question", "")
        for call in execution.get("tool_calls") or []:
            output = call["output"] or ""
            calls.append({"seq": call["seq"], "tool": call["tool"], "args": call["args"], "ok": call["ok"],
                          "duration_ms": call["duration_ms"], "chars": len(output),
                          "category": registry.category_of(call["tool"]),
                          "output": output[:OUTPUT_MAX], "truncated": len(output) > OUTPUT_MAX})
        feedback = graph.feedback_of([run["execution_id"]]).get(run["execution_id"], [])
    report = run.get("report") or {}
    steps = report.get("steps") or []
    assigned, extra = _assign(steps, [c for c in calls if c["category"] == "data"])
    rows = report.get("rows") or []
    view = []
    for n, step in enumerate(steps, 1):
        view.append({"n": n, "tool": step["tool"], "args": step.get("args") or {}, "checkpoint": step.get("checkpoint", ""),
                     "rows": [row for row in rows if row.get("n") == n], "calls": assigned.get(n, [])})
    unplaced = [row for row in rows if not row.get("n") or row["n"] > len(steps)]
    prev = previous(run) if run["status"] == "done" else None
    book = playbooks.get(run["playbook_id"])
    return {**run, "question": question, "steps": view, "unplaced": unplaced,
            "other_calls": extra + [c for c in calls if c["category"] != "data"],
            "feedback": feedback, "compare": compare(run, prev),
            "playbook": {"id": run["playbook_id"], "name": book["name"] if book else run["playbook_name"],
                         "exists": book is not None, "enabled": bool(book and book["enabled"])}}


def local_time(iso, seconds=True) -> str:
    """UTC ISO → 北京时间（页面、邮件、导出里给人看的）。"""
    if not iso:
        return ""
    try:
        moment = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return str(iso)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(CHINA).strftime("%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M")


def _fence(text) -> str:
    """代码块的围栏要比内容里最长的一串反引号还长，工具返回里有 ``` 也不会把导出的 Markdown 截断。"""
    longest = max((len(m) for m in re.findall(r"`+", text or "")), default=0)
    return "`" * max(3, longest + 1)


def _md_cell(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def markdown(run_id) -> str | None:
    """单次执行报告导出成 Markdown：结论、逐步表格、异常项、和上次比、需要跟进、每一步的调用和返回（截断）、人工反馈。"""
    run = detail(run_id)
    if run is None:
        return None
    lines = [f"# SOP《{run['playbook_name']}》执行报告", "",
             f"- 结论：{LEVEL_ICONS.get(run['level'], '')} {run['level_name']}" + (f"（{run['summary']}）" if run["summary"] else ""),
             f"- 触发：{run['trigger_name']}" + (f"（{run['note']}）" if run["note"] else ""),
             f"- 开始：{local_time(run['started_at'])}（北京时间）",
             f"- 结束：{local_time(run['finished_at']) or '—'}"]
    if run["params"]:
        lines.append("- 参数：" + "，".join(f"{k}={v}" for k, v in run["params"].items()))
    if run["error"]:
        lines.append(f"- 出错：{run['error']}")
    report = run.get("report") or {}
    rows = report.get("rows") or []
    if rows:
        lines += ["", "## 逐步结论", "", "| 步骤 | 查看 | 实际数据 | 结论 |", "|---|---|---|---|"]
        lines += [f"| {_md_cell(r['step'])} | {_md_cell(r['check'])} | {_md_cell(r['value'])} | {_md_cell(r['verdict'])} |"
                  for r in rows]
    elif report.get("reason"):
        lines += ["", f"> {report['reason']}"]
    items = report.get("findings") or []
    if items:
        lines += ["", "## 异常项", ""]
        lines += [f"{i}. {MARK_ICONS[item['mark']]} {item['step']}：{item['value'] or '—'}"
                  + (f"（{item['note']}）" if item["note"] else "") for i, item in enumerate(items, 1)]
    diff = run.get("compare")
    if diff:
        lines += ["", f"## 和上一次比（{local_time(diff['previous']['started_at'], False)}，"
                      f"{LEVEL_NAMES.get(diff['previous']['level'], '')}）", ""]
        if diff["note"]:
            lines.append(diff["note"])
        for key, title in (("new", "新出现的异常"), ("still", "仍未恢复"), ("recovered", "已经恢复")):
            for item in diff[key]:
                lines.append(f"- {title}：{item['step']}：{item['value'] or '—'}")
        for item in diff["changed"]:
            lines.append(f"- 数值变化：{item['step']}：{item['before'] or '—'} → {item['value'] or '—'}"
                         + (f"（{'；'.join(item['deltas'])}）" if item["deltas"] else ""))
        if not any(diff[k] for k in ("new", "still", "recovered", "changed")) and not diff["note"]:
            lines.append("和上一次一样，没有变化。")
    if report.get("followups"):
        lines += ["", "## 需要跟进", ""] + [f"- {item}" for item in report["followups"]]
    lines += ["", "## 每一步", ""]
    for step in run["steps"]:
        lines.append(f"### 第 {step['n']} 步：{step['tool']}")
        if step["checkpoint"]:
            lines.append(f"检查点：{step['checkpoint']}")
        if not step["calls"]:
            lines.append("（这一步没有调用工具）")
        for call in step["calls"]:
            fence = _fence(call["output"])
            body = call["output"][:EXPORT_OUTPUT_MAX] + ("\n…（已截断）" if len(call["output"]) > EXPORT_OUTPUT_MAX else "")
            lines += [f"- 调用 `{call['tool']}`，参数 `{json.dumps(call['args'], ensure_ascii=False)}`，"
                      f"{'成功' if call['ok'] else '失败'}，{call['duration_ms']} ms", "", fence, body, fence]
        lines.append("")
    if run["feedback"]:
        lines += ["## 人工反馈", ""] + [f"- {FEEDBACK_NAMES.get(f['verdict'], f['verdict'])}"
                                       + (f"：{f['note']}" if f["note"] else "") + f"（{local_time(f['created_at'])}）"
                                       for f in run["feedback"]]
    if run["answer"]:
        lines += ["", "## 完整回答", "", run["answer"]]
    return "\n".join(lines).rstrip() + "\n"


FEEDBACK_NAMES = {"correct": "判断正确", "false_alarm": "误报", "wrong_threshold": "阈值不对", "missing_step": "漏了一步",
                  "unhelpful": "没答好"}
