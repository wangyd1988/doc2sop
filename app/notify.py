"""SOP 执行完以后发不发邮件、发什么（docs/自动执行.md「邮件」）。

计划和告警规则上各有一份设置：发给哪个收件组（只存名字）、什么时候发、同一个问题重复出现时怎么办。

    when    problems（默认）：只在有异常、没跑成、没法判断时发；always：每次都发
    repeat  同一个问题连续出现时：daily（默认）每天最多提醒一次，标「仍未恢复」；always 每次都发；never 恢复之前不重复发
    恢复    之前发过问题、这次正常了：发一封「已恢复」

「同一个问题」看的是哪几步、什么结论（runs.signature），数值变了不算新问题。上一封没发出去的，下一次照样会发。
邮件正文：结论、异常项、和上次比的变化、报告链接（页面地址在服务器上配置）；不附工具的原始返回。
HTML 里的动态内容一律转义，只有我们自己的报告链接是可点的——模型输出里的链接不做成链接。
"""
import html
from datetime import datetime, timedelta, timezone

from app import mailer, runs
from app.config import BOT_NAME, log

WHEN = ("problems", "always")
REPEAT = ("daily", "always", "never")
DEFAULTS = {"group": "", "when": "problems", "repeat": "daily"}
REMIND_HOURS = 24
KIND_TAGS = {"recovered": "已恢复"}


class InvalidNotify(ValueError):
    pass


def clean(raw, groups) -> dict:
    """页面上的设置 → 存进库的。收件组只能是服务器上配置好的名字之一；不发邮件就是空的组名。"""
    raw = raw if isinstance(raw, dict) else {}
    group = " ".join(str(raw.get("group") or "").split())
    if group and group not in groups:
        raise InvalidNotify(f"服务器上没有收件组「{group}」：收件组在服务器的配置文件里定，页面上只能选")
    when = raw.get("when") or DEFAULTS["when"]
    repeat = raw.get("repeat") or DEFAULTS["repeat"]
    if when not in WHEN:
        raise InvalidNotify("什么时候发邮件只能是 problems（有问题时）或 always（每次）")
    if repeat not in REPEAT:
        raise InvalidNotify("重复提醒只能是 daily、always 或 never")
    return {"group": group, "when": when, "repeat": repeat}


def _parse(iso):
    try:
        moment = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def decide(notify, state, run, now=None):
    """(要发的种类, 说明)。种类：problem 新问题 / still 仍未恢复 / recovered 已恢复 / normal 正常；不发时种类是 None。"""
    notify = {**DEFAULTS, **(notify or {})}
    state = state or {}
    if not notify["group"]:
        return None, "没有选收件组"
    signature = runs.signature(run)
    notified = state.get("notified", "")
    if signature == "":
        if notified:
            return "recovered", ""
        return ("normal", "") if notify["when"] == "always" else (None, "正常，按设置不发")
    if signature != notified:
        return "problem", ""
    if notify["when"] == "always" or notify["repeat"] == "always":
        return "still", ""
    if notify["repeat"] == "daily":
        sent = _parse(state.get("sent_at"))
        if sent is None or (now or datetime.now(timezone.utc)) - sent >= timedelta(hours=REMIND_HOURS):
            return "still", ""
        return None, f"同一个问题 {REMIND_HOURS} 小时内已经提醒过"
    return None, "同一个问题已经发过，恢复之前不重复发"


def _tag(run, kind):
    if kind in KIND_TAGS:
        return KIND_TAGS[kind]
    name = runs.LEVEL_NAMES.get(run["level"], run["level"])
    return f"仍未恢复·{name}" if kind == "still" else name


def report_url(site_url, run) -> str:
    return f"{site_url}/sop?tab=runs&item={run['id']}" if site_url else ""


def compose(run, kind, diff, site_url=""):
    """(标题, 纯文本, HTML)。"""
    when = runs.local_time(run["started_at"], seconds=False)
    subject = f"[{BOT_NAME}] 【{_tag(run, kind)}】SOP《{run['playbook_name']}》 {when[5:]}"
    report = run.get("report") or {}
    items = report.get("findings") or []
    trigger = runs.TRIGGER_NAMES.get(run["trigger"], run["trigger"]) + (f"（{run['note']}）" if run.get("note") else "")
    head = [f"SOP《{run['playbook_name']}》{trigger}",
            f"结论：{runs.LEVEL_ICONS.get(run['level'], '')} {run['level_name']}"
            + (f"（{run['summary']}）" if run.get("summary") else ""),
            f"时间：{runs.local_time(run['started_at'])} — {runs.local_time(run.get('finished_at')) or '—'}（北京时间）"]
    if run.get("params"):
        head.append("参数：" + "，".join(f"{k}={v}" for k, v in run["params"].items()))
    if kind == "recovered":
        head.append("之前报过的问题这次都正常了。")
    elif kind == "still":
        head.append("和之前报过的是同一个问题，还没有恢复。")
    sections = []
    if items:
        sections.append(("异常项", [f"{runs.MARK_ICONS[i['mark']]} {i['step']}：{i['value'] or '—'}"
                                    + (f"（{i['note']}）" if i["note"] else "") for i in items]))
    if diff:
        lines = [diff["note"]] if diff.get("note") else []
        lines += [f"新出现：{i['step']}：{i['value'] or '—'}" for i in diff["new"]]
        lines += [f"仍未恢复：{i['step']}：{i['value'] or '—'}" for i in diff["still"]]
        lines += [f"已恢复：{i['step']}：{i['value'] or '—'}" for i in diff["recovered"]]
        lines += [f"数值变化：{i['step']}：{'；'.join(i['deltas'])}" for i in diff["changed"] if i["deltas"]]
        if not lines:
            lines = ["和上一次一样"]
        sections.append((f"和上次比（{runs.local_time(diff['previous']['started_at'], seconds=False)}）", lines))
    if report.get("followups"):
        sections.append(("需要跟进", report["followups"]))
    url = report_url(site_url, run)
    foot = (f"查看完整报告：{url}" if url else "（服务器上没有配置 site_url，邮件里没有报告链接；到 SOP 页的「执行记录」里看。）")
    note = f"这封邮件由 {BOT_NAME} 自动发送。工具的原始返回只在页面上看，不随邮件发出。"

    text = "\n".join(head) + "\n"
    for title, lines in sections:
        text += f"\n{title}：\n" + "\n".join(f"- {line}" for line in lines) + "\n"
    text += f"\n{foot}\n\n{note}\n"

    e = html.escape
    color = {"ok": "#047857", "anomaly": "#b45309", "failed": "#dc2626", "unknown": "#6b7280"}.get(run["level"], "#374151")
    if kind == "recovered":
        color = "#047857"
    body = [f'<div style="font:14px/1.6 -apple-system,Segoe UI,Microsoft YaHei,sans-serif;color:#1f2937;max-width:680px">',
            f'<div style="font-size:16px;font-weight:600;color:{color};margin-bottom:6px">{e(_tag(run, kind))}：'
            f'SOP《{e(run["playbook_name"])}》</div>']
    body += [f'<div>{e(line)}</div>' for line in head]
    for title, lines in sections:
        body.append(f'<h3 style="font-size:14px;margin:16px 0 6px">{e(title)}</h3><ul style="margin:0;padding-left:20px">')
        body += [f"<li>{e(line)}</li>" for line in lines]
        body.append("</ul>")
    if url:
        body.append(f'<p style="margin-top:16px"><a href="{e(url, quote=True)}">查看完整报告</a></p>')
    else:
        body.append(f'<p style="margin-top:16px;color:#6b7280">{e(foot)}</p>')
    body.append(f'<p style="color:#6b7280;font-size:12px">{e(note)}</p></div>')
    return subject, text, "\n".join(body)


def after_run(run, notify, state, save_state, settings=None, send=None, now=None) -> dict:
    """一次执行结束后：按设置决定发不发，发了把结果记进执行记录（mail），更新这份设置的状态（save_state）。"""
    from app import automation_config
    send = send or mailer.send
    now = now or datetime.now(timezone.utc)
    state = dict(state or {})
    kind, why = decide(notify, state, run, now)
    signature = runs.signature(run)
    mail = {"kind": kind, "group": (notify or {}).get("group", "")}
    if kind is None:
        mail.update(status="skipped", reason=why)
    else:
        settings = settings or automation_config.load()
        diff = runs.compare(run, runs.previous(run)) if run.get("execution_id") else None
        subject, text, body = compose(run, kind, diff, settings.site_url)
        try:
            result = send(notify["group"], subject, text, body, settings=settings)
        except mailer.MailError as exc:
            mail.update(status="failed", error=str(exc), attempts=exc.attempts)
            log.warning("run %s: mail to %s not sent: %s", run["id"], notify["group"], exc)
        else:
            mail.update(status="sent", attempts=result["attempts"], recipients=result["recipients"], subject=subject)
            if kind == "recovered":
                state["notified"] = ""
            elif kind in ("problem", "still"):
                state["notified"] = signature
            state["sent_at"] = now.isoformat(timespec="seconds")
    state["last"] = signature
    mail["at"] = now.isoformat(timespec="seconds")
    runs.set_mail(run["id"], mail)
    save_state(state)
    return mail
