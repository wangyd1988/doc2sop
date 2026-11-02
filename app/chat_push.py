"""云上协同的推送（docs/正式部署.md「云上协同」）：计划、告警规则的执行结果推到群里；每周的知识库缺口摘要。

推送只能按名字：名字 → 群 ID 或用户 ID 的对应只写在转接程序的 targets.yaml 里（root 才能改），页面上只能选名字。
每个计划、告警规则推到哪、什么时候推，存在 chat.db 的旁表 chat_notify 里：不动计划和规则自己的表，也不动邮件的设置。
推不推沿用邮件那一套规则（notify.decide：有问题时 / 每次；同一个问题每天提醒一次 / 每次 / 恢复前不重复），
状态和邮件各记各的：邮件没发出去不影响群推送的「已提醒」，反之亦然。转接程序那边每个目标每小时最多 20 条，
超出的攒着，合并成一条「另有 N 条」。

关着时（没配转接程序）after_run 直接返回，不碰 chat.db。这里的函数都不抛异常：推送失败不影响执行记录和邮件。
"""
from datetime import datetime, timedelta, timezone

from app import chat_bridge, chat_config, chat_format, chat_store, notify, runs
from app.chat_bridge import BridgeError
from app.config import log

CHINA = timezone(timedelta(hours=8))
SOURCE_KINDS = {"schedule": "schedule", "alert": "rule"}     # 执行记录的触发方式 → chat_notify 里的来源
DIGEST_GROUPS = 5


def site_url() -> str:
    """报告链接用的页面地址（邮件的配置里那个）；只有 https 的才会出现在聊天里（chat_format.report_ref）。"""
    try:
        from app import automation_config
        return automation_config.load().site_url
    except Exception:
        return ""


def after_run(run) -> dict | None:
    """一次自动执行结束后（autorun 发完邮件之后调）：按这条计划、规则的推送设置决定推不推、推什么。"""
    bridge = chat_bridge.current()
    if bridge is None or not run:
        return None
    try:
        return _after_run(bridge, run)
    except Exception:
        log.warning("run %s: chat push failed", run.get("id"), exc_info=True)
        return None


def _after_run(bridge, run):
    kind = SOURCE_KINDS.get(run.get("trigger"))
    if not kind or not run.get("source_id"):
        return None
    setting = chat_store.notify_get(kind, run["source_id"])
    if setting is None or not setting["target"]:
        return None
    now = datetime.now(timezone.utc)
    state = dict(setting["state"])
    rule = {"group": setting["target"], "when": setting["when"], "repeat": setting["repeat"]}
    decision, reason = notify.decide(rule, state, run, now)
    signature = runs.signature(run)
    result = {"kind": decision, "target": setting["target"]}
    if decision is None:
        result.update(status="skipped", reason=reason)
    else:
        diff = runs.compare(run, runs.previous(run)) if run.get("execution_id") else None
        text = chat_format.push_text(run, decision, diff, site_url())
        try:
            reply = bridge.push(setting["target"], text)
        except BridgeError as exc:
            result.update(status="failed", reason=str(exc))
            log.warning("run %s: chat push not sent: %s", run["id"], exc)
        else:
            # 被转接程序攒着的（这个目标这一小时已经 20 条）也算提醒过：之后会合并成「另有 N 条」发出去
            result["status"] = "held" if reply.get("held") else "sent"
            if decision == "recovered":
                state["notified"] = ""
            elif decision in ("problem", "still"):
                state["notified"] = signature
            state["sent_at"] = now.isoformat(timespec="seconds")
    state["last"] = signature
    chat_store.notify_state(kind, run["source_id"], state)
    chat_store.push_log("run", setting["target"], result["status"], result.get("reason", ""), run_id=run["id"])
    log.info("run %s: chat push (%s) → %s", run["id"], kind, result["status"])      # 目标名可能是人名，只记在推送记录里
    return result


def test_push(target) -> dict:
    """「发一条测试消息」：只能发给转接程序里配好的目标名字。失败抛 BridgeError。"""
    bridge = chat_bridge.current()
    if bridge is None:
        raise BridgeError("没有配转接程序", status=503, definite=True)
    try:
        reply = bridge.push(target, chat_format.test_push_text(target))
    except BridgeError as exc:
        chat_store.push_log("test", target, "failed", str(exc))
        raise
    chat_store.push_log("test", target, "held" if reply.get("held") else "sent")
    return reply


def target_kinds(bridge) -> dict:
    """推送目标的名字 → chat（群）/ user（个人）。转接程序连不上时是空的。"""
    try:
        kinds = bridge.status().get("target_kinds")
    except BridgeError:
        return {}
    return kinds if isinstance(kinds, dict) else {}


def maybe_digest(now=None) -> list:
    """每周的缺口摘要：到了 chat.yaml 里写的那一天、那个小时，每个目标每周发一次。聊天线程每轮顺带调。"""
    bridge = chat_bridge.current()
    if bridge is None:
        return []
    cfg = chat_config.load()
    if not cfg.digest:
        return []
    local = (now or datetime.now(timezone.utc)).astimezone(CHINA)
    done = []
    for item in cfg.digest:
        if local.isoweekday() != item.weekday or local.hour != item.hour:
            continue
        key = f"digest:{item.target}:{item.group}"
        week = local.strftime("%G-W%V")
        if chat_store.state_get(key) == week:
            continue
        chat_store.state_set(key, week)         # 先记下：发失败也不在这一小时里反复重试
        done.append(send_digest(bridge, cfg, item))
    return done


def send_digest(bridge, cfg, item) -> str:
    """缺口看板的前几组。全部缺口只能发给个人：看板汇总了网页、私聊、各个群的问题，直接发到群里会把别处的问题主题带过去；
    要发到群，chat.yaml 里写 group，只汇总这个群自己的问题。"""
    from app import gaps
    if not item.group and target_kinds(bridge).get(item.target) != "user":
        reason = "全部缺口只能发给个人；发到群要写 group，只汇总这个群自己的问题（或者转接程序连不上，认不出目标是个人）"
        chat_store.push_log("digest", item.target, "skipped", reason)
        log.warning("chat digest skipped: whole-board digest needs a personal target or a group scope")
        return "skipped"
    only = chat_store.conversations_of_chat(item.group) if item.group else None
    groups = gaps.board(embed=False, only=only)["groups"][:DIGEST_GROUPS]
    if not groups:
        chat_store.push_log("digest", item.target, "skipped", "这一周没有缺口")
        return "skipped"
    scope = cfg.groups.get(item.group)
    text = chat_format.digest_text(groups, scope.name if scope else "")
    try:
        reply = bridge.push(item.target, text)
    except BridgeError as exc:
        chat_store.push_log("digest", item.target, "failed", str(exc))
        log.warning("chat digest not sent: %s", exc)
        return "failed"
    status = "held" if reply.get("held") else "sent"
    chat_store.push_log("digest", item.target, status, f"{len(groups)} 组")
    log.info("chat digest → %s (%d groups)", status, len(groups))
    return status
