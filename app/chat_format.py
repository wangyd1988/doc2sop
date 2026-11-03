"""云上协同里的文字（docs/正式部署.md「云上协同」）：回答转成好读的纯文本、出处、截断、命令的回复、推送和缺口摘要。

只有纯函数，不连任何东西。先假设云上协同不渲染 Markdown：标题写成【标题】，SOP 的逐步表格一步一行，
别的表格一行一条「列｜列」，链接写成「文字（地址）」。chat.yaml 里 markdown: true 时回答原样发。
"""
import re
from urllib.parse import urlsplit

from app import runs
from app.agent import modes
from app.config import BOT_NAME

PLATFORM_NAMES = {"ccwork": "云上协同", "dingtalk": "钉钉"}


def platform_name(platform="ccwork") -> str:
    """面向用户的平台名。认不出（或没有）的按云上协同：它是先有的，那条路上的字一个都不变。"""
    return PLATFORM_NAMES.get(platform or "ccwork", PLATFORM_NAMES["ccwork"])


def chat_rules(platform="ccwork") -> str:
    """群聊、私聊的回答在系统提示词末尾多这一段（只在这个渠道加，网页的提示词不变）。"""
    return f"""

**这次回答会发到{platform_name(platform)}的群聊或私聊里**：先给结论，尽量 800 字以内；少用表格（按 SOP 执行时的逐步表格照旧）；
不要写「点击按钮」「在页面上打开」这类网页上的操作。"""


CHAT_RULES = chat_rules("ccwork")


def platform_mismatch(bridge_platform, config_platform) -> str:
    """转接程序和 chat.yaml 不是同一个平台时，页面、日志里的说明。"""
    if not config_platform:
        return "chat.yaml 的 platform 写错了：聊天和推送都停着"
    return (f"转接程序是{PLATFORM_NAMES.get(bridge_platform, bridge_platform)}的，"
            f"chat.yaml 是{PLATFORM_NAMES.get(config_platform, config_platform)}的"
            f"（platform: {config_platform}）：聊天和推送都停着。换平台时要一起改 chat.yaml，并重新选推送目标")

STATUS_SEARCH = "🔎 正在查知识库…"
STATUS_WEB = "🌐 正在搜索网页…"
STATUS_COMPUTE = "🧮 正在计算…"
MORE_HINT = "……回答较长，回「全文」看剩下的部分"
FEEDBACK_HINT = "结论不对可回：误报 / 阈值不对 / 漏了一步；对的回：结论对"
SOURCES_MAX = 8
QUOTE_MAX = 20

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_RULE = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
_IMAGE = re.compile(r"!\[([^\]\n]*)\]\([^)\s]+\)")
_LINK = re.compile(r"\[([^\]\n]+)\]\((https?://[^)\s]+)\)")
_EMPHASIS = re.compile(r"\*\*|__|~~|`")
_BULLET = re.compile(r"^(\s*)[-*+]\s+")
_QUOTE = re.compile(r"^\s{0,3}>\s?")
_BREAK = re.compile(r"<br\s*/?>", re.IGNORECASE)
_CITATION = re.compile(r"\[((?:W?\d{1,3})(?:\s*[,，、]\s*W?\d{1,3})*)\]")


def strip_mention(text, robot_name="") -> str:
    """去掉「@机器人」和首尾空白；中间的换行留着（贴进来的日志）。"""
    text = str(text or "").replace("\u2005", " ").replace("\u00a0", " ").replace("\r\n", "\n")
    if robot_name:
        text = re.sub(r"@" + re.escape(robot_name), " ", text)
    lines = [" ".join(line.split()) for line in text.split("\n")]
    return "\n".join(lines).strip()


def _cells_text(cells) -> str:
    return "｜".join(runs._plain(cell) for cell in cells)


def _sop_rows(columns, body) -> list:
    """SOP 的逐步表格 → 一步一行：「1. 根分区使用率：87% ⚠️（阈值 85%）」。"""
    def cell(cells, key):
        index = columns[key]
        return runs._plain(cells[index]) if index is not None and index < len(cells) else ""

    out = []
    for cells in body:
        if not any(c.strip() for c in cells):
            continue
        verdict = cell(cells, "verdict")
        mark, note, marked = runs._mark(verdict)
        step = cell(cells, "step")
        found = runs._STEP_NO.match(step)
        label = f"{found.group(1)}." if found else (f"{step}：" if step else "•")
        what, value = cell(cells, "check"), cell(cells, "value")
        line = f"{label} {what}：{value}" if what and value else f"{label} {what or value}"
        if marked:
            line += f" {runs.MARK_ICONS[mark]}" + (f"（{note}）" if note else "")
        elif verdict:
            line += f"（{verdict}）"
        out.append(line)
    return out


def _table(lines) -> list:
    header = runs._cells(lines[0])
    body = [runs._cells(line) for line in lines[2:]]
    columns = runs._columns(header)
    if columns is not None:
        return _sop_rows(columns, body)
    return [_cells_text(header)] + [_cells_text(cells) for cells in body if any(c.strip() for c in cells)]


def _inline(line) -> str:
    line = _BREAK.sub(" ", line)
    line = _IMAGE.sub(lambda m: f"（图片：{m.group(1)}）" if m.group(1) else "（图片）", line)
    line = _LINK.sub(lambda m: f"{m.group(1)}（{m.group(2)}）", line)
    line = line.replace(modes.GENERAL_TAG, "（💡通用知识）")
    return _EMPHASIS.sub("", line)


def plain(text, markdown=False) -> str:
    """回答 → 聊天里好读的纯文本。markdown=True（云上协同会渲染）时原样返回。"""
    text = str(text or "")
    if markdown:
        return text.strip()
    lines = text.replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if _FENCE.match(line):
            i += 1
            continue
        if "|" in line and i + 1 < len(lines) and runs._SEPARATOR.match(lines[i + 1]) and "-" in lines[i + 1]:
            j = i + 2
            while j < len(lines) and lines[j].strip() and "|" in lines[j]:
                j += 1
            out.extend(_table(lines[i:j]))
            i = j
            continue
        heading = _HEADING.match(line)
        if heading:
            out.append(f"【{_inline(heading.group(1)).strip()}】")
        elif _RULE.match(line):
            out.append("")
        else:
            line = _QUOTE.sub("", line)
            line = _BULLET.sub(lambda m: f"{m.group(1)}• ", line)
            out.append(_inline(line).rstrip())
        i += 1
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def cited(answer) -> set:
    """正文里真正引用了的编号（「1」「W2」）。"""
    found = set()
    for group in _CITATION.findall(str(answer or "")):
        found.update(part.strip() for part in re.split(r"[,，、]", group))
    return found


def _clip(text, limit) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def sources_line(answer, hits) -> str:
    """「出处：[1] 运维手册.md　[W1] Redis 官方文档（redis.io）」：只列正文里引用了的。"""
    wanted = cited(answer)
    seen, parts = set(), []
    for hit in hits or []:
        index = str(hit.get("index", ""))
        if index not in wanted or index in seen:
            continue
        seen.add(index)
        if hit.get("web") or index.startswith("W"):
            host = urlsplit(str(hit.get("url") or "")).hostname or ""
            parts.append(f"[{index}] {_clip(hit.get('location'), 40)}" + (f"（{host}）" if host else ""))
        else:
            parts.append(f"[{index}] {_clip(hit.get('location'), 60)}")
    return ("出处：" + "　".join(parts[:SOURCES_MAX])) if parts else ""


def truncate(text, limit) -> tuple:
    """(前面能发的, 剩下的)。尽量在段落、换行处断开。"""
    text = str(text or "")
    if len(text) <= limit:
        return text, ""
    cut = text.rfind("\n\n", 0, limit)
    if cut < limit // 2:
        cut = text.rfind("\n", 0, limit)
    if cut < limit // 2:
        cut = limit
    return text[:cut].rstrip(), text[cut:].lstrip()


def pieces(text, limit, count) -> tuple:
    """「全文」：剩下的部分分成最多 count 段，每段不超过 limit 字。返回 (各段, 还剩的)。"""
    out, rest = [], str(text or "")
    while rest and len(out) < count:
        head, rest = truncate(rest, limit)
        out.append(head)
    return out, rest


def quote(question) -> str:
    first = " ".join(str(question or "").split())
    return first if len(first) <= QUOTE_MAX else first[:QUOTE_MAX] + "…"


def reply_head(sender_name, question) -> str:
    """群里回答的第一行：流式消息不能真 @，写明在回谁、回的哪一句。"""
    return f"↪ 回复 {sender_name or '你'}：{quote(question)}"


def status_for(call, titles) -> str | None:
    """调工具时显示的那一行；流程类（待办清单）不换。"""
    category = call.get("category") or "data"
    if category == "knowledge":
        return STATUS_SEARCH
    if category == "web":
        return STATUS_WEB
    if category == "compute":
        return STATUS_COMPUTE
    if category == "data":
        name = call.get("tool") or ""
        return f"🛠 正在查：{titles.get(name, name)}…"
    return None


def compose(head, body, tail_lines, limit):
    """一条回复：第一行（群里是「↪ 回复 …」）、正文（超过 limit 截断）、末尾几行。返回 (全文, 截下来的剩余)。"""
    shown, rest = truncate(body, limit)
    if rest:
        shown += "\n" + MORE_HINT
    parts = [part for part in (head, shown) if part]
    text = "\n".join(parts)
    tail = [line for line in tail_lines if line]
    if tail:
        text += "\n\n" + "\n".join(tail)
    return text, rest


def candidates_line(names) -> str:
    if not names:
        return ""
    marks = "①②③④⑤"
    listed = "　".join(f"{marks[i]} {name}" for i, name in enumerate(names[:5]))
    return f"相关 SOP：{listed}——回「执行 1」按 SOP 查一遍（会调用只读工具，结果发在这里）"


def report_ref(run, site_url="") -> str:
    """执行记录在哪看。只有页面地址是 https 时才给链接：从聊天里点开明文地址，网页密码会在不可信的网络上明文传。"""
    if str(site_url or "").startswith("https://"):
        return f"查看完整报告：{site_url.rstrip('/')}/sop?tab=runs&item={run['id']}"
    return f"执行记录 {run['id'][:6]}（网页：SOP → 执行记录）"


def run_lines(run, site_url="") -> list:
    """群里「执行」完的那几行：结论、执行记录在哪、怎么纠正。"""
    if not run or run.get("status") != "done":
        return []
    head = f"结论：{runs.LEVEL_ICONS.get(run['level'], '')} {run['level_name']}"
    if run.get("summary"):
        head += f"（{_clip(run['summary'], 80)}）"
    return [head + "　" + report_ref(run, site_url), FEEDBACK_HINT]


def help_text(scope, titles, *, group, web, contact="", platform="ccwork") -> str:
    """「帮助」：这里能查什么、怎么问、命令，以及按当前配置的数据去向。"""
    tools = [titles.get(name, name) for name in scope.tools]
    can = (f"回答团队文档里的问题，还能查这些实际数据（只读）：{'、'.join(tools)}" if tools
           else "回答团队文档里的问题（这里只查文档，不查实际数据）")
    lines = [f"我是 {BOT_NAME}，在这里可以{can}。",
             ("怎么问：@ 我再说问题" if group else "怎么问：直接发问题") + "，比如「kb-app 内存高怎么办」。"
             "同一个人 30 分钟内的追问会接着上文。",
             "命令（整条消息就是命令时才算）：",
             "• 新话题：不接上文，重新开始",
             "• 没答好 [补充说明]：记下上一条回答没答好，管理员会据此补文档",
             "• 全文：回答太长被截断时，发剩下的部分"]
    if tools:
        lines += ["• 执行 / 执行 2 / 执行 SOP名 参数=值：按 SOP 查一遍（会调用只读工具，结果发在这里）",
                  "• 误报 / 阈值不对 / 漏了一步 / 结论对：给上一次 SOP 执行的结论打分"]
    flow = (f"数据去向：问题和回答经{platform_name(platform)}服务器到 doc2sop 所在的服务器（存在对话记录里，管理员能在网页上看到，"
            "目前不自动删除），再发给模型网关和它后面的模型服务商")
    if web:
        flow += "；联网搜索时搜索词会发给搜索服务"
    lines.append(flow + "。")
    if contact:
        lines.append(f"有问题找 {contact}。")
    return "\n".join(lines)


# --- 推送 ---------------------------------------------------------------------------------

TAGS = {"recovered": "已恢复"}


def push_text(run, kind, diff, site_url="") -> str:
    """计划、告警规则的执行结果推到群里：和邮件同样的素材（结论、异常项、和上次比、需要跟进），不附工具的原始返回。"""
    level = runs.LEVEL_NAMES.get(run["level"], run["level"])
    tag = TAGS.get(kind) or (f"仍未恢复·{level}" if kind == "still" else level)
    when = runs.local_time(run["started_at"], seconds=False)
    trigger = runs.TRIGGER_NAMES.get(run["trigger"], run["trigger"]) + (f"（{run['note']}）" if run.get("note") else "")
    lines = [f"【{tag}】SOP《{run['playbook_name']}》{when[5:]}",
             f"结论：{runs.LEVEL_ICONS.get(run['level'], '')} {level}" + (f"（{run['summary']}）" if run.get("summary") else "")
             + f"　触发：{trigger}"]
    if run.get("params"):
        lines.append("参数：" + "，".join(f"{k}={v}" for k, v in run["params"].items()))
    if kind == "recovered":
        lines.append("之前报过的问题这次都正常了。")
    elif kind == "still":
        lines.append("和之前报过的是同一个问题，还没有恢复。")
    report = run.get("report") or {}
    items = report.get("findings") or []
    if items:
        lines.append("异常项：")
        lines += [f"{runs.MARK_ICONS[i['mark']]} {i['step']}：{i['value'] or '—'}" + (f"（{i['note']}）" if i["note"] else "")
                  for i in items[:10]]
    if diff:
        changes = [diff["note"]] if diff.get("note") else []
        changes += [f"新出现：{i['step']}：{i['value'] or '—'}" for i in diff["new"]]
        changes += [f"已恢复：{i['step']}：{i['value'] or '—'}" for i in diff["recovered"]]
        changes += [f"数值变化：{i['step']}：{'；'.join(i['deltas'])}" for i in diff["changed"] if i["deltas"]]
        if changes:
            lines.append(f"和上次比（{runs.local_time(diff['previous']['started_at'], seconds=False)[5:]}）：")
            lines += [f"• {line}" for line in changes[:8]]
    if report.get("followups"):
        lines.append("需要跟进：")
        lines += [f"• {item}" for item in report["followups"][:8]]
    lines.append(report_ref(run, site_url))
    return "\n".join(lines)


def test_push_text(target, platform="ccwork") -> str:
    return (f"这是 {BOT_NAME} 的测试消息，发给推送目标「{target}」。收到它说明{platform_name(platform)}的推送能用："
            "SOP 自动执行有异常、没跑成、没法判断时，按计划和告警规则上的设置推到这里。")


def digest_text(groups, scope_name="") -> str:
    """每周的知识库缺口摘要：缺口看板的前几组。"""
    where = f"「{scope_name}」里" if scope_name else ""
    lines = [f"本周{where}大家常问、文档里没写的问题："]
    lines += [f"{n}. {_clip(g['example'], 40)}（{g['count']} 次）" for n, g in enumerate(groups, 1)]
    lines.append("到网页「文档 → 知识库缺口」补文档，或在那里忽略不需要补的。")
    return "\n".join(lines)
