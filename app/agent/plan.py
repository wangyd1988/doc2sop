"""plan：本轮的待办清单（统一契约里的 internal 流程类，应用内提供，PLAN_TOOL 打开才绑定）。

参数是整张清单（每项一个标题和状态），每次整体替换。清单存在本轮状态里（usage["plan"]），
通过 plan 事件推给页面画成勾选列表。点「▶ 执行」时代码先按 SOP 步骤预填（from_playbook），
模型逐项勾掉：长 SOP 不漏步，最后的对照表也和清单一一对应。跨文档的问题也可以先列子问题再逐个检索。

流程类：不算观察到系统、不进 SOP、不记进图谱（registry.POLICIES["internal"]）。
"""
NAME = "plan"
STATUSES = ("pending", "in_progress", "done", "skipped")
MARKS = {"pending": "[ ]", "in_progress": "[~]", "done": "[x]", "skipped": "[-]"}
MAX_ITEMS = 20
TITLE_MAX = 80

TOOL = {
    "name": NAME,
    "title": "待办清单",
    "description": (
        "维护本轮的待办清单。多步骤的任务（按 SOP 执行、要分几步查的问题、跨文档要拆成几个子问题的）先列清单，"
        "每做完一步更新一次。每次传整张清单（整体替换）；状态：pending 待办、in_progress 进行中、done 完成、"
        "skipped 跳过（标题里写明原因）。简单问题不用列清单。"),
    "inputSchema": {
        "type": "object",
        "properties": {"items": {
            "type": "array", "maxItems": MAX_ITEMS, "description": "整张清单，按顺序",
            "items": {"type": "object",
                      "properties": {"title": {"type": "string", "description": "这一项做什么，一句话"},
                                     "status": {"type": "string", "enum": list(STATUSES)}},
                      "required": ["title", "status"]}}},
        "required": ["items"]},
    "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    "_meta": {"doc2sop": {"category": "internal", "provider": "app", "export": False, "group": "流程"}},
}


def normalize(items) -> list:
    """模型传来的清单 → [{"title", "status"}]：标题去空白、截断，认不出的状态当待办，最多 MAX_ITEMS 项。"""
    if not isinstance(items, list):
        raise ValueError("items 要是一个清单（数组），每项有 title 和 status")
    out = []
    for item in items[:MAX_ITEMS]:
        if isinstance(item, str):
            item = {"title": item}
        if not isinstance(item, dict):
            continue
        title = " ".join(str(item.get("title") or "").split())[:TITLE_MAX]
        if not title:
            continue
        status = str(item.get("status") or "").strip().lower()
        out.append({"title": title, "status": status if status in STATUSES else "pending"})
    if not out:
        raise ValueError("清单是空的：每项要有 title")
    return out


def as_text(items) -> str:
    return "\n".join(f"{n}. {MARKS[item['status']]} {item['title']}" for n, item in enumerate(items, 1))


def run(args, turn) -> str:
    """整体替换本轮的清单，推 plan 事件。"""
    try:
        items = normalize(args.get("items"))
    except ValueError as exc:
        return f"[执行失败] {exc}"
    turn.usage["plan"] = items
    turn.emit(("plan", items))
    finished = sum(item["status"] in ("done", "skipped") for item in items)
    return f"清单已更新：共 {len(items)} 项，已完成 {finished} 项。\n{as_text(items)}"


def from_playbook(playbook, titles=None) -> list:
    """「▶ 执行」时按 SOP 步骤预填的清单。titles：工具名 → 界面显示名（契约里的 title）。"""
    titles = titles or {}
    items = []
    for n, step in enumerate((playbook or {}).get("steps") or [], 1):
        label = titles.get(step.get("tool")) or step.get("tool") or "步骤"
        check = " ".join(str(step.get("checkpoint") or "").split())
        items.append({"title": (f"第 {n} 步 {label}" + (f"：{check}" if check else ""))[:TITLE_MAX],
                      "status": "pending"})
    return items[:MAX_ITEMS]
