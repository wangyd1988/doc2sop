"""工作台（首页）要的汇总：四张状态卡、待处理、示例问题、最近的对话。

只读。哪一块取不到就降级（空列表、带上原因），不让首页整页出错。工具服务各取一次：/tools/full（工具、主机、
MCP server、连接）和 /tools/review（待审申请、要重新确认的脚本、审批口令的状态）。
"""
from app import catalog, conversations, graph, packs, playbooks
from app.agent import ops_client, registry, sandbox, web_search
from app.config import MCP_ENABLED, log
from app.rag import store

EXAMPLE_KINDS = packs.EXAMPLE_KINDS
RECENT = 6
EXAMPLES_PER_KIND = 3
# 没有场景包时的兜底示例
KNOWLEDGE_EXAMPLE = "总结一下知识库里有哪些主要内容"
COMPUTE_EXAMPLE = "用计算算一下：每天 1.2 万次调用、每次平均 3000 token，一个月大约多少 token？"


def host_reason(name, error):
    """主机离线的原因。页面上主机名已经单独写了：去掉原因开头重复的「主机 名字：」「主机 名字 的」。"""
    text = str(error or "").strip()
    for prefix in (f"主机 {name}：", f"主机 {name}:", f"主机 {name} 的"):
        while text.startswith(prefix):
            text = text[len(prefix):].lstrip()
    return text or "连不上"


def _knowledge():
    docs = store.list_documents()
    categories = {}
    for doc in docs:
        name = doc.get("category") or "未分类"
        categories[name] = categories.get(name, 0) + 1
    return {"documents": len(docs), "chunks": sum(int(doc.get("chunks") or 0) for doc in docs),
            "categories": [{"name": name, "documents": count}
                           for name, count in sorted(categories.items(), key=lambda item: (-item[1], item[0]))]}


def _hosts(described):
    """主机清单的在线情况。只把检查过、连不上的远程主机算离线；还没检查过的不算。"""
    listed = (described or {}).get("list") or {}
    offline, online = [], 0
    for name, host in listed.items():
        status = host.get("status")
        if host.get("via") != "ssh" or (status and status.get("reachable")):
            online += 1
        elif status is not None:
            offline.append({"name": name, "error": host_reason(name, status.get("error"))})
    return {"configured": bool((described or {}).get("configured")), "total": len(listed), "online": online,
            "offline": offline}


def _tools(detail):
    tools = detail.get("tools") or {}
    page = catalog.page_tools(tools, "", "", 0, 1)
    connections = detail.get("connections") or {}
    servers = detail.get("mcp_servers") or {}
    hosts = _hosts(detail.get("hosts"))
    k8s = sum(1 for tool in tools.values()
              if tool.get("binary") == "kubectl" or "k8s" in str(tool.get("conn") or "").lower())
    return {"live": page["live"], "total": page["count"], "groups": page["groups"], "error": detail.get("error", ""),
            "hosts": hosts,
            "sources": {"k8s": k8s, "hosts": sum(1 for h in ((detail.get("hosts") or {}).get("list") or {}).values()
                                                 if h.get("via") == "ssh"),
                        "sql": sum(1 for c in connections.values() if c.get("type") in ("postgres", "mysql", "sqlite")),
                        "http": sum(1 for c in connections.values() if c.get("type") == "http"),
                        "mcp": {"servers": len(servers),
                                "online": sum(1 for s in servers.values() if s.get("online"))},
                        "sandbox": sandbox.enabled(), "web": web_search.enabled()}}


def _access():
    out = {"enabled": MCP_ENABLED}
    if MCP_ENABLED:
        from app import access
        tokens = access.list_tokens()
        calls = access.recent_calls(1)
        out.update(tokens=len(tokens), active=sum(1 for token in tokens if token["status"] == "active"),
                   last_call=calls[0]["at"] if calls else None)
    return out


def _recent():
    """最近的对话：按哪个 SOP 执行的、调了几次数据类工具（工作台上一眼看出这一轮用了什么）。"""
    out = []
    for conv in conversations.list_conversations(RECENT):
        runs = graph.executions_by_message(conv["id"]).values()
        book = next((run["playbook_id"] for run in runs if run.get("playbook_id")), None)
        calls = 0
        for run in runs:
            execution = graph.execution(run["execution_id"]) or {}
            calls += sum(1 for call in execution.get("tool_calls", []) if registry.category_of(call["tool"]) == "data")
        out.append({**conv, "playbook": (playbooks.get(book) or {}).get("name") if book else None, "calls": calls})
    return out


def examples(knowledge, tools, live_sops, labels):
    """示例问题，按用途分四类。导入了场景包就用包里 pack.yaml 写的，缺的类别补上兜底的；
    没有场景包时按现有的文档、可用的工具、生效的 SOP 生成。SOP 类的生成示例带着 SOP，点了就按它执行。"""
    out = list(packs.example_items())
    have = {item["kind"] for item in out}
    generated = []
    if knowledge["documents"]:
        generated.append({"text": KNOWLEDGE_EXAMPLE, "kind": "knowledge"})
        for category in knowledge["categories"][:2]:
            if category["name"] != "未分类":
                generated.append({"text": f"「{category['name']}」类的文档里讲了哪些要点？", "kind": "knowledge"})
    for name in sorted(tools)[:EXAMPLES_PER_KIND]:
        generated.append({"text": f"用「{labels.get(name) or name}」查一下现在的情况", "kind": "data"})
    for book in live_sops[:EXAMPLES_PER_KIND]:
        generated.append({"text": f"执行 SOP《{book['name']}》", "kind": "sop",
                          "playbook": {"id": book["id"], "name": book["name"]}})
    if sandbox.enabled():
        generated.append({"text": COMPUTE_EXAMPLE, "kind": "compute"})
    out += [item for item in generated if not out or item["kind"] not in have]
    return out


def overview(usable_tools) -> dict:
    """GET /api/overview。usable_tools：此刻能进 SOP 的数据类工具（名字 → 说明），由 main 传进来。"""
    usable_tools = dict(usable_tools or {})
    knowledge = _knowledge()
    detail = ops_client.describe_tools()
    review = ops_client.review()
    tools = _tools(detail)
    labels = {name: tool.get("label") or name for name, tool in (detail.get("tools") or {}).items()}
    sops = playbooks.list_all()
    live = playbooks.usable(set(usable_tools))
    proposals = graph.list_proposals(status="pending")
    try:
        access = _access()
    except Exception as exc:   # 对外接入的库出问题不影响首页别的部分
        log.warning("overview: access summary failed: %s", exc)
        access = {"enabled": MCP_ENABLED, "tokens": 0, "active": 0, "last_call": None}
    return {
        "knowledge": knowledge,
        "tools": tools,
        "sops": {"live": len(live), "total": len(sops), "proposals": len(proposals),
                 "names": [book["name"] for book in live]},
        "access": access,
        "approval": review.get("approval") or {},
        "pending": {
            "tools": [{"id": item.get("id"), "name": (item.get("tool") or {}).get("name", ""),
                       "label": (item.get("tool") or {}).get("label", ""),
                       "kind": (item.get("detail") or {}).get("kind", ""), "author": item.get("author", ""),
                       "created_at": item.get("created_at", ""),
                       "reason": (item.get("review") or {}).get("reason", "")}
                      for item in review.get("pending") or []],
            "scripts": [{key: entry.get(key) for key in ("tool", "label", "script", "state")}
                        for entry in review.get("held") or []],
            "proposals": [{"id": p["id"], "name": p["payload"].get("name", "") or
                           ((p["payload"].get("target") or {}).get("name", "")),
                           "kind": p["kind"], "created_at": p["created_at"]} for p in proposals],
            "hosts": tools["hosts"]["offline"],
        },
        "recent": _recent(),
        "examples": examples(knowledge, usable_tools, live, labels),
        "tool_labels": labels,
    }
