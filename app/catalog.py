"""Paging and search for the management drawers.

Tools and SOPs will grow into the hundreds or thousands. The page therefore
never asks for "everything": it asks for the group list (names + counts), then
one page of one group, or one page of search results. Everything here is plain
Python over dicts so it works for the tool catalogue (which comes from the ops
host as one dict) as well as for SQL rows.
"""
PAGE = 30
PAGE_MAX = 100


def clamp(offset, limit):
    offset = max(0, int(offset or 0))
    limit = min(PAGE_MAX, max(1, int(limit or PAGE)))
    return offset, limit


def haystack(*parts) -> str:
    out = []
    for part in parts:
        if isinstance(part, (list, tuple, set)):
            out.append(haystack(*part))
        elif isinstance(part, dict):
            out.append(haystack(*part.keys(), *part.values()))
        elif part:
            out.append(str(part))
    return " ".join(out).lower()


def matches(q: str, text: str) -> bool:
    """Every whitespace-separated term must appear."""
    return all(term in text for term in q.lower().split())


def page_tools(tools: dict, q: str = "", group: str = "", offset=0, limit=PAGE):
    """Group summary plus one page of tools.

    Without q/group the item page is empty on purpose: the page shows collapsed
    groups and fetches a group only when the user opens it.
    """
    offset, limit = clamp(offset, limit)
    live = lambda t: bool(t.get("enabled")) and bool(t.get("runnable", True))
    groups = {}
    for name, t in tools.items():
        g = groups.setdefault(t.get("group") or "其他", {"name": t.get("group") or "其他", "live": 0, "total": 0})
        g["total"] += 1
        g["live"] += live(t)
    ordered = sorted(groups.values(), key=lambda g: (g["name"] == "其他", g["name"]))

    q = (q or "").strip()
    if q:
        names = [n for n, t in tools.items()
                 if matches(q, haystack(n, t.get("label"), t.get("desc"), t.get("command"),
                                        t.get("group"), t.get("params")))]
    elif group:
        names = [n for n, t in tools.items() if (t.get("group") or "其他") == group]
    else:
        names = []
    names.sort()
    page = names[offset:offset + limit]
    return {"groups": ordered, "tools": {n: tools[n] for n in page},
            "total": len(names), "offset": offset, "limit": limit,
            "live": sum(live(t) for t in tools.values()), "count": len(tools)}
