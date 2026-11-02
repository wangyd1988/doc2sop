"""文档分类的维护：改名、合并（改名到已有的分类）、删除（这类文档并入「未分类」）。

分类仍是按文档动态聚合的：没有空分类，新建分类就是上传或「改分类」时写一个新名字。

两类东西按分类名引用分类，改名时要一起考虑：
    对外接入的令牌（access.db 的 categories 白名单）   页面上同步改：改名到新名字时 A 换成 B（范围不变）；
                                                       合并到已有的 B、删除时只去掉 A、不加 B（只缩不放）
    云上协同的 chat.yaml（服务器上的文件）            页面改不了：预览里列出受影响的群、人，提示去服务器上改

不能因为改名让谁看到的变多：对每枚有效令牌、chat.yaml 里每个限定了分类的群和人，比较操作前后看得到的文档集合，
有一个变大（比如令牌有 B 没 A，合并后多看到 A 的文档）这次操作就要审批口令（工具服务核对），预览里逐个列出。

预览给一个版本号（文档的分类、令牌、chat.yaml 里的分类和这次操作一起算的摘要）。apply 在服务端重新算一遍，
版本号对不上就 409（不消耗口令次数）；口令核对通过后，在 store.write_lock（上传、改单篇分类也拿它）和 access.lock
（签发令牌也拿它）里再算一遍、再比一次，然后先改令牌白名单（只缩）、再改文档的分类、写操作记录。
"""
import hashlib
import json
import re
from dataclasses import dataclass, field

from app import approval, chat_config
from app.config import CATEGORY_MAX, DATA_DIR, DEFAULT_CATEGORY, MCP_ENABLED, WEB_NOTE_CATEGORY, log
from app.rag import store

ACTIONS = ("rename", "delete")
_BAD = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


class Refused(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.extra = extra


@dataclass
class Impact:
    action: str
    source: str
    target: str
    merge: bool
    documents: list
    tokens: list = field(default_factory=list)       # 白名单里有 A 或者可见范围会变的令牌
    chat: list = field(default_factory=list)         # chat.yaml 里受影响的群、人
    chat_file: str = ""
    updates: dict = field(default_factory=dict)      # 令牌 id -> 新白名单
    version: str = ""

    @property
    def expands(self) -> bool:
        return any(t["gained"] and t["status"] == "active" for t in self.tokens) or any(c["gained"] for c in self.chat)

    def view(self) -> dict:
        return {"action": self.action, "from": self.source, "to": self.target, "merge": self.merge,
                "documents": self.documents, "tokens": self.tokens, "chat": self.chat, "chat_file": self.chat_file,
                "needs_passphrase": self.expands, "version": self.version}

    def text(self) -> str:
        if self.action == "delete":
            return f"删除分类「{self.source}」（{len(self.documents)} 篇并入{DEFAULT_CATEGORY}）"
        verb = "合并到" if self.merge else "改名为"
        return f"分类「{self.source}」{verb}「{self.target}」（{len(self.documents)} 篇）"


def _access():
    """有令牌库才看令牌：MCP 从没打开过的部署不为这个建 access.db。"""
    if MCP_ENABLED or (DATA_DIR / "access.db").exists():
        from app import access
        return access
    return None


def _name(value, what) -> str:
    if not isinstance(value, str):
        raise Refused(400, f"要填{what}")
    name = " ".join(value.split())
    if not name:
        raise Refused(400, f"要填{what}")
    if len(name) > CATEGORY_MAX or _BAD.search(name):
        raise Refused(400, f"{what}最多 {CATEGORY_MAX} 个字，不能有换行之类的控制字符")
    return name


def _tokens(access, locked=False):
    if access is None:
        return []
    query = "SELECT id, name, categories, revoked_at, expires_at FROM mcp_tokens ORDER BY created_at"
    if locked:
        rows = access.db.execute(query).fetchall()
    else:
        with access.lock:
            rows = access.db.execute(query).fetchall()
    out = []
    for row in rows:
        categories = json.loads(row["categories"]) if row["categories"] else None
        out.append({"id": row["id"], "name": row["name"], "categories": categories, "status": access._status(row)})
    return out


def _chat():
    settings = chat_config.load()
    scopes = [(scope, "群") for scope in settings.groups.values()] + [(scope, "人") for scope in settings.people.values()]
    return settings, [(f"{kind} {scope.name}", list(scope.categories)) for scope, kind in scopes
                      if scope.categories is not None]


def _visible(docs, categories) -> set:
    allowed = set(categories)
    return {source for source, category in docs.items() if category in allowed}


def compute(data, access=None, docs=None, locked=False) -> Impact:
    """这次操作的影响。不合法抛 Refused(400)。不改任何东西，也不碰口令。locked：调用方已经拿着 access.lock。"""
    data = data if isinstance(data, dict) else {}
    action = data.get("action")
    if action not in ACTIONS:
        raise Refused(400, "操作只能是改名（rename）或删除（delete）")
    source = _name(data.get("from"), "分类名")
    docs = {d["source"]: d["category"] for d in store.list_documents()} if docs is None else docs
    existing = set(docs.values())
    if source not in existing:
        raise Refused(409, f"没有分类「{source}」了（可能刚被改过）：刷新后再试", stale=True)
    if source == WEB_NOTE_CATEGORY:
        raise Refused(400, f"「{WEB_NOTE_CATEGORY}」是联网补充的资料，标着「未核实」：不能改名、合并或删除")
    if action == "delete":
        if source == DEFAULT_CATEGORY:
            raise Refused(400, f"「{DEFAULT_CATEGORY}」是默认分类，不能删除；可以改名或合并到别的分类")
        target = DEFAULT_CATEGORY
    else:
        target = _name(data.get("to"), "新名字")
        if target == source:
            raise Refused(400, "新名字和原来的一样")
        if target == WEB_NOTE_CATEGORY:
            raise Refused(400, f"不能并进「{WEB_NOTE_CATEGORY}」：那是联网补充、未核实的资料")
    merge = target in existing
    moving = sorted(s for s, c in docs.items() if c == source)
    after = {s: (target if c == source else c) for s, c in docs.items()}
    impact = Impact(action=action, source=source, target=target, merge=merge, documents=moving)

    tokens = _tokens(access, locked)
    for token in tokens:
        if token["categories"] is None:
            continue
        before_list = list(token["categories"])
        new_list = [c for c in before_list if c != source]
        if source in before_list and action == "rename" and not merge and target not in new_list:
            new_list.append(target)
        before, now = _visible(docs, before_list), _visible(after, new_list)
        gained, lost = len(now - before), len(before - now)
        if sorted(new_list) != sorted(before_list):
            impact.updates[token["id"]] = sorted(new_list)
        if gained or lost or token["id"] in impact.updates:
            impact.tokens.append({"id": token["id"], "name": token["name"], "status": token["status"],
                                  "before": sorted(before_list), "after": sorted(new_list), "gained": gained, "lost": lost})

    settings, scopes = _chat()
    impact.chat_file = settings.path if settings.exists else ""
    for name, categories in scopes:
        before, now = _visible(docs, categories), _visible(after, categories)
        gained, lost = len(now - before), len(before - now)
        if gained or lost or source in categories:
            impact.chat.append({"name": name, "categories": sorted(categories), "gained": gained, "lost": lost})

    digest = hashlib.sha256(json.dumps({
        "op": [action, source, target], "docs": sorted(docs.items()),
        "tokens": [(t["id"], t["status"], t["categories"]) for t in tokens],
        "chat": scopes}, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    impact.version = digest[:16]
    return impact


def preview(data) -> dict:
    return compute(data, _access()).view()


def apply(data, caller="", user="", ip="") -> dict:
    """做这次操作。顺序：重新算影响 → 版本号对不上 409 → 扩大可见范围的核对口令 → 在锁里再算、再比 →
    改令牌白名单（只缩）→ 改文档的分类 → 记日志和操作记录。"""
    access = _access()
    impact = compute(data, access)
    stale = {"stale": True, "preview": impact.view()}
    if data.get("version") != impact.version:
        raise Refused(409, "刚才预览以后，文档的分类、令牌或 chat.yaml 变了：看一下新的影响再确认", **stale)
    if impact.expands:
        try:
            approval.verify(data.get("passphrase"), "category-" + impact.action,
                            f"{impact.source}→{impact.target}", caller)
        except approval.Refused as exc:
            raise Refused(exc.status, str(exc), passphrase=exc.passphrase) from None
    with store.write_lock:
        if access is None:
            return _commit(compute(data, None), data, None, user, ip)
        with access.lock:
            return _commit(compute(data, access, locked=True), data, access, user, ip)


def _commit(impact, data, access, user, ip) -> dict:
    if impact.version != data.get("version"):
        raise Refused(409, "核对口令的时候，文档的分类、令牌或 chat.yaml 又变了：看一下新的影响再确认",
                      stale=True, preview=impact.view())
    if access is not None and impact.updates:
        names = "、".join(access.clean(t["name"], 40) for t in impact.tokens if t["id"] in impact.updates)
        access.set_categories(impact.updates, f"{impact.text()}：同步了令牌 {names} 的分类白名单", user, ip)
    chunks = store.retag_locked(impact.documents, impact.target)
    log.info("category %s: %s -> %s, %d document(s), %d chunk(s), %d token whitelist(s) updated, user=%s ip=%s",
             impact.action, impact.source, impact.target, len(impact.documents), chunks, len(impact.updates), user, ip)
    return {"done": impact.view(), "categories": store.all_categories()}
